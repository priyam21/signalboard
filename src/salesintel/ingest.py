"""Stream Shodan JSONL (zstd, gzip, or plain) into a SQLite account mart.

Monthly drops are more files of the same shape. Aggregation keeps one row per
company, so extra files add findings instead of a second copy of the internet.
Raw banners are not stored.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

try:
    import orjson
except ImportError:  # pragma: no cover
    orjson = None

try:
    import zstandard as zstd
except ImportError:  # pragma: no cover
    zstd = None

from salesintel.brief import call_brief, why_now
from salesintel.signals import interpret_banner

_IP_CAP = 4000
_FINDING_KEEP = 8


def _loads(line: bytes) -> dict:
    if orjson is not None:
        return orjson.loads(line)
    return json.loads(line)


def _iter_lines(path: Path):
    with path.open("rb") as handle:
        magic = handle.read(4)
        handle.seek(0)
        if magic == b"\x28\xb5\x2f\xfd":
            if zstd is None:
                raise RuntimeError("zstandard is required to read this file")
            source = zstd.ZstdDecompressor().stream_reader(handle)
        elif magic[:2] == b"\x1f\x8b":
            source = gzip.GzipFile(fileobj=handle)
        else:
            source = handle
        buf = b""
        while True:
            chunk = source.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    break
                line = buf[:nl]
                buf = buf[nl + 1:]
                if line.strip():
                    yield line
        if buf.strip():
            yield buf


def _fingerprint(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        digest.update(handle.read(8 << 20))
    return {"name": path.name, "bytes": path.stat().st_size, "sha256_first_8mb": digest.hexdigest()}


class Account:
    __slots__ = (
        "key", "kind", "name", "domain", "findings", "dedupe", "ips",
        "banners", "countries", "orgs", "asns", "max_points",
    )

    def __init__(self, key: str, kind: str, name: str, domain: str | None):
        self.key = key
        self.kind = kind
        self.name = name
        self.domain = domain
        self.findings: list[dict] = []
        self.dedupe: set = set()
        self.ips: set[str] = set()
        self.banners = 0
        self.countries: Counter = Counter()
        self.orgs: Counter = Counter()
        self.asns: Counter = Counter()
        self.max_points = 0

    def add(self, view, findings: list[dict]) -> None:
        self.banners += 1
        if view.country:
            self.countries[view.country] += 1
        if view.org:
            self.orgs[view.org] += 1
        if view.asn:
            self.asns[view.asn] += 1
        if view.ip and len(self.ips) < 40:
            self.ips.add(view.ip)
        for finding in findings:
            sig = (finding["klass"], finding.get("cve"), finding.get("ip"), finding.get("port"), finding["title"])
            if sig in self.dedupe or len(self.dedupe) >= 60:
                continue
            self.dedupe.add(sig)
            self.findings.append(finding)
            if finding["points"] > self.max_points:
                self.max_points = finding["points"]
        if len(self.findings) > 24:
            self.findings.sort(key=lambda item: item["points"], reverse=True)
            self.findings = self.findings[:_FINDING_KEEP]


def _org_key(name: str) -> str:
    slug = "".join(ch if ch.isalnum() else "-" for ch in name.lower())
    while "--" in slug:
        slug = slug.replace("--", "-")
    return "org:" + slug.strip("-")[:96]


def _place(accounts: dict[str, Account], view, findings: list[dict], stats: Counter) -> None:
    if view.domain:
        key = "domain:" + view.domain
        account = accounts.get(key)
        if account is None:
            account = Account(key, "domain", view.domain, view.domain)
            accounts[key] = account
        account.add(view, findings)
        return

    material = [finding for finding in findings if finding["klass"] != "trust"]
    if not material:
        stats["dropped_trust_without_domain"] += 1
        return
    if view.org and not view.org_is_infra:
        key = _org_key(view.org)
        account = accounts.get(key)
        if account is None:
            account = Account(key, "org", view.org, None)
            accounts[key] = account
        account.add(view, material)
        return
    top = max(finding["points"] for finding in material)
    if view.ip and top >= 22:
        key = "ip:" + view.ip
        account = accounts.get(key)
        if account is None:
            account = Account(key, "ip", view.ip, None)
            accounts[key] = account
        account.add(view, material)
        return
    stats["unattributed_material"] += 1


def _prune_ips(accounts: dict[str, Account]) -> int:
    ip_keys = [key for key, account in accounts.items() if account.kind == "ip"]
    if len(ip_keys) <= _IP_CAP:
        return 0
    ip_keys.sort(key=lambda key: accounts[key].max_points, reverse=True)
    for key in ip_keys[_IP_CAP:]:
        del accounts[key]
    return len(ip_keys) - _IP_CAP


def _mode(counter: Counter) -> str:
    if not counter:
        return ""
    return counter.most_common(1)[0][0]


def ingest_paths(paths: list[Path], out: Path, limit: int = 0) -> dict:
    accounts: dict[str, Account] = {}
    stats: Counter = Counter()
    started = time.time()
    files = []
    for path in paths:
        files.append(_fingerprint(path))
        print(f"reading {path} ({path.stat().st_size / 1e9:.2f} GB)", flush=True)
        for line in _iter_lines(path):
            stats["records"] += 1
            if limit and stats["records"] > limit:
                stats["records"] -= 1
                break
            try:
                rec = _loads(line)
            except Exception:
                stats["bad_json"] += 1
                continue
            if not isinstance(rec, dict):
                stats["bad_json"] += 1
                continue
            view = interpret_banner(rec)
            if view.skip == "honeypot":
                stats["honeypot"] += 1
                continue
            if view.probe_module:
                stats["probe_banners"] += 1
                if view.findings:
                    stats["probe_banners_confirmed"] += 1
            stats["unverified_cves"] += view.unverified_cves
            stats["weak_verified_cves"] += view.weak_verified_cves
            if not view.findings:
                stats["no_material_signal"] += 1
                continue
            for finding in view.findings:
                stats[f"class:{finding['klass']}"] += 1
            _place(accounts, view, view.findings, stats)
            if stats["records"] % 250_000 == 0:
                pruned = _prune_ips(accounts)
                stats["ip_rows_pruned"] += pruned
                elapsed = time.time() - started
                rate = stats["records"] / elapsed if elapsed else 0
                print(
                    f"  {stats['records']:,} banners  {len(accounts):,} accounts  "
                    f"{rate:,.0f} banners/s  pruned_ips={pruned}",
                    flush=True,
                )
        if limit and stats["records"] >= limit:
            break
    stats["ip_rows_pruned"] += _prune_ips(accounts)
    elapsed = time.time() - started
    meta = {
        "records": stats["records"],
        "elapsed_sec": round(elapsed, 1),
        "banners_per_sec": round(stats["records"] / elapsed, 1) if elapsed else 0,
        "accounts": len(accounts),
        "files": files,
        "stats": dict(stats),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _write_db(out, accounts, meta)
    print(
        f"wrote {out}  accounts={len(accounts):,}  "
        f"banners={stats['records']:,}  {meta['banners_per_sec']:,.0f}/s",
        flush=True,
    )
    return meta


def _write_db(out: Path, accounts: dict[str, Account], meta: dict) -> None:
    from salesintel.score import score_findings

    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    conn = sqlite3.connect(out)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.executescript(
        """
        CREATE TABLE accounts (
            account_key TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            domain TEXT,
            org_hint TEXT,
            asn TEXT,
            country TEXT,
            priority INTEGER NOT NULL,
            pain INTEGER NOT NULL,
            urgency INTEGER NOT NULL,
            breadth INTEGER NOT NULL,
            queue TEXT NOT NULL,
            ip_count INTEGER NOT NULL,
            banner_count INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            classes TEXT NOT NULL,
            why_now TEXT NOT NULL,
            call_brief TEXT NOT NULL,
            breakdown TEXT NOT NULL
        );
        CREATE TABLE findings (
            account_key TEXT NOT NULL,
            klass TEXT NOT NULL,
            points INTEGER NOT NULL,
            title TEXT NOT NULL,
            detail TEXT,
            ip TEXT,
            port INTEGER,
            product TEXT,
            version TEXT,
            cve TEXT,
            cvss REAL,
            epss REAL,
            verified INTEGER NOT NULL,
            country TEXT,
            evidence TEXT
        );
        CREATE TABLE meta (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        );
        CREATE INDEX idx_accounts_priority ON accounts(priority DESC);
        CREATE INDEX idx_accounts_queue ON accounts(queue, priority DESC);
        CREATE INDEX idx_accounts_country ON accounts(country);
        CREATE INDEX idx_accounts_kind ON accounts(kind);
        CREATE INDEX idx_findings_account ON findings(account_key);
        """
    )
    account_rows = []
    finding_rows = []
    for account in accounts.values():
        if not account.findings:
            continue
        account.findings.sort(key=lambda item: item["points"], reverse=True)
        kept = account.findings[:_FINDING_KEEP]
        scored = score_findings(kept)
        org_hint = _mode(account.orgs)
        country = _mode(account.countries)
        brief = call_brief(account.name, kept, account.kind)
        account_rows.append((
            account.key,
            account.kind,
            account.name,
            account.domain,
            org_hint,
            _mode(account.asns),
            country,
            scored["priority"],
            scored["pain"],
            scored["urgency"],
            scored["breadth"],
            scored["queue"],
            len(account.ips),
            account.banners,
            len(kept),
            json.dumps(scored["classes"]),
            why_now(kept),
            brief,
            json.dumps(scored),
        ))
        for finding in kept:
            finding_rows.append((
                account.key,
                finding["klass"],
                finding["points"],
                finding["title"],
                finding.get("detail") or "",
                finding.get("ip") or "",
                finding.get("port"),
                finding.get("product") or "",
                finding.get("version") or "",
                finding.get("cve"),
                finding.get("cvss"),
                finding.get("epss"),
                1 if finding.get("verified") else 0,
                finding.get("country") or "",
                finding.get("evidence") or "",
            ))
    conn.executemany(
        """INSERT INTO accounts (
            account_key, kind, name, domain, org_hint, asn, country,
            priority, pain, urgency, breadth, queue, ip_count, banner_count,
            finding_count, classes, why_now, call_brief, breakdown
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        account_rows,
    )
    conn.executemany(
        """INSERT INTO findings (
            account_key, klass, points, title, detail, ip, port, product, version,
            cve, cvss, epss, verified, country, evidence
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        finding_rows,
    )
    conn.execute("INSERT INTO meta (k, v) VALUES ('ingest', ?)", (json.dumps(meta),))
    conn.commit()
    conn.close()


def _expand_inputs(raw: list[str]) -> list[Path]:
    paths: list[Path] = []
    for item in raw:
        path = Path(item)
        if path.is_dir():
            paths.extend(sorted(p for p in path.iterdir() if p.is_file() and not p.name.startswith(".")))
        else:
            paths.append(path)
    if not paths:
        raise SystemExit("no input files")
    return paths


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Ingest Shodan banners into a Signalboard mart")
    parser.add_argument("--input", action="append", required=True, help="zstd/jsonl file or directory. Repeatable.")
    parser.add_argument("--out", required=True, help="SQLite path to write")
    parser.add_argument("--limit", type=int, default=0, help="Stop after N banners (0 = all)")
    args = parser.parse_args(argv)
    ingest_paths(_expand_inputs(args.input), Path(args.out), limit=args.limit)


if __name__ == "__main__":
    main(sys.argv[1:])
