"""Write a standalone HTML leave-behind from the scored mart."""

from __future__ import annotations

import argparse
import html
import json
import sqlite3
from pathlib import Path

from salesintel.score import CLASS_LABEL

LIVE_URL = "https://resulted-gzip-pepper-governing.trycloudflare.com"

FEATURED = (
    "uam.mx",
    "ntu.edu.tw",
    "sp.gov.br",
    "huayundata.com",
    "fishing-guide.si",
    "sendblaster.de",
)


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _fmt(n) -> str:
    return f"{int(n):,}"


def _epss(value) -> str:
    if value is None:
        return ""
    return f"{float(value):.3f}"


def build_report(db_path: Path, out_path: Path, live_url: str = LIVE_URL) -> Path:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    meta = json.loads(conn.execute("select v from meta where k = 'ingest'").fetchone()["v"])
    stats = meta["stats"]
    counts = {
        (row["kind"], row["queue"]): row["n"]
        for row in conn.execute("select kind, queue, count(*) n from accounts group by 1, 2")
    }
    accounts = conn.execute("select count(*) from accounts").fetchone()[0]
    findings_n = conn.execute("select count(*) from findings").fetchone()[0]
    top = conn.execute(
        """
        select account_key, priority, pain, urgency, breadth, country, name, org_hint,
               asn, ip_count, why_now, call_brief, classes, queue
        from accounts
        where kind = 'domain' and queue = 'now'
        order by priority desc, name
        limit 25
        """
    ).fetchall()
    featured_rows = []
    for name in FEATURED:
        row = conn.execute("select * from accounts where account_key = ?", (f"domain:{name}",)).fetchone()
        if row:
            featured_rows.append(row)
    finding_map = {}
    keys = [row["account_key"] for row in list(top) + featured_rows]
    for key in dict.fromkeys(keys):
        finding_map[key] = conn.execute(
            """
            select klass, points, title, detail, ip, port, cve, cvss, epss, verified, evidence
            from findings where account_key = ? order by points desc
            """,
            (key,),
        ).fetchall()
    conn.close()

    def finding_rows(key: str) -> str:
        blocks = []
        for finding in finding_map.get(key, []):
            detail = finding["detail"] or ""
            if "([]uint8)" in detail or "00000030" in detail:
                detail = finding["evidence"] or "Scanner confirmed the issue."
            elif len(detail) > 360:
                detail = detail[:357].rsplit(" ", 1)[0] + "…"
            bits = [f"{_esc(finding['ip'])}:{_esc(finding['port'])}"]
            if finding["cve"]:
                bits.append(_esc(finding["cve"]))
            if finding["cvss"] is not None:
                bits.append(f"CVSS {finding['cvss']:g}")
            if finding["epss"] is not None:
                bits.append(f"EPSS {_epss(finding['epss'])}")
            blocks.append(
                f"<tr><td>{finding['points']}</td>"
                f"<td>{_esc(CLASS_LABEL.get(finding['klass'], finding['klass']))}</td>"
                f"<td><strong>{_esc(finding['title'])}</strong>"
                f"<div class='muted'>{_esc(' · '.join(bits))}</div>"
                f"<div>{_esc(detail)}</div></td></tr>"
            )
        return "".join(blocks)

    top_rows = []
    for index, row in enumerate(top, start=1):
        classes = ", ".join(CLASS_LABEL.get(item, item) for item in json.loads(row["classes"]))
        top_rows.append(
            f"<tr><td>{index}</td><td class='prio'>{row['priority']}</td>"
            f"<td><strong>{_esc(row['name'])}</strong>"
            f"<div class='muted'>{_esc(row['country'] or '—')} · {_esc(row['org_hint'] or 'network unknown')} · {row['ip_count']} IP{'s' if row['ip_count'] != 1 else ''}</div></td>"
            f"<td>{_esc(row['why_now'])}<div class='muted'>{_esc(classes)}</div></td></tr>"
        )

    cards = []
    for row in featured_rows:
        cards.append(
            f"<article class='card'><p class='kicker'>Priority {row['priority']} · {_esc(row['country'] or '—')}</p>"
            f"<h3>{_esc(row['name'])}</h3>"
            f"<p class='muted'>Network: {_esc(row['org_hint'] or '—')} · {_esc(row['asn'] or '')}</p>"
            f"<p class='brief'>{_esc(row['call_brief'])}</p>"
            f"<table><thead><tr><th>Pts</th><th>Kind</th><th>Evidence</th></tr></thead>"
            f"<tbody>{finding_rows(row['account_key'])}</tbody></table></article>"
        )

    now_domains = counts.get(("domain", "now"), 0)
    month_domains = counts.get(("domain", "month"), 0)
    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Signalboard — exposure report</title>
<style>
  :root {{ --paper:#f3efe6; --ink:#1c1915; --muted:#5e584e; --line:#ddd4c4; --card:#fffdf8; --rust:#9a3412; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font: 16px/1.45 "Iowan Old Style", Palatino, "Palatino Linotype", Georgia, serif; color: var(--ink); background: var(--paper); }}
  main {{ max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-weight: 560; font-size: 40px; letter-spacing: -0.03em; margin: 0 0 8px; }}
  h2 {{ font-size: 26px; margin: 36px 0 8px; }}
  h3 {{ margin: 0 0 6px; font-size: 22px; }}
  a {{ color: var(--rust); }}
  .lede {{ font-size: 18px; max-width: 68ch; }}
  .muted {{ color: var(--muted); font-size: 14px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin: 20px 0; }}
  .stat {{ background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; }}
  .stat b {{ display:block; font-size: 26px; }}
  .note, .brief {{ background: #1c1915; color: #f6f1e7; border-radius: 12px; padding: 14px 16px; }}
  table {{ width:100%; border-collapse: collapse; background: var(--card); }}
  th, td {{ text-align:left; vertical-align: top; padding: 8px 10px; border-top: 1px solid var(--line); }}
  th {{ font-size: 12px; letter-spacing: .04em; text-transform: uppercase; color: var(--muted); }}
  .prio {{ font-size: 22px; }}
  .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 16px; margin: 14px 0; }}
  .kicker {{ letter-spacing: .06em; text-transform: uppercase; font-size: 12px; color: var(--rust); margin: 0 0 4px; }}
  ul {{ padding-left: 18px; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.92em; }}
</style>
</head>
<body>
<main>
  <p class="kicker">Cybersecurity sales desk · scan 26 Oct 2026</p>
  <h1>Signalboard</h1>
  <p class="lede">Which businesses are exposed right now, ranked from a Shodan banner dump. This file is the leave-behind. It opens with the laptop closed.</p>
  <p>Live desk, only while this Mac is awake and the tunnel is running:<br />
  <a href="{_esc(live_url)}">{_esc(live_url)}</a></p>
  <p class="note">Closing the laptop takes that link down, and opening it again does not restore the same address. This report does not depend on the link.</p>

  <div class="stats">
    <div class="stat"><b>{_fmt(stats['records'])}</b><span>banners read</span></div>
    <div class="stat"><b>{_fmt(accounts)}</b><span>accounts scored</span></div>
    <div class="stat"><b>{_fmt(now_domains)}</b><span>named domains to call now</span></div>
    <div class="stat"><b>{_fmt(month_domains)}</b><span>named domains this month</span></div>
    <div class="stat"><b>{_fmt(round(meta['banners_per_sec']))}</b><span>banners per second</span></div>
    <div class="stat"><b>{_fmt(findings_n)}</b><span>confirmed findings kept</span></div>
  </div>

  <h2>What was thrown away</h2>
  <p>Most of the file is scanner noise. These counts are from the one pass over the 17.6 GB dump ({meta['elapsed_sec']} seconds).</p>
  <table>
    <thead><tr><th>Check</th><th>Count</th><th>What it means</th></tr></thead>
    <tbody>
      <tr><td>No confirmed signal</td><td>{_fmt(stats['no_material_signal'])}</td><td>About 95% of banners are not a sales lead.</td></tr>
      <tr><td>Unverified CVE rows ignored</td><td>{_fmt(stats['unverified_cves'])}</td><td>Version guesses. They would have drowned the ranking.</td></tr>
      <tr><td>Verified CVEs that scored</td><td>{_fmt(stats['class:verified_cve'])}</td><td>Scanner-verified, and CVSS ≥ 7 or EPSS ≥ 0.05.</td></tr>
      <tr><td>Honeypots dropped</td><td>{_fmt(stats['honeypot'])}</td><td>Research boxes, not prospects.</td></tr>
      <tr><td>RAT / tank-gauge / DICOM probes</td><td>{_fmt(stats['probe_banners'])}</td><td>The probe ran. That is not a detection.</td></tr>
      <tr><td>Those probes actually confirmed</td><td>{_fmt(stats['probe_banners_confirmed'])}</td><td>About 2%. A module name alone never becomes a finding.</td></tr>
    </tbody>
  </table>

  <h2>How an account gets its number</h2>
  <ul>
    <li>Priority is the single worst confirmed issue, plus 8 points for each extra kind of problem, capped at 24. It is not a count of banners.</li>
    <li>EPSS decides timing. A verified CVSS 10 with EPSS near 1 (SMBGhost) outranks a pile of end-of-life nginx.</li>
    <li>The company name comes from a real hostname. Reverse DNS, Shodan's stripped <code>domains</code> field, cloud PTR, and hoster zones are not the buyer.</li>
    <li>The call note is filled from the evidence row. No model writes it, so it cannot invent a CVE.</li>
    <li>Country is where the exposed host sits, not the company's headquarters.</li>
  </ul>

  <h2>Call now — top named domains</h2>
  <p class="muted">Some provider zones still rank high when the hostname has no reverse-DNS tell (<code>skystark.net</code>, <code>stimo.net</code>). The cards under the table are the ones a rep can defend without that caveat.</p>
  <table>
    <thead><tr><th>#</th><th>Pri</th><th>Account</th><th>Why it is on the list</th></tr></thead>
    <tbody>
      {''.join(top_rows)}
    </tbody>
  </table>

  <h2>Accounts worth opening first</h2>
  {''.join(cards)}

  <h2>Confirmed finding types in the whole file</h2>
  <table>
    <thead><tr><th>Type</th><th>Findings</th></tr></thead>
    <tbody>
      {''.join(
        f"<tr><td>{_esc(CLASS_LABEL.get(key.split(':',1)[1], key))}</td><td>{_fmt(value)}</td></tr>"
        for key, value in sorted(stats.items()) if str(key).startswith('class:')
      )}
    </tbody>
  </table>
  <p class="muted">Mart generated { _esc(meta.get('generated_at', '')) }. Source repo: signalboard. Raw banners are not in this file.</p>
</main>
</body>
</html>
"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(body, encoding="utf-8")
    return out_path


def _clean_detail(detail: str) -> str:
    text = detail or ""
    if "([]uint8)" in text or "00000030" in text:
        return "Scanner confirmed the issue. Raw probe bytes are omitted from this file."
    if len(text) > 360:
        return text[:357].rsplit(" ", 1)[0] + "…"
    return text


def _desk_payload(db_path: Path) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    meta = json.loads(conn.execute("select v from meta where k = 'ingest'").fetchone()["v"])
    accounts = []
    index_of = {}
    rows = conn.execute(
        """
        select account_key, kind, name, domain, org_hint, asn, country,
               priority, pain, urgency, breadth, queue, ip_count,
               why_now, call_brief, breakdown
        from accounts
        order by priority desc, finding_count desc
        """
    )
    for row in rows:
        index_of[row["account_key"]] = len(accounts)
        scored = json.loads(row["breakdown"])
        accounts.append([
            row["account_key"],
            row["kind"],
            row["name"],
            row["domain"] or "",
            row["org_hint"] or "",
            row["asn"] or "",
            row["country"] or "",
            row["priority"],
            row["pain"],
            row["urgency"],
            row["breadth"],
            row["queue"],
            row["ip_count"],
            row["why_now"] or "",
            row["call_brief"] or "",
            [[klass, points] for klass, points in (scored.get("by_class") or {}).items()],
        ])
    findings: list[list] = [[] for _ in accounts]
    for row in conn.execute(
        """
        select account_key, klass, points, title, detail, ip, port, cve, cvss, epss, evidence
        from findings
        order by account_key, points desc
        """
    ):
        slot = index_of.get(row["account_key"])
        if slot is None:
            continue
        findings[slot].append([
            row["klass"],
            row["points"],
            row["title"] or "",
            _clean_detail(row["detail"] or ""),
            row["ip"] or "",
            row["port"],
            row["cve"] or "",
            row["cvss"],
            None if row["epss"] is None else round(float(row["epss"]), 5),
            row["evidence"] or "",
        ])
    counts = {
        "accounts": len(accounts),
        "findings": sum(len(items) for items in findings),
        "by_queue": {},
        "by_kind": {},
    }
    countries: dict[str, int] = {}
    for account in accounts:
        counts["by_queue"][account[11]] = counts["by_queue"].get(account[11], 0) + 1
        counts["by_kind"][account[1]] = counts["by_kind"].get(account[1], 0) + 1
        if account[6]:
            countries[account[6]] = countries.get(account[6], 0) + 1
    conn.close()
    return {
        "meta": {
            "records": meta.get("records"),
            "elapsed_sec": meta.get("elapsed_sec"),
            "banners_per_sec": meta.get("banners_per_sec"),
            "generated_at": meta.get("generated_at"),
            "files": meta.get("files") or [],
            "stats": {
                "honeypot": meta["stats"].get("honeypot", 0),
                "unverified_cves": meta["stats"].get("unverified_cves", 0),
            },
        },
        "counts": counts,
        "countries": [
            {"country": code, "n": count}
            for code, count in sorted(countries.items(), key=lambda item: (-item[1], item[0]))
        ],
        "classes": CLASS_LABEL,
        "accounts": accounts,
        "findings": findings,
    }


_DESK_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Signalboard</title>
<style>
  :root {
    --paper: #f3efe6; --ink: #1c1915; --muted: #5e584e; --line: #ddd4c4; --card: #fffdf8;
    --rust: #9a3412; --now: #9f1239; --month: #92400e; --nurture: #3f6212; --chip: #efe8db;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body {
    font-family: "Avenir Next", "Segoe UI", sans-serif;
    color: var(--ink);
    background: radial-gradient(1200px 400px at 10% -10%, #efe2cf 0%, transparent 50%), var(--paper);
  }
  header { display: flex; justify-content: space-between; gap: 24px; align-items: flex-end; padding: 22px 28px 12px; }
  h1 { font-family: Palatino, "Iowan Old Style", Georgia, serif; font-weight: 560; font-size: 34px; margin: 0; letter-spacing: -0.03em; }
  header p { margin: 4px 0 0; color: var(--muted); max-width: 720px; }
  header a { color: var(--rust); }
  .meta-line { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--muted); text-align: right; }
  .stats { display: flex; gap: 10px; padding: 0 28px 12px; flex-wrap: wrap; }
  .stat { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 8px 12px; min-width: 120px; }
  .stat b { display: block; font-family: Palatino, Georgia, serif; font-size: 22px; font-weight: 560; }
  .stat span { color: var(--muted); font-size: 12px; }
  .layout { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(340px, 0.85fr); gap: 14px; padding: 0 28px 28px; height: calc(100% - 190px); }
  .panel { background: var(--card); border: 1px solid var(--line); border-radius: 14px; min-height: 0; display: flex; flex-direction: column; }
  .filters { display: flex; gap: 8px; flex-wrap: wrap; padding: 12px; border-bottom: 1px solid var(--line); align-items: center; }
  input, select, button { font: inherit; color: var(--ink); background: var(--paper); border: 1px solid var(--line); border-radius: 8px; padding: 7px 10px; }
  input[type="search"] { min-width: 220px; flex: 1; }
  button { cursor: pointer; background: var(--ink); color: #f6f1e7; border-color: var(--ink); }
  button.ghost { background: transparent; color: var(--ink); }
  .chips { display: flex; gap: 6px; }
  .chips button[aria-pressed="true"] { background: var(--rust); border-color: var(--rust); color: white; }
  .list { overflow: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); padding: 8px 10px; position: sticky; top: 0; background: var(--card); }
  td { padding: 10px; border-top: 1px solid var(--line); vertical-align: top; font-size: 14px; }
  tr { cursor: pointer; }
  tr:hover, tr.active { background: #faf6ee; }
  .prio { font-family: Palatino, Georgia, serif; font-size: 22px; }
  .badge { display: inline-block; font-size: 11px; font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase; padding: 2px 6px; border-radius: 999px; }
  .badge.now { color: var(--now); background: #ffe4e6; }
  .badge.month { color: var(--month); background: #ffedd5; }
  .badge.nurture { color: var(--nurture); background: #ecfccb; }
  .sub { color: var(--muted); font-size: 12px; }
  .pager { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; border-top: 1px solid var(--line); font-size: 13px; }
  .detail { overflow: auto; padding: 16px 18px 24px; }
  .detail h2 { font-family: Palatino, Georgia, serif; font-weight: 560; margin: 0 0 4px; font-size: 28px; }
  .brief { background: #1c1915; color: #f6f1e7; border-radius: 12px; padding: 14px 16px; line-height: 1.45; }
  .bars { display: grid; gap: 6px; margin: 14px 0; }
  .bar { display: grid; grid-template-columns: 140px 1fr 28px; gap: 8px; align-items: center; font-size: 12px; }
  .bar i { display: block; height: 8px; background: var(--chip); border-radius: 99px; }
  .bar i span { display: block; height: 8px; background: var(--rust); border-radius: 99px; }
  .finding { border-top: 1px solid var(--line); padding: 12px 0; }
  .finding h3 { margin: 0 0 4px; font-size: 15px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .empty { color: var(--muted); padding: 28px 8px; }
  .method { font-size: 13px; color: var(--muted); line-height: 1.5; }
  .method summary { cursor: pointer; color: var(--ink); font-weight: 600; }
  @media (max-width: 980px) {
    .layout { grid-template-columns: 1fr; height: auto; }
    header { flex-direction: column; align-items: flex-start; }
    .meta-line { text-align: left; }
  }
</style>
</head>
<body>
<header>
  <div>
    <h1>Signalboard</h1>
    <p>Who needs a cybersecurity conversation this week, based on confirmed exposure. Not a count of open ports. This file is the full desk and opens with the laptop closed.</p>
    <p>Live desk, only while this Mac is awake: <a href="__LIVE_URL__">__LIVE_URL__</a></p>
  </div>
  <div class="meta-line" id="meta">Loading the full desk…</div>
</header>
<section class="stats" id="stats"></section>
<main class="layout">
  <section class="panel">
    <div class="filters">
      <input id="q" type="search" placeholder="Search domain, network, CVE…" />
      <div class="chips" id="queues">
        <button class="ghost" data-queue="" aria-pressed="true">All</button>
        <button class="ghost" data-queue="now">Now</button>
        <button class="ghost" data-queue="month">This month</button>
        <button class="ghost" data-queue="nurture">Nurture</button>
      </div>
      <select id="kind">
        <option value="domain">Named domain</option>
        <option value="">Any attribution</option>
        <option value="org">Network owner</option>
        <option value="ip">IP only</option>
      </select>
      <select id="country"><option value="">Any country</option></select>
      <select id="klass"><option value="">Any signal</option></select>
      <button id="export" class="ghost" type="button">Export CSV</button>
    </div>
    <div class="list">
      <table>
        <thead><tr><th>Pri</th><th>Account</th><th>Why it is on the list</th><th>IPs</th></tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <div class="pager">
      <span id="pageinfo"></span>
      <span>
        <button id="prev" class="ghost" type="button">Prev</button>
        <button id="next" class="ghost" type="button">Next</button>
      </span>
    </div>
  </section>
  <section class="panel detail" id="detail">
    <div class="empty">Select an account. The note on the right is filled only from scanner evidence, so it cannot invent a CVE.</div>
  </section>
</main>
"""

_DESK_SCRIPT = r"""
<script>
const data = JSON.parse(document.getElementById("payload").textContent);
const accounts = data.accounts;
const findings = data.findings;
const searchText = accounts.map(a => [a[2], a[3], a[4], a[0], a[13]].join("\n").toLowerCase());
const state = { page: 1, pageSize: 40, queue: "", total: 0, selected: null, filtered: [] };

function badge(queue) {
  const label = queue === "now" ? "Now" : queue === "month" ? "This month" : "Nurture";
  return `<span class="badge ${queue}">${label}</span>`;
}
function kindLabel(kind) {
  return kind === "domain" ? "Named domain" : kind === "org" ? "Network owner" : "IP only";
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}
function classLabels(pairs) {
  return (pairs || []).map(pair => data.classes[pair[0]] || pair[0]);
}

function loadStats() {
  const m = data.meta || {};
  const files = (m.files || []).map(f => f.name).join(", ") || "mart";
  const rate = m.banners_per_sec ? `${Math.round(m.banners_per_sec).toLocaleString()} banners/s` : "";
  document.getElementById("meta").textContent =
    `${(m.records || 0).toLocaleString()} banners · ${files} · ${m.generated_at || ""} · ${rate} · offline copy`;
  const c = data.counts || {};
  const q = c.by_queue || {};
  const rejected = (m.stats || {});
  document.getElementById("stats").innerHTML = [
    ["Accounts", c.accounts || 0],
    ["Call now", q.now || 0],
    ["This month", q.month || 0],
    ["Honeypots dropped", rejected.honeypot || 0],
    ["Unverified CVEs ignored", rejected.unverified_cves || 0],
  ].map(([label, n]) => `<div class="stat"><b>${Number(n).toLocaleString()}</b><span>${label}</span></div>`).join("");
  const country = document.getElementById("country");
  country.innerHTML = `<option value="">Any country</option>` + (data.countries || [])
    .map(row => `<option value="${row.country}">${row.country} (${row.n.toLocaleString()})</option>`).join("");
  const klass = document.getElementById("klass");
  klass.innerHTML = `<option value="">Any signal</option>` + Object.entries(data.classes || {})
    .map(([key, label]) => `<option value="${key}">${label}</option>`).join("");
}

function applyFilter() {
  const q = document.getElementById("q").value.trim().toLowerCase();
  const kind = document.getElementById("kind").value;
  const country = document.getElementById("country").value;
  const klass = document.getElementById("klass").value;
  const filtered = [];
  for (let i = 0; i < accounts.length; i++) {
    const a = accounts[i];
    if (state.queue && a[11] !== state.queue) continue;
    if (kind && a[1] !== kind) continue;
    if (country && a[6] !== country) continue;
    if (klass && !(a[15] || []).some(pair => pair[0] === klass)) continue;
    if (q && !searchText[i].includes(q)) continue;
    filtered.push(i);
  }
  state.filtered = filtered;
  state.total = filtered.length;
}

function renderPage() {
  const body = document.getElementById("rows");
  const start = (state.page - 1) * state.pageSize;
  const slice = state.filtered.slice(start, start + state.pageSize);
  body.innerHTML = slice.map(i => {
    const a = accounts[i];
    return `<tr data-i="${i}" class="${state.selected === i ? "active" : ""}">
      <td><div class="prio">${a[7]}</div>${badge(a[11])}</td>
      <td><strong>${escapeHtml(a[2])}</strong><div class="sub">${kindLabel(a[1])}${a[6] ? " · " + a[6] : ""}${a[4] ? " · " + escapeHtml(a[4]) : ""}</div></td>
      <td>${escapeHtml(a[13])}<div class="sub">${classLabels(a[15]).join(" · ")}</div></td>
      <td class="mono">${a[12]}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="4" class="empty">Nothing matches. Confirmed exposures only, so a quiet filter is expected.</td></tr>`;
  const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
  document.getElementById("pageinfo").textContent = `${state.total.toLocaleString()} accounts · page ${state.page} of ${pages}`;
  body.querySelectorAll("tr[data-i]").forEach(tr => { tr.onclick = () => openAccount(Number(tr.dataset.i)); });
}

function loadAccounts() {
  applyFilter();
  renderPage();
}

function openAccount(i) {
  state.selected = i;
  const a = accounts[i];
  const bars = (a[15] || []).slice().sort((x, y) => y[1] - x[1]).map(([k, v]) => `
    <div class="bar"><span>${escapeHtml(data.classes[k] || k)}</span><i><span style="width:${Math.min(100, v)}%"></span></i><b>${v}</b></div>`).join("");
  const rows = (findings[i] || []).map(f => `
    <article class="finding">
      <h3>${escapeHtml(f[2])} <span class="badge month">${f[1]} pts</span></h3>
      <div class="mono">${escapeHtml(f[4] || "")}:${f[5] ?? ""} ${f[6] ? "· " + escapeHtml(f[6]) : ""} ${f[7] ? "· CVSS " + f[7] : ""} ${f[8] != null ? "· EPSS " + Number(f[8]).toFixed(3) : ""}</div>
      <p>${escapeHtml(f[3] || "")}</p>
      <p class="sub">${escapeHtml(f[9] || "")}</p>
    </article>`).join("");
  document.getElementById("detail").innerHTML = `
    <div class="sub">${kindLabel(a[1])} · priority ${a[7]} · pain ${a[8]} · urgency ${a[9]} + breadth ${a[10]}</div>
    <h2>${escapeHtml(a[2])}</h2>
    <p class="sub">${a[3] ? escapeHtml(a[3]) + " · " : ""}${a[6] || "country unknown"}${a[4] ? " · network " + escapeHtml(a[4]) : ""}${a[5] ? " · " + escapeHtml(a[5]) : ""}</p>
    <div class="brief">${escapeHtml(a[14])}</div>
    <div class="bars">${bars}</div>
    <h3>Evidence</h3>
    ${rows}
    <details class="method">
      <summary>How this number was built</summary>
      <p>Priority is the worst confirmed issue (urgency) plus 8 points for each extra kind of problem, capped at 24. It is not a count of banners. Unverified CVEs, honeypots, CDN challenge pages, and malware-module probes that came back as ordinary HTTP are not in the score. Certificate findings are kept only when a real domain was on the banner. Network-owner rows have no customer hostname, so confirm the org before you write.</p>
    </details>`;
  document.querySelectorAll("#rows tr").forEach(tr => tr.classList.toggle("active", Number(tr.dataset.i) === i));
}

function csvCell(value) {
  const text = String(value ?? "");
  if (/[",\n]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
  return text;
}

document.getElementById("queues").onclick = (event) => {
  const btn = event.target.closest("button");
  if (!btn) return;
  state.queue = btn.dataset.queue;
  state.page = 1;
  document.querySelectorAll("#queues button").forEach(b => b.setAttribute("aria-pressed", b === btn ? "true" : "false"));
  loadAccounts();
};
["kind", "country", "klass"].forEach(id => {
  document.getElementById(id).onchange = () => { state.page = 1; loadAccounts(); };
});
let timer = 0;
document.getElementById("q").oninput = () => {
  clearTimeout(timer);
  timer = setTimeout(() => { state.page = 1; loadAccounts(); }, 200);
};
document.getElementById("prev").onclick = () => { if (state.page > 1) { state.page--; renderPage(); } };
document.getElementById("next").onclick = () => {
  if (state.page * state.pageSize < state.total) { state.page++; renderPage(); }
};
document.getElementById("export").onclick = () => {
  applyFilter();
  const header = ["name", "domain", "kind", "country", "queue", "priority", "pain", "why_now", "network", "asn", "ips"];
  const lines = [header.join(",")];
  state.filtered.forEach(i => {
    const a = accounts[i];
    lines.push([a[2], a[3], a[1], a[6], a[11], a[7], a[8], a[13], a[4], a[5], a[12]].map(csvCell).join(","));
  });
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "signalboard.csv";
  link.click();
  URL.revokeObjectURL(link.href);
};

loadStats();
loadAccounts();
</script>
</body>
</html>
"""


def build_desk(db_path: Path, out_path: Path, live_url: str = LIVE_URL) -> Path:
    """Write one HTML file with every account, finding, filter, and CSV export."""
    payload = _desk_payload(db_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    with out_path.open("w", encoding="utf-8") as handle:
        handle.write(_DESK_HEAD.replace("__LIVE_URL__", html.escape(live_url, quote=True)))
        handle.write('<script id="payload" type="application/json">')
        handle.write(encoded)
        handle.write("</script>\n")
        handle.write(_DESK_SCRIPT)
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the Signalboard HTML report")
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--url", default=LIVE_URL)
    parser.add_argument("--summary", action="store_true", help="Write the short leave-behind instead of the full desk")
    args = parser.parse_args()
    if args.summary:
        path = build_report(Path(args.db), Path(args.out), args.url)
    else:
        path = build_desk(Path(args.db), Path(args.out), args.url)
    print(path)


if __name__ == "__main__":
    main()
