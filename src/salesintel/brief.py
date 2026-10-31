"""Deterministic call notes. No model, so the text cannot invent a CVE."""

from __future__ import annotations

from salesintel.score import CLASS_LABEL


def _top(findings: list[dict]) -> dict:
    return max(findings, key=lambda finding: (finding["points"], finding.get("epss") or 0))


def why_now(findings: list[dict]) -> str:
    top = _top(findings)
    where = f"{top.get('ip') or 'unknown ip'}:{top.get('port')}"
    if top.get("cve"):
        epss = top.get("epss")
        epss_bit = f", EPSS {epss:.2f}" if isinstance(epss, (int, float)) else ""
        return f"{top['cve']} is scanner-verified{epss_bit} on {where}."
    return f"{top['title']} on {where}."


def call_brief(display_name: str, findings: list[dict], kind: str) -> str:
    top = _top(findings)
    where = f"{top.get('ip') or 'unknown ip'}:{top.get('port')}"
    opener = f"{display_name}: {top['title']} ({where})."
    if top.get("cve"):
        cvss = top.get("cvss")
        epss = top.get("epss")
        middle = (
            f"{top['cve']} was verified by the scanner"
            + (f", CVSS {cvss:g}" if isinstance(cvss, (int, float)) else "")
            + (f", EPSS {epss:.3f}" if isinstance(epss, (int, float)) else "")
            + ". Open with that host, not a generic security pitch."
        )
    else:
        detail = (top.get("detail") or "").strip()
        middle = detail or top.get("evidence") or "The protocol was identified, not just an open port."
    extra = len(findings) - 1
    if extra:
        kinds = sorted({CLASS_LABEL.get(f["klass"], f["klass"]) for f in findings})
        tail = f" {extra} other confirmed issue{'s' if extra != 1 else ''} ({', '.join(kinds)})."
    else:
        tail = ""
    if kind == "org":
        reach = " No customer domain was on the banner, so this is the network owner. Confirm it is their own environment before you write."
    elif kind == "ip":
        reach = " No company name was visible. Use this only if you can resolve who operates the host."
    else:
        reach = " Ask who owns that host and whether it is supposed to be reachable from the internet."
    return f"{opener} {middle}{tail}{reach}"
