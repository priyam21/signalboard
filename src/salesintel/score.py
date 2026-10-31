"""Account priority from confirmed findings.

Priority is the single worst issue, plus a small bump when a second kind of
problem shows up. It is not a count of banners, open ports, or unverified CVEs.
One scanner-verified critical beats a long tail of missing headers.
"""

from __future__ import annotations

CLASS_CAP = {
    "verified_cve": 50,
    "heartbleed": 40,
    "malware": 45,
    "ransomware_entry": 40,
    "data_store": 40,
    "control_plane": 36,
    "ot_ics": 36,
    "camera": 24,
    "eol": 16,
    "trust": 16,
    "exposure": 18,
}

CLASS_LABEL = {
    "verified_cve": "Verified CVE",
    "heartbleed": "Heartbleed",
    "malware": "Malware service",
    "ransomware_entry": "Ransomware entry",
    "data_store": "Exposed data store",
    "control_plane": "Exposed control plane",
    "ot_ics": "OT / clinical",
    "camera": "Camera / DVR",
    "eol": "End of life",
    "trust": "Certificate trust",
    "exposure": "Information exposure",
}


def queue_for(findings: list[dict]) -> str:
    for finding in findings:
        klass = finding["klass"]
        points = finding["points"]
        epss = finding.get("epss") or 0
        cvss = finding.get("cvss") or 0
        if klass in ("malware", "heartbleed"):
            return "now"
        if klass == "ransomware_entry" and points >= 20:
            return "now"
        if klass == "data_store" and points >= 28:
            return "now"
        if klass == "control_plane" and points >= 22:
            return "now"
        if klass == "ot_ics" and points >= 20:
            return "now"
        if klass == "verified_cve" and (epss >= 0.4 or cvss >= 9):
            return "now"
    if any(finding["points"] >= 12 for finding in findings):
        return "month"
    return "nurture"


def score_findings(findings: list[dict]) -> dict:
    by_class: dict[str, int] = {}
    for finding in findings:
        by_class[finding["klass"]] = by_class.get(finding["klass"], 0) + int(finding["points"])
    capped = {klass: min(CLASS_CAP.get(klass, 20), points) for klass, points in by_class.items()}
    urgency = max((int(finding["points"]) for finding in findings), default=0)
    classes = sorted(klass for klass, points in capped.items() if points > 0)
    breadth = min(24, max(0, len(classes) - 1) * 8)
    priority = min(100, urgency + breadth)
    pain = min(100, sum(capped.values()))
    return {
        "urgency": urgency,
        "breadth": breadth,
        "priority": priority,
        "pain": pain,
        "queue": queue_for(findings),
        "classes": classes,
        "by_class": capped,
    }
