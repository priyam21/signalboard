"""Turn one Shodan banner into confirmed sales signals.

The file is full of scanner theatre: malware modules that received an HTTP 400,
CVE rows Shodan did not verify, CDN edges, honeypots. None of those become a
finding. A finding needs a parsed protocol, a verified CVE, or an explicit
end-of-life version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from salesintel.attribution import best_domain, is_infra_org, org_name

PROBE_MODULES = {
    "remcos-pro-rat",
    "darktrack-rat",
    "orcus-rat",
    "automated-tank-gauge",
    "dicom",
    "dahua-dvr",
    "dahua-dvr-web",
}

_ANCIENT = re.compile(
    r"(apache/2\.[0-2](?:[.\s]|$))"
    r"|(microsoft-iis/[67](?:[.\s]|$))"
    r"|(?:^|[\s/])iis/[67]\.[05]"
    r"|(php/[45](?:[.\s]|$))"
    r"|(openssl/1\.0\.[12])"
    r"|(nginx/1\.(?:[0-9]|1[0-7])\.)",
    re.I,
)

_MALWARE_PRODUCT = (
    "remcos",
    "darktrack",
    "orcus",
    "meterpreter",
    "cobalt strike",
    "metasploit",
)


@dataclass
class BannerView:
    findings: list[dict] = field(default_factory=list)
    domain: str | None = None
    org: str | None = None
    org_is_infra: bool = False
    skip: str | None = None
    unverified_cves: int = 0
    weak_verified_cves: int = 0
    probe_module: str | None = None
    country: str = ""
    ip: str = ""
    asn: str = ""
    port: int | None = None


def _tags(rec: dict) -> set[str]:
    raw = rec.get("tags") or []
    if not isinstance(raw, list):
        return set()
    return {str(t).lower() for t in raw}


def _headers(rec: dict) -> dict[str, str]:
    http = rec.get("http")
    if not isinstance(http, dict):
        return {}
    headers = http.get("headers")
    if not isinstance(headers, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items() if v is not None}


def _country(rec: dict) -> str:
    loc = rec.get("location") or {}
    if not isinstance(loc, dict):
        return ""
    return str(loc.get("country_code") or "")


def _cve_points(cvss: float, epss: float) -> int:
    base = float(cvss or 0) * 3.0
    if epss >= 0.5:
        base *= 1.4
    elif epss >= 0.1:
        base *= 1.15
    return int(min(45, round(base)))


def _add(findings: list[dict], item: dict) -> None:
    for existing in findings:
        if (
            existing["klass"] == item["klass"]
            and existing.get("cve") == item.get("cve")
            and existing.get("port") == item.get("port")
        ):
            if item["points"] > existing["points"]:
                existing.update(item)
            return
    findings.append(item)


def _base(rec: dict, **extra) -> dict:
    product = rec.get("product") or ""
    version = rec.get("version") or ""
    return {
        "ip": rec.get("ip_str") or "",
        "port": rec.get("port"),
        "product": str(product)[:120],
        "version": str(version)[:60],
        "cve": None,
        "cvss": None,
        "epss": None,
        "verified": False,
        "country": _country(rec),
        **extra,
    }


def _verified_cves(rec: dict, findings: list[dict], view: BannerView) -> None:
    vulns = rec.get("vulns") or {}
    if not isinstance(vulns, dict):
        return
    for cve, detail in vulns.items():
        if not isinstance(detail, dict) or not detail.get("verified"):
            view.unverified_cves += 1
            continue
        try:
            cvss = float(detail.get("cvss") or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        try:
            epss = float(detail.get("epss") or 0)
        except (TypeError, ValueError):
            epss = 0.0
        if cvss < 7 and epss < 0.05:
            view.weak_verified_cves += 1
            continue
        summary = str(detail.get("summary") or "").strip()
        points = _cve_points(cvss, epss)
        _add(findings, _base(
            rec,
            klass="verified_cve",
            points=points,
            title=f"{cve} verified on {rec.get('product') or 'this service'}",
            detail=summary[:420],
            cve=str(cve),
            cvss=cvss,
            epss=epss,
            verified=True,
            evidence=(
                f"Scanner-verified. CVSS {cvss:g}. "
                f"EPSS {epss:.3f} (chance of exploit activity in the next 30 days)."
            ),
        ))


def _heartbleed(rec: dict, findings: list[dict]) -> None:
    raw = (rec.get("opts") or {}).get("heartbleed") if isinstance(rec.get("opts"), dict) else None
    if not isinstance(raw, str):
        return
    upper = raw.upper()
    if "VULNERABLE" not in upper or "NOT VULNERABLE" in upper or "SAFE" in upper:
        return
    _add(findings, _base(
        rec,
        klass="heartbleed",
        points=40,
        title="Heartbleed still exploitable",
        detail=raw.strip()[:300],
        cve="CVE-2014-0160",
        cvss=7.5,
        epss=0.9,
        verified=True,
        evidence="Heartbeat probe returned vulnerable, not an error and not SAFE.",
    ))


def _malware_product(rec: dict, findings: list[dict]) -> None:
    product = str(rec.get("product") or "")
    info = rec.get("info")
    info_s = info if isinstance(info, str) else ""
    # Module name is intentionally excluded. Probes fire on ordinary web servers.
    blob = f"{product} {info_s}".lower()
    if not any(token in blob for token in _MALWARE_PRODUCT):
        return
    _add(findings, _base(
        rec,
        klass="malware",
        points=45,
        title=f"Malware service identified: {product or info_s[:60]}",
        detail="The scanner named the malware family from the service banner, not from the probe module.",
        evidence="Product or info field names a malware family.",
    ))


def _ransomware(rec: dict, findings: list[dict]) -> None:
    product = str(rec.get("product") or "").lower()
    port = rec.get("port")
    smb = rec.get("smb")
    if isinstance(smb, dict):
        version = smb.get("smb_version")
        _add(findings, _base(
            rec,
            klass="ransomware_entry",
            points=26,
            title=f"SMB{'' if version is None else version} reachable from the internet",
            detail="File shares on the open internet are a standard ransomware entry point.",
            evidence="SMB handshake parsed (not a bare open port).",
        ))
    elif port == 445 and "smb" in product:
        _add(findings, _base(
            rec,
            klass="ransomware_entry",
            points=26,
            title="SMB reachable from the internet",
            detail="File shares on the open internet are a standard ransomware entry point.",
            evidence="Product identified as SMB.",
        ))
    if "remote desktop" in product or isinstance(rec.get("rdp_encryption"), dict):
        _add(findings, _base(
            rec,
            klass="ransomware_entry",
            points=28,
            title="RDP exposed to the internet",
            detail="Remote Desktop on a public IP is one of the most common ransomware doors.",
            evidence="RDP protocol identified.",
        ))
    if isinstance(rec.get("vnc"), dict) or "vnc" in product:
        _add(findings, _base(
            rec,
            klass="ransomware_entry",
            points=24,
            title="VNC exposed to the internet",
            detail="A graphical remote console is reachable without a VPN in front of it.",
            evidence="VNC protocol identified.",
        ))
    if isinstance(rec.get("telnet"), dict) or product == "telnet" or product.startswith("telnet "):
        _add(findings, _base(
            rec,
            klass="ransomware_entry",
            points=24,
            title="Telnet exposed to the internet",
            detail="Telnet sends credentials in the clear.",
            evidence="Telnet protocol identified.",
        ))


def _data_stores(rec: dict, findings: list[dict]) -> None:
    product = str(rec.get("product") or "").lower()
    elastic = rec.get("elastic")
    if isinstance(elastic, dict) and (elastic.get("indices") or elastic.get("tagline")):
        names = list((elastic.get("indices") or {}).keys())[:5]
        shown = ", ".join(names) if names else "cluster metadata"
        _add(findings, _base(
            rec,
            klass="data_store",
            points=34,
            title="Elasticsearch open to the internet",
            detail=f"Index data is readable without authenticating. Sample: {shown}"[:420],
            evidence="Elasticsearch returned indices or the default unauthenticated tagline.",
        ))
    redis = rec.get("redis")
    if isinstance(redis, dict) and redis.get("authentication_required") is not True:
        if any(k for k in redis.keys() if k != "authentication_required"):
            _add(findings, _base(
                rec,
                klass="data_store",
                points=32,
                title="Redis open to the internet",
                detail="The scanner read Redis metadata without credentials.",
                evidence="Redis responded and authentication_required is not true.",
            ))
    for key in ("mongo", "mongodb"):
        mongo = rec.get(key)
        if isinstance(mongo, dict) and (
            mongo.get("databases") or mongo.get("buildInfo") or mongo.get("listDatabases")
        ):
            if mongo.get("authentication") is True or mongo.get("authentication_required") is True:
                break
            _add(findings, _base(
                rec,
                klass="data_store",
                points=32,
                title="MongoDB open to the internet",
                detail="Database names or build info were returned without authentication.",
                evidence="MongoDB listing parsed.",
            ))
            break
    if isinstance(rec.get("mysql"), dict) or "mysql" in product:
        _add(findings, _base(
            rec,
            klass="data_store",
            points=16,
            title="MySQL reachable from the internet",
            detail="The database port answers on a public IP. Even with a password, it will be brute-forced.",
            evidence="MySQL protocol identified.",
        ))
    if "postgres" in product or isinstance(rec.get("postgresql"), dict):
        _add(findings, _base(
            rec,
            klass="data_store",
            points=16,
            title="PostgreSQL reachable from the internet",
            detail="The database port answers on a public IP.",
            evidence="PostgreSQL identified.",
        ))
    if "microsoft sql" in product or "mssql" in product or isinstance(rec.get("mssql"), dict):
        _add(findings, _base(
            rec,
            klass="data_store",
            points=18,
            title="SQL Server reachable from the internet",
            detail="MSSQL on a public IP is a frequent ransomware and data-theft target.",
            evidence="SQL Server identified.",
        ))


def _control_plane(rec: dict, findings: list[dict]) -> None:
    product = str(rec.get("product") or "").lower()
    port = rec.get("port")
    k8s = rec.get("kubernetes")
    if isinstance(k8s, dict) or product == "kubernetes":
        version = ""
        if isinstance(k8s, dict):
            version = str(k8s.get("version") or k8s.get("git_version") or "")
        _add(findings, _base(
            rec,
            klass="control_plane",
            points=26,
            title="Kubernetes API exposed to the internet",
            detail=(f"API responded{(': ' + version) if version else ''}. "
                    "An exposed control plane is a full-cluster compromise path.").strip(),
            evidence="Kubernetes API parsed.",
        ))
    if "docker" in product and port in (2375, 2376, 4243, 2377):
        _add(findings, _base(
            rec,
            klass="control_plane",
            points=32,
            title="Docker API exposed to the internet",
            detail="An open Docker API can start containers as root on the host.",
            evidence="Docker identified on the API port.",
        ))
    if "jenkins" in product:
        _add(findings, _base(
            rec,
            klass="control_plane",
            points=22,
            title="Jenkins exposed to the internet",
            detail="Build servers hold source, secrets, and a path onto production.",
            evidence="Jenkins identified.",
        ))
    if "winbox" in product or isinstance(rec.get("mikrotik_winbox"), dict):
        _add(findings, _base(
            rec,
            klass="control_plane",
            points=22,
            title="MikroTik Winbox exposed to the internet",
            detail="Winbox is the router admin interface. It does not belong on a public IP.",
            evidence="Winbox identified.",
        ))


def _cameras(rec: dict, findings: list[dict]) -> None:
    product = str(rec.get("product") or "").lower()
    if (
        isinstance(rec.get("hikvision"), dict)
        or isinstance(rec.get("dahua_dvr_web"), dict)
        or "hikvision" in product
        or "dahua" in product
        or "ip camera" in product
    ):
        _add(findings, _base(
            rec,
            klass="camera",
            points=18,
            title="Camera or DVR exposed to the internet",
            detail="Internet-facing cameras are regularly recruited into botnets and are an easy way into a site network.",
            evidence="Camera vendor protocol or product identified.",
        ))


def _payload_is_noise(data: str) -> bool:
    """HTTP errors and TLS handshakes are not an OT confirmation."""
    if not data or len(data) < 24:
        return True
    if data.startswith(("HTTP/", "{", "<", "SSH-", "220 ")):
        return True
    if data.startswith(("\x16\x03", "\x15\x03", "\\x16", "\\x15")):
        return True
    return False


def _ot(rec: dict, findings: list[dict]) -> None:
    product = str(rec.get("product") or "").lower()
    data = rec.get("data") if isinstance(rec.get("data"), str) else ""
    module = ""
    shodan = rec.get("_shodan")
    if isinstance(shodan, dict):
        module = str(shodan.get("module") or "")
    if any(token in product for token in ("modbus", "siemens", "bacnet", "tank gauge", "dicom", "plc")):
        confirmed = True
        why = "Product name is an OT or medical protocol."
    else:
        # 10001 is common and not OT. Tank gauges count only via the module plus a real payload.
        interesting_port = rec.get("port") in (502, 102, 44818, 20000, 47808, 104, 11112)
        confirmed = not _payload_is_noise(data) and (
            module in ("automated-tank-gauge", "dicom") or interesting_port
        )
        why = "Non-HTTP payload on an OT or medical probe, so the module was not just a failed guess."
    if not confirmed:
        return
    _add(findings, _base(
        rec,
        klass="ot_ics",
        points=30,
        title="Industrial or clinical system on the internet",
        detail="OT and DICOM endpoints are high-consequence and usually have no security owner.",
        evidence=why,
    ))


def _eol(rec: dict, findings: list[dict], tags: set[str]) -> None:
    product = str(rec.get("product") or "")
    version = str(rec.get("version") or "")
    headers = _headers(rec)
    banner = " ".join(
        part for part in (headers.get("server", ""), headers.get("x-powered-by", ""), product, version) if part
    )
    if "eol-product" in tags and (product or version):
        _add(findings, _base(
            rec,
            klass="eol",
            points=12,
            title=f"End-of-life {product or 'software'} {version}".strip(),
            detail="The vendor no longer ships fixes. The next CVE becomes a permanent hole.",
            evidence="Shodan eol-product tag plus a named version.",
        ))
        return
    if banner and _ANCIENT.search(banner):
        _add(findings, _base(
            rec,
            klass="eol",
            points=12,
            title=f"Ancient software announced in the banner: {banner[:80]}",
            detail="The server header is volunteering an unsupported version.",
            evidence="Version string matched Apache 2.2, IIS 6/7, PHP 4/5, OpenSSL 1.0, or nginx < 1.18.",
        ))


def _trust(rec: dict, findings: list[dict], tags: set[str]) -> None:
    ssl = rec.get("ssl") if isinstance(rec.get("ssl"), dict) else {}
    cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
    if cert.get("expired") is True:
        subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
        cn = subject.get("CN") or ""
        _add(findings, _base(
            rec,
            klass="trust",
            points=14,
            title="Expired TLS certificate",
            detail=f"Certificate CN {cn} expired {cert.get('expires') or ''}".strip(),
            evidence="ssl.cert.expired is true.",
        ))
    if "self-signed" in tags:
        _add(findings, _base(
            rec,
            klass="trust",
            points=12,
            title="Self-signed certificate on a public hostname",
            detail="Browsers and partners will not trust this name. Often a stand-in for an unfinished edge.",
            evidence="self-signed tag. Kept only when a real customer domain is present.",
        ))


def _open_dir(rec: dict, findings: list[dict], tags: set[str]) -> None:
    if "open-dir" not in tags:
        return
    http = rec.get("http") if isinstance(rec.get("http"), dict) else {}
    title = http.get("title") or "directory listing"
    _add(findings, _base(
        rec,
        klass="exposure",
        points=16,
        title=f"Open directory ({title})"[:140],
        detail="A file listing is public. These often hold backups, exports, or keys.",
        evidence="open-dir tag.",
    ))


def _snmp(rec: dict, findings: list[dict]) -> None:
    snmp = rec.get("snmp")
    if not isinstance(snmp, dict):
        return
    versions = snmp.get("versions") or []
    legacy = False
    for version in versions:
        if version in (1, 2, "1", "2", "2c", "v1", "v2c"):
            legacy = True
    if not legacy:
        return
    name = snmp.get("enterprise_name") or "device"
    _add(findings, _base(
        rec,
        klass="exposure",
        points=14,
        title=f"SNMPv1/v2c exposed ({name})",
        detail="Legacy SNMP is usually readable with the community string 'public' and maps the internal network.",
        evidence="SNMP versions include v1 or v2c. SNMPv3-only banners are ignored.",
    ))


def interpret_banner(rec: dict) -> BannerView:
    view = BannerView(
        domain=best_domain(rec),
        org=org_name(rec),
        country=_country(rec),
        ip=str(rec.get("ip_str") or ""),
        asn=str(rec.get("asn") or ""),
        port=rec.get("port") if isinstance(rec.get("port"), int) else None,
    )
    view.org_is_infra = is_infra_org(view.org)
    tags = _tags(rec)
    if "honeypot" in tags:
        view.skip = "honeypot"
        return view
    shodan = rec.get("_shodan") if isinstance(rec.get("_shodan"), dict) else {}
    module = str(shodan.get("module") or "")
    if module in PROBE_MODULES:
        view.probe_module = module

    findings: list[dict] = []
    _verified_cves(rec, findings, view)
    _heartbleed(rec, findings)
    _malware_product(rec, findings)
    _ransomware(rec, findings)
    _data_stores(rec, findings)
    _control_plane(rec, findings)
    _cameras(rec, findings)
    _ot(rec, findings)
    _eol(rec, findings, tags)
    _trust(rec, findings, tags)
    _open_dir(rec, findings, tags)
    _snmp(rec, findings)
    view.findings = findings
    return view
