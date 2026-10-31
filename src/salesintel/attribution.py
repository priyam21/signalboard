"""Decide which business a banner belongs to.

Shodan `org` is usually the network operator (cloud, CDN, ISP), not the
buyer. Customer identity comes from a real virtual host. Reverse-DNS that
embeds the IP, and cloud PTR suffixes, are not companies.
"""

from __future__ import annotations

import re

# Second-level public suffixes we actually see in this corpus. Not a full PSL.
_MULTI = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "ad.jp", "gr.jp", "ed.jp", "lg.jp",
    "com.br", "com.mx", "com.sg", "com.hk", "com.tw", "com.cn",
    "com.tr", "co.za", "co.in", "com.ar", "co.kr", "com.my",
    "com.ph", "co.id", "net.id", "or.id", "ac.id", "web.id", "go.id",
    "com.vn", "co.th", "com.ua", "com.pl",
    "co.il", "com.ng", "com.pk", "co.ke", "com.gh", "com.co",
    "com.pe", "com.ec", "com.uy", "com.bo", "co.cr", "com.cy",
    "co.at", "or.at", "ac.at", "com.es", "com.pt", "edu.cn",
    "edu.sg", "edu.hk", "ac.za", "gov.uk",
    "com.tw", "net.tw", "org.tw", "idv.tw", "gov.tw", "edu.tw",
    "net.ua", "org.ua", "in.ua", "com.ua",
    "net.br", "org.br", "net.mx", "org.mx", "gob.mx",
    "net.au", "asn.au", "id.au",
    "gov.br", "edu.br", "gov.gr", "edu.gr", "com.gr", "net.gr", "org.gr",
    "co.mz", "ac.mz", "org.mz", "gov.mz", "net.mz",
    "com.py", "net.py", "org.py", "edu.py",
    "com.lb", "net.lb", "org.lb", "edu.lb", "gov.lb",
    "edu.hu", "gov.hu", "co.hu", "org.hu",
    "gov.za", "org.za", "net.za", "web.za",
    "go.jp", "go.kr", "ac.kr", "or.kr", "ne.kr",
    "gov.in", "ac.in", "net.in", "org.in", "gen.in",
    "edu.mx", "gov.cn", "net.cn", "org.cn",
    "net.tr", "org.tr", "gen.tr", "edu.tr", "gov.tr",
    "edu.pl", "com.pl", "net.pl", "org.pl", "gov.pl",
}

# Registrable domains that are infrastructure, not a sales account.
INFRA_DOMAINS = {
    "amazonaws.com", "amazonaws.com.cn", "cloudfront.net", "aws.dev",
    "googleusercontent.com", "googleapis.com", "googlehosted.com",
    "appspot.com", "withgoogle.com", "google.com", "goog",
    "azure.com", "azurewebsites.net", "cloudapp.net", "azure-api.net",
    "windows.net", "trafficmanager.net", "microsoft.com", "msedge.net",
    "akamaitechnologies.com", "akamaized.net", "akamaihd.net", "edgekey.net",
    "cloudflare.com", "cloudflaressl.com", "workers.dev",
    "incapdns.net", "impervadns.net",
    "fastly.net", "fastlylb.net",
    "digitaloceanspaces.com", "digitalocean.com",
    "linode.com", "linodeobjects.com",
    "vultr.com", "vultrusercontent.com",
    "oraclecloud.com", "oraclevcn.com",
    "aliyuncs.com", "alibabacloud.com", "myqcloud.com",
    "herokuapp.com", "herokussl.com",
    "github.io", "githubusercontent.com",
    "netlify.app", "vercel.app", "pages.dev", "firebaseapp.com",
    "wpengine.com", "wpenginepowered.com",
    "squarespace.com", "shopify.com", "myshopify.com",
    "cloudapp.azure.com",
    "bc.googleusercontent.com",
    # ISP and hoster zones used as reverse DNS for somebody else's machines.
    "sl-reverse.com", "virtua.com.br", "prod-infinitum.com.mx", "bahnhof.se",
    "ovh.net", "ovh.ca", "contaboserver.net", "hwclouds-dns.com",
    "comcast.net", "comcastbusiness.net", "sparklight.net", "shawcable.net",
    "rima-tde.net", "rr.com", "sbcglobal.net", "optonline.net", "verizon.net",
    "cox.net", "charter.com", "spectrum.com", "myvzw.com", "telus.net",
    "btcentralplus.com", "virginmedia.com", "proxad.net", "wanadoo.fr",
    "bbox.fr", "numericable.fr", "kabel-deutschland.de", "t-ipconnect.de",
    "hinet.net", "kbtelecom.net", "so-net.net",
    "ocn.ne.jp", "nuro.jp", "otenet.gr", "viettel.vn", "comnet.bg",
    "forpsi.net", "colocall.com", "hosted-by-vdsina.com", "ovh.us",
    "fastvps-server.com", "contaboserver.net",
    "free.fr", "orange.fr", "bbtec.net", "toob.co.uk", "multi.fi",
    "onvol.net", "t-online.hu", "lcv.ne.jp", "bai.ne.jp", "vectant.ne.jp",
    "inet.co.th", "salnet.net", "odn.ad.jp", "wanadoo.fr", "proxad.net",
    "zap.cloud", "scw.cloud", "dogado.eu", "dogado.net",
}

# Substrings matched against a normalised " org name " (spaces, lowercased).
_INFRA_ORG = (
    "amazon", "google", "microsoft", "azure", "cloudflare", "akamai",
    "fastly", "digitalocean", "linode", "hetzner", "ovh", "choopa",
    "vultr", "oracle", "alibaba", "tencent", "incapsula", "imperva",
    "leaseweb", "hurricane electric", "wpengine", "wp engine", "godaddy",
    "rackspace", "softlayer", "contabo", "scaleway", "hostinger", "ionos",
    "cdn77", "stackpath", "sucuri", "datacamp", "m247", "psychz",
    "quadranet", "colocrossing", "constant company", "frantech",
    "chinanet", "china unicom", "china mobile", "china telecom",
    "comcast", "verizon", "charter comm", "centurylink", "lumen",
    "cogent", "zayo", "telia", "vodafone", "singtel", "starhub",
    "kddi", "softbank", "telstra", "bahnhof", "broadband", "telecom",
    "telekom", "telefonica", "hosting", "data center", "datacenter",
    "colocation", "cloud computing", "aceville", "unified layer",
    "singlehop", "servermania", "gandi", "namecheap", "bluehost",
    "dreamhost", "hostgator", "online s a s", "level 3", "ntt ",
    "deutsche telekom", "swisscom", "kpn ", "rostelecom", "virgin media",
    "cloudflare london", "amazon data services", "google llc",
    "google cloud", "microsoft corporation", "digital ocean",
    "linode llc", "akamai international", "edgecast", "highwinds",
    "limelight", "cachefly", "stackpath", "softlayer", "ipxo",
    "zenlayer", "m247", "datacamp limited", "packethub", "estnoc",
    "online.net", "scaleway", "gcore", "g-core", "cdnetworks",
    "quantil", "wangsu", "baidu", "huawei cloud", "ucloud",
    "kingsoft", "qingcloud", "viettel", "dotcom", "fastplanet",
    "serverstep", "claro", "uninet", "contabo", "ovh",
    "communications", "cable one", "shaw communications", "huawei",
    "maxnet", "so-net", "kbtelecom", "hinet",
    "dynamic pool", "iaas", "private network", "end user", "telecommunications",
    "hostpapa", "ibm cloud", "dsl", "netcup", "hetzner", "strato",
    "digitalocean", "contabo", "ovh", "scaleway", "linode", "vultr",
    "hosting",
)

# Device vendors and dynamic-DNS suffixes. A banner on a residential ISP
# that "names" www.draytek.com is the router's default identity, not the vendor.
VENDOR_DDNS = {
    "draytek.com", "synology.me", "myds.me", "quickconnect.to", "duckdns.org",
    "dyndns.org", "no-ip.com", "no-ip.org", "hopto.org", "ddns.net", "zapto.org",
    "sytes.net", "myfritz.net", "tplinkdns.com", "homeip.net", "ddnsfree.com",
    "arubanetworks.com", "cisco.com", "fortinet.com", "paloaltonetworks.com",
}
_ZONE_SLD = re.compile(
    r"(server|hosting|webhost|datacent|datacentre|vps|sunucu|dedicated|domainzone|broadband)"
)
_ZONE_SLD_EXACT = {
    "personal", "static", "dynamic", "customer", "customers", "pool",
    "clients", "client", "dsl", "dyn", "cust",
}
_FAKE_TLDS = {"adsl", "localhost", "local", "internal", "lan", "home", "localdomain"}

_HOST_RE = re.compile(r"^[a-z0-9.-]+$")
# Reverse-DNS tells. Matched on the hostname, not on a stripped registrable domain,
# because Shodan's `domains` field throws away the reverse-DNS labels.
_PTR_HINT = re.compile(
    r"(?:^|[.-])(?:reverse|static|dynamic|dyn|dhcp|in-addr|ip6|ip4|ptr|dsl|pool|"
    r"broadband|dynamicip|hfc|cpe|customer|virtua|hosted-by|ppp|vlan)(?:[.-]|$)",
    re.I,
)
_IP_RUN = re.compile(r"\d{1,3}[-.]\d{1,3}[-.]\d{1,3}")


def clean_host(value: str | None) -> str:
    host = (value or "").strip().lower().rstrip(".")
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host


def registrable(host: str | None) -> str | None:
    host = clean_host(host)
    if not host or not _HOST_RE.match(host):
        return None
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        return None
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return None
    if any(len(p) > 63 for p in parts):
        return None
    suffix2 = ".".join(parts[-2:])
    if suffix2 in _MULTI and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix2


def looks_like_ptr(host: str | None, ip: str | None) -> bool:
    host_c = clean_host(host)
    if not host_c:
        return False
    lowered = host_c.lower()
    if lowered.endswith(".arpa") or "in-addr" in lowered or ".ip6." in lowered:
        return True
    if _PTR_HINT.search(lowered) or _IP_RUN.search(lowered):
        return True
    labels = [label for label in lowered.split(".") if label]
    if sum(1 for label in labels if label.isdigit()) >= 2:
        return True
    if not ip or ":" in ip:
        return False
    tokens = set(re.split(r"[^0-9a-z]+", lowered))
    octets = [o for o in ip.split(".") if o]
    return sum(1 for octet in octets if octet in tokens) >= 3


def domain_is_zone_name(domain: str) -> bool:
    """Names that are a provider's customer zone, not a company brand."""
    sld = domain.split(".")[0].lower()
    flat = sld.replace("-", "")
    if sld in _ZONE_SLD_EXACT or flat in _ZONE_SLD_EXACT:
        return True
    if domain.rsplit(".", 1)[-1] == "host":
        return True
    if flat.endswith(("cloud", "server", "hosting", "srv", "cust")):
        return True
    if _ZONE_SLD.search(flat):
        return True
    return False


def _provider_zone(domain: str, org: str | None) -> bool:
    """Hoster's own naming zone, not a customer who happens to sit on that network.

    fishing-guide.si on DigitalOcean stays. zap.cloud on ZAP-Hosting does not.
    """
    if not org or not is_infra_org(org):
        return False
    sld = re.sub(r"[^a-z0-9]", "", domain.split(".")[0].lower())
    org_flat = re.sub(r"[^a-z0-9]", "", org.lower())
    if len(sld) >= 4 and sld in org_flat:
        return True
    org_tokens = re.findall(r"[a-z0-9]{4,}", org.lower())
    if len(sld) >= 3 and any(token.startswith(sld) and len(token) >= len(sld) + 3 for token in org_tokens):
        return True
    if any(len(token) >= 5 and token in sld for token in org_tokens):
        return True
    return False


def is_infra_domain(domain: str | None) -> bool:
    if not domain:
        return True
    domain = domain.lower()
    if domain in INFRA_DOMAINS:
        return True
    return any(domain.endswith("." + infra) or domain == infra for infra in INFRA_DOMAINS)


def is_infra_org(org: str | None) -> bool:
    if not org or not str(org).strip():
        return True
    padded = " " + re.sub(r"[^a-z0-9]+", " ", org.lower()).strip() + " "
    for needle in _INFRA_ORG:
        token = " ".join(needle.split())
        if not token:
            continue
        if f" {token} " in padded:
            return True
    return False


def best_domain(rec: dict) -> str | None:
    """Prefer the scanned virtual host, then other hostnames.

    The `domains` array is ignored on purpose. Shodan reduces
    `h-85-24-242-85.priv.bahnhof.se` to `bahnhof.se`, which is the ISP,
    not the company at that address.
    """
    ip = rec.get("ip_str") or ""
    hosts: list[str] = []
    http_host = ((rec.get("http") or {}).get("host")) if isinstance(rec.get("http"), dict) else None
    if http_host:
        hosts.append(str(http_host))
    for item in rec.get("hostnames") or []:
        if item:
            hosts.append(str(item))
    seen = set()
    for raw in hosts:
        if looks_like_ptr(raw, ip):
            continue
        domain = registrable(raw)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        if is_infra_domain(domain) or domain in _MULTI:
            continue
        tld = domain.rsplit(".", 1)[-1]
        if tld in _FAKE_TLDS:
            continue
        if domain_is_zone_name(domain):
            continue
        org = rec.get("org")
        if domain in VENDOR_DDNS and is_infra_org(org):
            continue
        if _provider_zone(domain, org if isinstance(org, str) else None):
            continue
        return domain
    return None


def org_name(rec: dict) -> str | None:
    org = rec.get("org")
    if not org:
        return None
    text = re.sub(r"\s+", " ", str(org)).strip()
    return text or None
