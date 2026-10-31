import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path

from salesintel.attribution import is_infra_org, looks_like_ptr, registrable
from salesintel.ingest import ingest_paths
from salesintel.score import score_findings
from salesintel.signals import interpret_banner


def _banner(**overrides):
    rec = {
        "ip_str": "203.0.113.10",
        "port": 443,
        "org": "Example Pty Ltd",
        "asn": "AS64500",
        "hostnames": [],
        "domains": [],
        "tags": [],
        "product": None,
        "version": None,
        "data": "",
        "opts": {},
        "location": {"country_code": "AU", "city": "Sydney"},
        "_shodan": {"module": "https"},
    }
    rec.update(overrides)
    return rec


class AttributionTests(unittest.TestCase):
    def test_registrable_multipart_suffix(self):
        self.assertEqual(registrable("www.acme.co.uk"), "acme.co.uk")
        self.assertEqual(registrable("WWW.Acme.com."), "acme.com")

    def test_ptr_is_not_a_company(self):
        self.assertTrue(looks_like_ptr("h-85-24-242-85.A980.priv.bahnhof.se", "85.24.242.85"))
        self.assertTrue(looks_like_ptr("0.00.5195.ip4.static.sl-reverse.com", "149.81.0.0"))
        self.assertTrue(looks_like_ptr("75-147-217-29-Miami.hfc.comcastbusiness.net", "75.147.217.29"))
        self.assertFalse(looks_like_ptr("jamasoftware.com", "141.193.213.20"))
        self.assertFalse(looks_like_ptr("mail.focuslab.co.th", "203.150.224.14"))

    def test_domains_field_cannot_promote_an_isp(self):
        view = interpret_banner(_banner(
            ip_str="85.24.242.85",
            port=445,
            org="Bahnhof AB",
            hostnames=["h-85-24-242-85.A980.priv.bahnhof.se"],
            domains=["bahnhof.se"],
            smb={"smb_version": 2},
        ))
        self.assertIsNone(view.domain)

    def test_real_name_wins_over_provider_ptr(self):
        view = interpret_banner(_banner(
            ip_str="123.252.113.57",
            hostnames=["host-123-252-113-57.static.kbtelecom.net.tw", "tygs-caic.coolermaster.com.tw"],
            domains=["net.tw", "com.tw"],
            http={"host": "123.252.113.57"},
        ))
        self.assertEqual(view.domain, "coolermaster.com.tw")

    def test_vendor_default_name_on_a_dsl_pool_is_not_the_vendor(self):
        view = interpret_banner(_banner(
            org="Dynamic pool for DSL",
            hostnames=["www.draytek.com"],
            product="DrayTek Vigor Router",
        ))
        self.assertIsNone(view.domain)

    def test_numeric_reverse_labels_are_not_a_company(self):
        self.assertTrue(looks_like_ptr("28.239.forpsi.net", "80.211.203.101"))
        self.assertTrue(looks_like_ptr("103-24-107-50.quantum.net.id", "103.24.107.50"))

    def test_provider_customer_zones_are_not_brands(self):
        from salesintel.attribution import domain_is_zone_name
        self.assertTrue(domain_is_zone_name("dogado-cloud.de"))
        self.assertTrue(domain_is_zone_name("personal.net.py"))
        self.assertTrue(domain_is_zone_name("vsys.host"))
        self.assertTrue(domain_is_zone_name("skybroadband.com"))
        self.assertFalse(domain_is_zone_name("fishing-guide.si"))
        self.assertFalse(domain_is_zone_name("ntu.edu.tw"))
        self.assertFalse(domain_is_zone_name("uam.mx"))

    def test_hoster_brand_zone_is_not_the_customer(self):
        view = interpret_banner(_banner(
            org="ZAP-Hosting GmbH",
            hostnames=["node1.zap.cloud"],
            port=445,
            smb={"smb_version": 2},
        ))
        self.assertIsNone(view.domain)

    def test_customer_on_a_cloud_ip_keeps_its_own_domain(self):
        view = interpret_banner(_banner(
            org="DigitalOcean, LLC",
            hostnames=["www.fishing-guide.si"],
            http={"host": "www.fishing-guide.si"},
        ))
        self.assertEqual(view.domain, "fishing-guide.si")

    def test_government_suffix_does_not_collapse_the_country(self):
        self.assertEqual(registrable("portal.saude.gov.br"), "saude.gov.br")

    def test_cloud_and_isp_orgs_are_not_buyers(self):
        self.assertTrue(is_infra_org("Amazon Data Services Jakarta"))
        self.assertTrue(is_infra_org("WPEngine, Inc."))
        self.assertTrue(is_infra_org("Bahnhof AB"))
        self.assertTrue(is_infra_org("SREE BROADBAND"))
        self.assertFalse(is_infra_org("Harbour Clinic"))


class SignalTests(unittest.TestCase):
    def test_cdn_challenge_is_not_a_finding(self):
        view = interpret_banner(_banner(
            org="WPEngine, Inc.",
            hostnames=["jamasoftware.com"],
            domains=["jamasoftware.com"],
            product="CloudFlare",
            http={"host": "jamasoftware.com", "title": "Just a moment...", "status": 403, "waf": "Cloudflare"},
            data="HTTP/1.1 403 Forbidden",
        ))
        self.assertEqual(view.domain, "jamasoftware.com")
        self.assertEqual(view.findings, [])

    def test_rat_probe_that_got_http_400_is_not_malware(self):
        view = interpret_banner(_banner(
            port=1800,
            org="Chinanet Jiangsu Province Network",
            product="nginx",
            data="HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n",
            _shodan={"module": "remcos-pro-rat"},
        ))
        self.assertEqual(view.probe_module, "remcos-pro-rat")
        self.assertEqual(view.findings, [])

    def test_unverified_low_cves_do_not_score(self):
        view = interpret_banner(_banner(
            port=22,
            product="OpenSSH",
            vulns={"CVE-2026-106583": {"cvss": 2.5, "verified": False, "epss": 0.001, "summary": "username injection"}},
        ))
        self.assertEqual(view.findings, [])
        self.assertEqual(view.unverified_cves, 1)

    def test_verified_critical_with_high_epss_outranks_noise(self):
        view = interpret_banner(_banner(
            ip_str="85.24.242.85",
            port=445,
            org="Bahnhof AB",
            hostnames=["h-85-24-242-85.A980.priv.bahnhof.se"],
            smb={"smb_version": 2},
            vulns={
                "CVE-2020-0796": {
                    "cvss": 10.0,
                    "verified": True,
                    "epss": 0.9981,
                    "summary": "SMBv3 remote code execution",
                }
            },
        ))
        self.assertIsNone(view.domain)
        self.assertTrue(view.org_is_infra)
        cve = next(f for f in view.findings if f["cve"] == "CVE-2020-0796")
        self.assertGreaterEqual(cve["points"], 40)
        self.assertTrue(cve["verified"])
        smb = next(f for f in view.findings if f["klass"] == "ransomware_entry")
        self.assertGreaterEqual(smb["points"], 26)

    def test_honeypot_rdp_is_dropped(self):
        view = interpret_banner(_banner(
            port=3389,
            product="Remote Desktop Protocol",
            tags=["honeypot"],
        ))
        self.assertEqual(view.skip, "honeypot")
        self.assertEqual(view.findings, [])

    def test_open_elastic_names_the_index(self):
        view = interpret_banner(_banner(
            port=9200,
            product="Elastic",
            hostnames=["search.harbourclinic.com"],
            http={"host": "search.harbourclinic.com"},
            elastic={"indices": {"tgbots-commands-2026-10": {}}, "tagline": "You Know, for Search"},
        ))
        self.assertEqual(view.domain, "harbourclinic.com")
        finding = view.findings[0]
        self.assertEqual(finding["klass"], "data_store")
        self.assertIn("tgbots-commands-2026-10", finding["detail"])
        self.assertGreaterEqual(finding["points"], 30)

    def test_redis_with_auth_is_not_an_open_datastore(self):
        view = interpret_banner(_banner(port=6379, product="Redis key-value store", redis={"authentication_required": True}))
        self.assertEqual(view.findings, [])

    def test_eol_nginx_is_a_modest_finding(self):
        view = interpret_banner(_banner(
            port=80,
            product="nginx",
            version="1.20.1",
            tags=["eol-product"],
            hostnames=["legacy.harbourclinic.com"],
            cpe=["cpe:/a:f5:nginx:1.20.1"],
        ))
        self.assertEqual(view.findings[0]["klass"], "eol")
        self.assertLess(view.findings[0]["points"], 20)

    def test_one_critical_beats_many_eol(self):
        critical = score_findings([{
            "klass": "verified_cve", "points": 42, "epss": 0.99, "cvss": 10, "verified": True,
        }])
        eol = score_findings([
            {"klass": "eol", "points": 12, "epss": 0, "cvss": 0},
            {"klass": "eol", "points": 12, "epss": 0, "cvss": 0},
            {"klass": "eol", "points": 12, "epss": 0, "cvss": 0},
        ])
        self.assertGreater(critical["priority"], eol["priority"])
        self.assertEqual(critical["queue"], "now")
        self.assertEqual(eol["queue"], "month")

    def test_heartbleed_safe_and_error_are_ignored(self):
        safe = interpret_banner(_banner(opts={"heartbleed": "2026/10/26 1.2.3.4:443 - SAFE\n"}))
        error = interpret_banner(_banner(opts={"heartbleed": "ERROR: broken pipe"}))
        vuln = interpret_banner(_banner(
            hostnames=["edge.harbourclinic.com"],
            opts={"heartbleed": "2026/10/26 203.0.113.10:443 - VULNERABLE\n"},
        ))
        self.assertEqual(safe.findings, [])
        self.assertEqual(error.findings, [])
        self.assertEqual(vuln.findings[0]["klass"], "heartbleed")
        self.assertEqual(vuln.findings[0]["cve"], "CVE-2014-0160")


class IngestTests(unittest.TestCase):
    def test_stream_roundtrip_attributes_domain_not_isp(self):
        banners = [
            _banner(
                ip_str="85.24.242.85",
                port=445,
                org="Bahnhof AB",
                hostnames=["h-85-24-242-85.A980.priv.bahnhof.se"],
                smb={"smb_version": 2},
                vulns={"CVE-2020-0796": {"cvss": 10, "verified": True, "epss": 0.99, "summary": "RCE"}},
            ),
            _banner(
                ip_str="203.0.113.50",
                port=9200,
                org="Harbour Clinic",
                hostnames=["search.harbourclinic.com"],
                http={"host": "search.harbourclinic.com"},
                elastic={"indices": {"patients-2026": {}}},
            ),
            _banner(
                port=1800,
                org="Chinanet Jiangsu Province Network",
                product="nginx",
                data="HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n",
                _shodan={"module": "remcos-pro-rat"},
            ),
        ]
        raw = "\n".join(json.dumps(b) for b in banners).encode() + b"\n"
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(raw)
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "drop.jsonl.gz"
            out = Path(tmp) / "mart.sqlite"
            src.write_bytes(buf.getvalue())
            meta = ingest_paths([src], out)
            self.assertEqual(meta["records"], 3)
            import sqlite3
            conn = sqlite3.connect(out)
            keys = [row[0] for row in conn.execute("SELECT account_key FROM accounts ORDER BY priority DESC")]
            conn.close()
        self.assertIn("domain:harbourclinic.com", keys)
        self.assertTrue(any(key.startswith("ip:") for key in keys))
        self.assertFalse(any("bahnhof" in key for key in keys))
        self.assertFalse(any("chinanet" in key for key in keys))


if __name__ == "__main__":
    unittest.main()
