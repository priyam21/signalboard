# Signalboard

A desk for a cybersecurity sales team. It reads a Shodan banner dump, throws away the scanner noise, and ranks the businesses that are actually exposed.

The interesting part is not the UI. It is which signals are real.

## What the file actually is

`b2_download_file_by_id` is one zstd-compressed JSONL file of Shodan banners from 26 Oct 2026 (about 17.6 GB compressed). Each line is one service on one IP: banner text, product, verified and unverified CVEs, TLS certificate, HTTP headers, and a module name for the probe Shodan tried.

Handing that file to a model and asking for "companies that need security" produces a bad list. The traps, confirmed on the first 200,000 banners:

| What it looks like | What it is | What we do |
|---|---|---|
| `remcos-pro-rat`, `darktrack-rat`, `orcus-rat` modules | The probe ran. A large share came back as `HTTP 400` from nginx or an empty banner | Ignore the module name. A malware finding requires the product or info field to name the family |
| 200k+ CVE rows | Almost all are `verified: false`. OpenSSH version-matching with CVSS 2.5 | Score only scanner-verified CVEs, and only when CVSS ≥ 7 or EPSS ≥ 0.05 |
| `automated-tank-gauge` / `dicom` on a CDN IP | Probe hit a Cloudflare or Incapsula 400 | Require a product name, or a non-HTTP, non-TLS payload |
| Hostname `h-85-24-242-85.priv.bahnhof.se`, and Shodan's `domains: ["bahnhof.se"]` | Reverse DNS of an ISP, then Shodan strips it to the ISP's domain | Never read `domains`. Skip reverse-DNS hostnames |
| `org: "Cloudflare, Inc."` / `"Amazon Data Services"` | The network operator, not the buyer | Do not open an account on a cloud, CDN, or carrier org |
| Honeypot tag | A research box, not a prospect | Drop the banner |
| Redis with `authentication_required: true` | Exposed port, but not an open database | No finding. Open Elasticsearch (indices readable) is a finding |
| Heartbleed line ending in `SAFE` or `ERROR` | The probe did not succeed | Only a line that says `VULNERABLE` |
| SNMPv3 | Encrypted SNMP | Ignore. SNMPv1/v2c still counts |

EPSS is the timing signal. CVSS says how bad a bug is. EPSS says how likely it is to be exploited this month. A verified CVE at CVSS 10 and EPSS 0.99 (SMBGhost, `CVE-2020-0796`, showed up immediately) outranks a pile of end-of-life nginx.

## How an account is chosen

1. Virtual host (`http.host`), then other hostnames.
2. Drop reverse DNS: IP-shaped labels, `static` / `dynamic` / `dsl` / `ptr`, two numeric labels, or a known ISP zone (`virtua.com.br`, `comcastbusiness.net`, `ocn.ne.jp`, …).
3. Drop infrastructure registrable domains (cloud PTRs, CDNs, hoster zones).
4. If the only name is a vendor or dynamic-DNS suffix (`www.draytek.com` on a "Dynamic pool for DSL" org), that is the router's default identity, not the vendor as a buyer.
5. If nothing callable remains, keep the network-owner org when it is not a carrier or hoster.
6. Otherwise keep the bare IP, and only for a serious finding (22 points or more). The IP list is capped at the 4,000 worst, so it cannot crowd out named accounts.

The desk opens on **named domains**. Network owners and bare IPs are a filter away, and the call note says when the name is only the network operator.

## How the score works

Each finding has points. Priority is **not** a count of banners.

```
priority = min(100, urgency + breadth)
urgency  = points of the single worst finding
breadth  = 8 points per extra kind of problem, capped at 24
```

One verified critical beats five end-of-life banners. Volume is a column (distinct IPs), not the rank. Class caps stop twenty MySQL ports from outscoring one open Elasticsearch cluster.

Queue, as a label on top of that number:

- **Now** — ransomware entry (SMB, RDP, VNC, Telnet), open data store, exposed control plane (Kubernetes, Docker API, Jenkins, Winbox), confirmed OT/clinical, heartbleed, named malware, or a verified CVE with EPSS ≥ 0.4 or CVSS ≥ 9
- **This month** — cameras, end-of-life software, expired or self-signed certs on a real domain, internet-reachable MySQL/Postgres/MSSQL, legacy SNMP
- **Nurture** — anything weaker that still cleared the bar

Certificate findings are stored only when a real domain was present. A self-signed cert on a bare cloud IP is not a prospect.

The call note is a template filled from the top finding. It cannot invent a CVE, a product, or a hostname, because no language model writes it. That also makes the note free to regenerate.

## Ingestion at monthly volume

Production receives hundreds or thousands of files like this one per month. The job is a streaming reduce, not a warehouse load of raw banners:

- zstd, gzip, or plain JSONL, one file or a directory, repeatable `--input`
- one pass, banners discarded after the finding is pulled
- aggregation key is the account, so a second month merges into the same company instead of duplicating the internet
- output is a SQLite mart small enough to serve. Raw banners are not stored
- rebuild is idempotent: rerunning replaces the mart. Replay the month's files together

On this file the reduce ran at about 26,000 banners/s. Throughput, honeypots dropped, unverified CVEs ignored, and probe banners that did not confirm are stored in the mart and shown on the desk.

## Run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src

python -m unittest discover -s tests -v

python -m salesintel.ingest \
  --input /path/to/b2_download_file_by_id \
  --out data/signalboard.sqlite

python -m salesintel.app --db data/signalboard.sqlite --port 8765

python -m salesintel.report \
  --db data/signalboard.sqlite \
  --out report/signalboard.html
```

`--limit 200000` is a fast sample of the front of the file. The desk is http://127.0.0.1:8765. The HTML file is the same desk with every account, filter, and finding, and it opens without the server. It is generated, not committed: the file is about 67 MB.

## Measured on this file

One pass, 14,608,407 banners, 565 seconds, 25,875 banners/s. Peak memory stayed in the account table, not the raw file. The mart is about 97 MB.

| Check | Count | Read |
|---|---:|---|
| Banners with no confirmed signal | 13,811,693 | 95% of the file is not a sales lead |
| Unverified CVE rows ignored | 19,846,654 | Version-matching would have dominated the ranking |
| Verified CVEs that cleared the bar | 6,065 | The rows that actually move an account |
| Honeypots dropped | 250,439 | |
| Special probes (RAT, tank gauge, DICOM, Dahua) | 177,178 | |
| Of those, confirmed by a real payload | 3,806 | 2% — the module name is not the finding |
| Named-domain accounts in the "now" queue | 2,304 | Callable this week |
| Named-domain accounts in "this month" | ~64,000 | Cameras, end-of-life, certs, reachable databases |

Country on the card is where the exposed host is, not the company's headquarters. `fishing-guide.si` sits on a DigitalOcean IP in the Netherlands.

Examples a rep can open from the top of the named-domain queue:

- **uam.mx** — Universidad Autónoma Metropolitana. Heartbleed still answers on `148.206.79.56:443` (EPSS 0.90), plus an expired certificate and end-of-life Apache.
- **ntu.edu.tw** — National Taiwan University. Scanner-verified SMBGhost (`CVE-2020-0796`, CVSS 10, EPSS 0.998) on `140.112.31.22:445`, with RDP and VNC on other campus IPs.
- **sp.gov.br** — São Paulo municipal IT. `CVE-2015-1635` / MS15-034 on IIS, CVSS 9.8, EPSS ~1, plus an open directory.
- **huayundata.com** — Jenkins `CVE-2024-23897` (CVSS 9.8, EPSS ~1) on `121.40.113.18:443`, hosted at Aliyun, and the Jenkins version is end-of-life. The call note names that host, not "a cloud security conversation."

A few provider zones still outrank these when the hostname has no reverse-DNS tell (`skystark.net`, `stimo.net`). The filter is a list plus patterns, not a magic company resolver. Named domain is the default view so a carrier ASN does not occupy the first screen.

## How we know it works

Unit tests in `tests/test_signals.py` lock the traps above: CDN challenge pages, RAT probes that returned HTTP 400, unverified low CVEs, honeypot RDP, authenticated Redis, Heartbleed SAFE/ERROR, the Bahnhof reverse-DNS case (including Shodan's stripped `domains` field), Cooler Master winning over a `.net.tw` PTR, and a DrayTek default name on a DSL pool. A separate test checks that one critical outranks several end-of-life findings.

After a full ingest, the stats bar on the desk is the empirical check: unverified CVEs ignored should dwarf verified CVEs used, and probe banners confirmed should be a small fraction of probe banners seen. The top of the named-domain list should be callable companies with a specific host, port, and evidence, not Cloudflare, Comcast reverse DNS, or `net.tw`.

## Decisions we would defend

- **Verified beats version-matched.** Shodan already did the noisy match. Using it as a score double-counts guesses.
- **EPSS changes the order, CVSS does not by itself.** Sales timing is "someone can exploit this now."
- **Priority is the worst hole, not the noisiest IP.** A salesperson cannot work a thousand missing headers.
- **No model in the scoring path.** The cost is zero, and a wrong CVE in an outreach email is worse than a plain sentence.
- **OS fingerprint (Windows 7 vs 8) is not a finding.** The `eol-product` tag plus an explicit ancient banner (Apache 2.2, IIS 6/7, PHP 5, OpenSSL 1.0, nginx &lt; 1.18) is.
- **Missing security headers are not a finding.** On this snapshot almost every real site fails some header check, so it does not separate anyone.
