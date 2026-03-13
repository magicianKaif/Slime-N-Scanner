# 🟢 SLIME N SCANNER

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/NVD-CVE%20Lookup-red?style=for-the-badge"/>
</p>

<p align="center">
  <b>Network Reconnaissance & Vulnerability Scanner</b><br/>
  Recon • Port Scan • Service Detection • CVE Lookup • HTML/JSON Reports
</p>

---

## What It Does

**SLIME N SCANNER** is a single-file Python CLI tool that performs a full security audit on any domain or IP address:

| Phase | What It Does |
|-------|-------------|
| **1 — Recon** | DNS resolution, Reverse DNS, ASN info, IP range/CIDR, WHOIS (registrar, dates), DNS record types |
| **2 — Port Scan** | Threaded TCP scan, top-1000 common ports or full 65535, real-time progress bar |
| **3 — Service Detection** | Banner grabbing, version fingerprinting, TLS cert info (cipher, expiry, SANs), OS TTL hint |
| **4 — CVE Lookup** | CPE-based NVD search (precise), keyword fallback, CVSS scores, rate-limit safe |
| **5 — Report** | Rich colored CLI tables + optional JSON or HTML export |

---

## Screenshot

```
  ███████╗██╗     ██╗███╗   ███╗███████╗    ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██║     ██║████╗ ████║██╔════╝    ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ...

  Port 22     -> SSH                    OpenSSH 8.2p1    [TLS: —]
  Port 80     -> HTTP                   nginx/1.18.0     [—]
  Port 443    -> HTTPS                  nginx/1.18.0     [TLS: TLSv1.3]

  ╭──────┬──────────────────────┬──────────────────┬────────────┬──────────────────────────────────────╮
  │ PORT │ SERVICE              │ VERSION          │ TLS        │ CVEs                                 │
  ├──────┼──────────────────────┼──────────────────┼────────────┼──────────────────────────────────────┤
  │  22  │ SSH                  │ OpenSSH 8.2p1    │ —          │ CVE-2023-38408 CVSS 9.8              │
  │  80  │ HTTP                 │ nginx/1.18.0     │ —          │ CVE-2021-23017 CVSS 7.7 (+1 more)    │
  │ 443  │ HTTPS                │ nginx/1.18.0     │ TLSv1.3    │ CVE-2021-23017 CVSS 7.7              │
  ╰──────┴──────────────────────┴──────────────────┴────────────┴──────────────────────────────────────╯
```

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/magicianKaif/Slime-N-Scanner.git
cd Slime-N-Scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run it

```bash
python slime_n_scanner.py example.com
```

> **Python 3.8 or higher** is required.

---

## Usage

```bash
python slime_n_scanner.py <target> [options]
```

### Basic Examples

```bash
# Scan a domain
python slime_n_scanner.py example.com

# Scan an IP address
python slime_n_scanner.py 192.168.1.1

# Scan with full port range
python slime_n_scanner.py example.com --ports full

# Save results as HTML report
python slime_n_scanner.py example.com --output report.html

# Save results as JSON
python slime_n_scanner.py example.com --output report.json
```

---

## All Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Domain name or IP address to scan | **required** |
| `--ports top1000` | Scan top 1000 most common ports | ✅ default |
| `--ports full` | Scan all 65,535 ports (slower but thorough) | — |
| `--timeout N` | Socket timeout per connection in seconds | `3` |
| `--threads N` | Number of concurrent scan threads | `100` |
| `--output FILE.json` | Export full report as JSON | — |
| `--output FILE.html` | Export full report as dark-theme HTML | — |
| `--severity all` | Show all CVE severities | ✅ default |
| `--severity critical` | Show only CRITICAL CVEs | — |
| `--severity high` | Show HIGH + CRITICAL CVEs | — |
| `--severity medium` | Show MEDIUM and above CVEs | — |
| `--no-cve` | Skip CVE lookup (faster scan) | — |
| `--api-key KEY` | NVD API key for 50 req/30s instead of 5 req/30s | — |

---

## Detailed Option Guide

### `--ports`

Controls which TCP ports are scanned.

```bash
# Default — scans ~100 hand-picked high-value ports
python slime_n_scanner.py target.com --ports top1000

# Full sweep — all 65,535 ports. Slower but finds non-standard services
python slime_n_scanner.py target.com --ports full
```

---

### `--timeout`

How long to wait for a port/service to respond.

```bash
python slime_n_scanner.py target.com --timeout 1    # Fast, may miss slow services
python slime_n_scanner.py target.com --timeout 5    # Better for slow/distant targets
```

> Low timeout = faster scan. High timeout = better service/version detection.
> Default is `3` seconds which balances speed and accuracy.

---

### `--threads`

How many ports are scanned in parallel.

```bash
python slime_n_scanner.py target.com --threads 50     # Gentle — less network load
python slime_n_scanner.py target.com --threads 200    # Aggressive — faster scan
```

> Default is `100`. Uses `ThreadPoolExecutor` so only exactly N threads are alive
> at any time — safe even with `--ports full`.

---

### `--output`

Save a full report to a file.

```bash
# JSON — structured data, good for scripting/parsing
python slime_n_scanner.py target.com --output results.json

# HTML — beautiful dark-theme report, opens in any browser
python slime_n_scanner.py target.com --output results.html
```

---

### `--severity`

Filter which vulnerabilities are displayed and exported.

```bash
python slime_n_scanner.py target.com --severity all       # Show everything (default)
python slime_n_scanner.py target.com --severity critical  # Only CRITICAL (CVSS 9.0+)
python slime_n_scanner.py target.com --severity high      # HIGH + CRITICAL
python slime_n_scanner.py target.com --severity medium    # MEDIUM and above
```

---

### `--no-cve`

Skip the CVE lookup phase entirely. Useful when you just want fast port/service info.

```bash
python slime_n_scanner.py target.com --no-cve
```

---

### `--api-key`

The tool queries the [NIST NVD API](https://nvd.nist.gov/developers) for CVE data.

- **Without a key**: 5 requests per 30 seconds (rate limited, tool auto-waits)
- **With a free key**: 50 requests per 30 seconds (10x faster CVE lookups)

Get your free key at: https://nvd.nist.gov/developers/request-an-api-key

```bash
python slime_n_scanner.py target.com --api-key YOUR_NVD_KEY_HERE
```

---

## Combining Options

```bash
# Full aggressive scan, only critical CVEs, save HTML
python slime_n_scanner.py target.com --ports full --threads 200 --severity critical --output report.html

# Quick recon only, no CVE lookup, fast timeout
python slime_n_scanner.py target.com --timeout 1 --threads 150 --no-cve

# Deep scan on a slow/distant server, save JSON
python slime_n_scanner.py 10.0.0.5 --ports full --timeout 5 --threads 50 --output results.json

# Full scan with NVD API key for fast CVE lookup
python slime_n_scanner.py target.com --ports full --api-key YOUR_KEY --output report.html
```

---

## How CVE Detection Works

1. **Version is detected** from the service banner (e.g. `nginx/1.18.0`)
2. **CPE string is built**: `cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*`
3. **NVD API is queried** with the CPE — returns only CVEs matching that exact product/version
4. **Fallback keyword search** is used if CPE returns no results
5. **Anti-false-positive filter**: CVE description must mention the product name
6. Results are **sorted by CVSS score** (highest severity first)
7. Results are **cached in SQLite** for 24 hours so repeated scans are instant

> If no version is detected for a service, CVE lookup is skipped for that service
> to avoid false positives.

---

## Supported Services

The scanner can detect and fingerprint versions for:

`OpenSSH` • `nginx` • `Apache httpd` • `Apache Tomcat` • `Microsoft IIS` •
`lighttpd` • `LiteSpeed` • `PHP` • `MySQL` • `MariaDB` • `PostgreSQL` •
`Redis` • `MongoDB` • `Elasticsearch` • `Memcached` • `vsftpd` • `ProFTPD` •
`FileZilla Server` • `Pure-FTPd` • `Exim` • `Postfix` • `Dovecot` •
`OpenSSL` • `Oracle WebLogic`

---

## Output Files

### JSON Report

Contains the full structured scan data:

```json
{
  "scan_time": "2025-01-01T12:00:00",
  "scanner": "SLIME N SCANNER",
  "author": "magician slime",
  "github": "https://github.com/magicianKaif",
  "recon": { "target": "...", "ip": "...", "asn": "...", ... },
  "services": { "80": { "service": "HTTP", "version": "nginx/1.18", ... } },
  "vulnerabilities": { "80": [ { "id": "CVE-...", "cvss_score": 7.7, ... } ] }
}
```

### HTML Report

A dark-themed browser report with:
- Recon summary table
- Open ports & services table
- Confirmed vulnerabilities table with CVE links

---

## Requirements

```
Python     >= 3.8
rich       >= 13.0.0    # Terminal UI / tables
requests   >= 2.28.0    # NVD API HTTP requests
dnspython  >= 2.3.0     # DNS record enumeration
ipwhois    >= 1.2.0     # ASN / IP range lookup
python-whois >= 0.8.0   # Domain WHOIS data
```

Install all at once:

```bash
pip install -r requirements.txt
```

---

## Disclaimer

> **This tool is for authorized security testing and educational purposes only.**
> Scanning systems without explicit permission is illegal in most jurisdictions.
> The author is not responsible for any misuse or damage caused by this tool.
> Always get written permission before scanning any system you do not own.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## Author

**magician slime**
- GitHub: [@magicianKaif](https://github.com/magicianKaif)

---

## Credits

This tool was **planned, designed, and crafted by [magician slime](https://github.com/magicianKaif)** — including the full architecture, feature set, scan phases, and bug reports.

The code was built with the assistance of **[Claude AI](https://claude.ai)** (by Anthropic), which helped translate the ideas and design into working Python.

> _"The brain behind it is human. The hands that typed it had a little AI help."_

---

<p align="center">
  Designed by 🧙 <a href="https://github.com/magicianKaif">magician slime</a>
  &nbsp;•&nbsp;
  Built with the help of <a href="https://claude.ai">Claude AI</a>
</p>
