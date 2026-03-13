#!/usr/bin/env python3

# ============================================================
#   SLIME N SCANNER - Network Recon & Vulnerability Scanner
#   Developed by magician slime
#   GitHub : https://github.com/magicianKaif
# ============================================================

import argparse
import socket
import ssl
import re
import struct
import threading
import json
import os
import sys
import time
import sqlite3
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
#  DEPENDENCY CHECK — loud fatal errors only
# ─────────────────────────────────────────────

def _check_dependencies():
    missing = []
    for lib in ("rich", "requests"):
        try:
            __import__(lib)
        except ImportError:
            missing.append(lib)
    if missing:
        print("\n  [!] MISSING REQUIRED LIBRARIES: " + ", ".join(missing))
        print("  [!] Run:  pip install " + " ".join(missing))
        print("  [!] Full install:  pip install rich requests dnspython ipwhois python-whois\n")
        sys.exit(1)

_check_dependencies()

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console()

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = r"""
  ███████╗██╗     ██╗███╗   ███╗███████╗    ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
  ██╔════╝██║     ██║████╗ ████║██╔════╝    ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ███████╗██║     ██║██╔████╔██║█████╗      ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ╚════██║██║     ██║██║╚██╔╝██║██╔══╝      ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ███████║███████╗██║██║ ╚═╝ ██║███████╗    ██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝╚═╝     ╚═╝╚══════╝    ╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""

# FIX #11 — randomised UA pool so WAFs don't trivially block SLIME-N-SCANNER/1.0
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

def _random_ua() -> str:
    return random.choice(_USER_AGENTS)

def print_banner():
    console.print(BANNER, style="bold green")
    console.print("  ╔══════════════════════════════════════════════════════════════╗", style="bold cyan")
    console.print("  ║       Network Reconnaissance & Vulnerability Scanner         ║", style="bold cyan")
    console.print("  ║            Recon  •  Port Scan  •  CVE Detection             ║", style="bold cyan")
    console.print("  ╚══════════════════════════════════════════════════════════════╝", style="bold cyan")
    console.print()

def print_footer():
    console.print()
    console.print("  ╔══════════════════════════════════════════════════════════════╗", style="bold green")
    console.print("  ║                                                              ║", style="bold green")
    console.print("  ║          Developed by  magician slime                        ║", style="bold green")
    console.print("  ║          GitHub : https://github.com/magicianKaif           ║", style="bold green")
    console.print("  ║                                                              ║", style="bold green")
    console.print("  ╚══════════════════════════════════════════════════════════════╝", style="bold green")
    console.print()


# ─────────────────────────────────────────────
#  PHASE 1 — RECON
# ─────────────────────────────────────────────

def _safe_whois_attr(w, *attr_names):
    """
    Robust WHOIS attribute reader.
    Works with both 'whois' and 'python-whois' library APIs.
    FIX #8: converts datetime objects to ISO strings so JSON export never fails.
    """
    val = None
    for name in attr_names:
        val = getattr(w, name, None)
        if val is None and hasattr(w, "get"):
            try:
                val = w.get(name)
            except Exception:
                pass
        if val is not None:
            break

    if val is None:
        return "N/A"
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return "N/A"
    # FIX #8: datetime objects crash json.dump — convert to string here
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val).strip() or "N/A"


def run_recon(target: str) -> dict:
    console.rule("[bold cyan]  PHASE 1 — RECONNAISSANCE  ")
    console.print()

    recon_data = {
        "target": target, "ip": None, "reverse_dns": "N/A",
        "asn": "N/A", "ip_range": "N/A", "org": "N/A",
        "country": "N/A", "registrar": "N/A", "created": "N/A",
        "expires": "N/A", "dns_records": {}
    }

    # ── Resolve IP ──────────────────────────────────────────────────────
    try:
        ip = socket.gethostbyname(target)
        recon_data["ip"] = ip
        console.print(f"  [bold green][+][/bold green] Resolved Target   : [bold white]{target}[/bold white] -> [bold yellow]{ip}[/bold yellow]")
    except socket.gaierror:
        console.print(f"  [bold red][-][/bold red] Could not resolve [bold white]{target}[/bold white]. Check the target and your DNS.")
        return None

    # ── Reverse DNS ─────────────────────────────────────────────────────
    try:
        reverse = socket.gethostbyaddr(ip)[0]
        recon_data["reverse_dns"] = reverse
        console.print(f"  [bold green][+][/bold green] Reverse DNS       : [cyan]{reverse}[/cyan]")
    except Exception:
        console.print("  [yellow][~][/yellow] Reverse DNS       : Not available")

    # ── DNS Records ──────────────────────────────────────────────────────
    try:
        import dns.resolver
        import dns.exception
        found_records = {}
        for rtype in ["A", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(target, rtype, raise_on_no_answer=False)
                records = [str(r) for r in answers]
                if records:
                    found_records[rtype] = records
            # FIX #6: catch specific dns exceptions that older dnspython versions raise
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass
        recon_data["dns_records"] = found_records
        if found_records:
            console.print(f"  [bold green][+][/bold green] DNS Records       : {', '.join(found_records.keys())}")
        else:
            console.print("  [yellow][~][/yellow] DNS Records       : None found")
    except ImportError:
        console.print("  [yellow][~][/yellow] dnspython not installed — skipping (pip install dnspython)")

    # ── ASN / IP Range / Org ─────────────────────────────────────────────
    try:
        from ipwhois import IPWhois
        result   = IPWhois(ip).lookup_rdap(depth=1)
        asn      = result.get("asn",              "N/A")
        asn_desc = result.get("asn_description",  "N/A")
        asn_cidr = result.get("asn_cidr",         "N/A")
        country  = result.get("asn_country_code", "N/A")
        net_name = result.get("network", {}).get("name", "N/A")

        recon_data.update({
            "asn":      "AS" + str(asn) + " (" + str(asn_desc) + ")",
            "ip_range": asn_cidr,
            "org":      net_name,
            "country":  country,
        })
        console.print(f"  [bold green][+][/bold green] ASN               : [magenta]AS{asn}[/magenta] — {asn_desc}")
        console.print(f"  [bold green][+][/bold green] IP Range (CIDR)   : [bold yellow]{asn_cidr}[/bold yellow]")
        console.print(f"  [bold green][+][/bold green] Organisation      : [cyan]{net_name}[/cyan]")
        console.print(f"  [bold green][+][/bold green] Country           : [cyan]{country}[/cyan]")
        try:
            import ipaddress
            net = ipaddress.ip_network(asn_cidr, strict=False)
            console.print(f"  [bold green][+][/bold green] Hosts in Range    : [bold white]{net.num_addresses:,}[/bold white]")
        except Exception:
            pass
    except ImportError:
        console.print("  [yellow][~][/yellow] ipwhois not installed — skipping ASN lookup (pip install ipwhois)")
    except Exception as e:
        console.print(f"  [yellow][~][/yellow] ASN Lookup failed : {e}")

    # ── WHOIS ─────────────────────────────────────────────────────────────
    try:
        import whois as _whois_lib
        try:
            w = _whois_lib.whois(target)
        except Exception:
            w = None

        if w is not None:
            registrar = _safe_whois_attr(w, "registrar")
            creation  = _safe_whois_attr(w, "creation_date",   "created")
            expiry    = _safe_whois_attr(w, "expiration_date",  "expires", "expiry_date")
            recon_data.update({"registrar": registrar, "created": creation, "expires": expiry})
            if registrar != "N/A":
                console.print(f"  [bold green][+][/bold green] Registrar         : [cyan]{registrar}[/cyan]")
            if creation  != "N/A":
                console.print(f"  [bold green][+][/bold green] Domain Created    : [cyan]{creation}[/cyan]")
            if expiry    != "N/A":
                console.print(f"  [bold green][+][/bold green] Domain Expires    : [cyan]{expiry}[/cyan]")
        else:
            console.print("  [yellow][~][/yellow] WHOIS             : No data returned")
    except ImportError:
        console.print("  [yellow][~][/yellow] WHOIS library not installed (pip install python-whois)")
    except Exception as e:
        console.print(f"  [yellow][~][/yellow] WHOIS error : {e}")

    console.print()
    return recon_data


# ─────────────────────────────────────────────
#  PHASE 2 — PORT SCANNER
# ─────────────────────────────────────────────

TOP_1000_PORTS = sorted(set([
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    636, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2121, 2181, 2222, 2375, 2376, 3000,
    3001, 3128, 3268, 3269, 3306, 3307, 3389, 4000, 4001, 4444, 4848,
    5000, 5001, 5432, 5601, 5672, 5900, 5901, 6000, 6001, 6379, 6443,
    6667, 7001, 7002, 7070, 7443, 7474, 7777, 8000, 8001, 8008, 8009,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    8161, 8443, 8444, 8500, 8888, 8983, 9000, 9001, 9042, 9090, 9091,
    9092, 9200, 9300, 9418, 9443, 9999, 10000, 10250, 10255, 11211,
    15672, 16379, 27017, 27018, 28017, 50000, 50070, 61616
]))


def _scan_port_task(ip: str, port: int, timeout: float) -> int | None:
    """Returns the port number if open, else None. Used by ThreadPoolExecutor."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            return port
    except Exception:
        pass
    finally:
        if s:
            try: s.close()
            except Exception: pass
    return None


def run_port_scan(ip: str, ports: str = "top1000", timeout: float = 3.0, threads: int = 100) -> list:
    console.rule("[bold cyan]  PHASE 2 — PORT SCANNING  ")
    console.print()

    port_list = list(range(1, 65536)) if ports == "full" else TOP_1000_PORTS
    label     = "all 65,535" if ports == "full" else f"top {len(port_list)} common"
    console.print(f"  [bold yellow][*][/bold yellow] Scanning {label} ports on [bold white]{ip}[/bold white] ...")

    open_ports = []
    total      = len(port_list)

    # FIX #2: ThreadPoolExecutor keeps exactly `threads` threads alive at a time.
    # Previously we spawned one thread per port → up to 65,535 threads → OOM / RuntimeError.
    with Progress(
        SpinnerColumn(style="bold green"),
        TextColumn("  [bold cyan]Scanning ports..."),
        BarColumn(bar_width=40),
        TextColumn("[bold white]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console, transient=True
    ) as progress:
        task = progress.add_task("scan", total=total)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_scan_port_task, ip, p, timeout): p for p in port_list}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
                progress.update(task, advance=1)

    open_ports_sorted = sorted(open_ports)
    if open_ports_sorted:
        console.print(
            f"  [bold green][+][/bold green] Found [bold green]{len(open_ports_sorted)}[/bold green]"
            f" open port(s): [bold yellow]{', '.join(map(str, open_ports_sorted))}[/bold yellow]"
        )
    else:
        console.print("  [bold red][-][/bold red] No open ports found.")

    console.print()
    return open_ports_sorted


# ─────────────────────────────────────────────
#  PHASE 3 — SERVICE & VERSION DETECTION
# ─────────────────────────────────────────────

PORT_SERVICE_MAP = {
    21:"FTP",   22:"SSH",    23:"Telnet",  25:"SMTP",   53:"DNS",
    80:"HTTP",  110:"POP3",  111:"RPC",    135:"MSRPC", 139:"NetBIOS",
    143:"IMAP", 443:"HTTPS", 445:"SMB",    465:"SMTPS", 587:"SMTP-TLS",
    636:"LDAPS", 993:"IMAPS", 995:"POP3S", 1433:"MSSQL", 1521:"Oracle",
    1883:"MQTT", 2181:"Zookeeper", 2375:"Docker", 2376:"Docker-TLS",
    3000:"Grafana",  3306:"MySQL",   3389:"RDP",   5432:"PostgreSQL",
    5601:"Kibana",   5672:"RabbitMQ", 5900:"VNC",  6379:"Redis",
    7001:"WebLogic", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"Jupyter",
    9000:"Portainer", 9090:"Prometheus", 9200:"Elasticsearch",
    9300:"Elastic-Transport", 10250:"Kubelet", 11211:"Memcached",
    15672:"RabbitMQ-Mgmt", 27017:"MongoDB", 50070:"Hadoop", 61616:"ActiveMQ",
}

VERSION_PATTERNS = [
    (r"SSH-[\d.]+-OpenSSH_([\d.p]+\w*)",        "OpenSSH"),
    (r"Server:\s*nginx/([\d.]+)",               "nginx"),
    (r"Server:\s*Apache/([\d.]+)",              "Apache httpd"),
    (r"Server:\s*Apache-Coyote/([\d.]+)",       "Apache Tomcat"),
    (r"Server:\s*Tomcat/([\d.]+)",              "Apache Tomcat"),
    (r"Server:\s*Microsoft-IIS/([\d.]+)",       "Microsoft IIS"),
    (r"Server:\s*lighttpd/([\d.]+)",            "lighttpd"),
    (r"Server:\s*LiteSpeed/([\d.]+)",           "LiteSpeed"),
    (r"X-Powered-By:\s*PHP/([\d.]+)",           "PHP"),
    (r"220[- ].*vsftpd\s+([\d.]+)",             "vsftpd"),
    (r"220[- ].*ProFTPD\s+([\d.]+)",            "ProFTPD"),
    (r"220[- ].*FileZilla\s+Server\s+([\d.]+)", "FileZilla Server"),
    (r"220[- ].*Pure-FTPd\s+([\d.]+)",          "Pure-FTPd"),
    (r"([\d]+\.[\d.]+)-MariaDB",                "MariaDB"),
    (r"([\d]+\.[\d.]+)\s+MySQL",                "MySQL"),
    (r'"version"\s*:\s*"([\d.]+)"',             "Elasticsearch"),
    (r"redis_version:([\d.]+)",                 "Redis"),
    (r"memcached\s+([\d.]+)",                   "Memcached"),
    (r"VERSION\s+([\d.]+)",                     "Memcached"),
    # FIX #3: patterns without capture groups (Postfix, Dovecot) — ver stays ""
    (r"Postfix\s+ESMTP",                        "Postfix"),
    (r"Exim\s+([\d.]+)",                        "Exim"),
    (r"Dovecot",                                "Dovecot"),
    (r"OpenSSH_([\d.p]+)",                      "OpenSSH"),
]

TLS_PORTS = {443, 8443, 993, 995, 465, 636}


def _build_probes(hostname: str) -> dict:
    """
    FIX #9: use GET HTTP/1.0 for better server compatibility.
    HEAD is rejected by many servers / WAFs.
    FIX #11: randomised User-Agent so WAFs don't trivially fingerprint the scanner.
    """
    ua = _random_ua()
    # HTTP/1.0 avoids chunked-encoding edge-cases and is accepted by virtually all servers
    http_get = (
        "GET / HTTP/1.0\r\n"
        "Host: " + hostname + "\r\n"
        "User-Agent: " + ua + "\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    return {
        80:    http_get,
        8080:  http_get,
        8000:  http_get,
        8001:  http_get,
        8081:  http_get,
        8082:  http_get,
        8088:  http_get,
        8443:  http_get,
        8888:  http_get,
        9000:  http_get,
        9090:  http_get,
        9200:  http_get,
        25:    b"EHLO slimescanner.local\r\n",
        21:    b"",
        22:    b"",
        110:   b"",
        143:   b"",
        3306:  b"",
        6379:  b"INFO server\r\n",
        27017: b"",
        11211: b"version\r\n",
    }


def _grab_banner(ip: str, port: int, timeout: float, probes: dict,
                 hostname: str = None) -> str:
    """
    FIX #1: pass hostname (domain) as SNI server_hostname, not the IP.
    TLS SNI expects the domain name. Using IP causes wrong cert / handshake failure.
    """
    sni      = hostname or ip      # FIX #1
    probe    = probes.get(port, b"")
    raw_data = b""
    s        = None
    try:
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = socket.create_connection((ip, port), timeout=timeout)
            s   = ctx.wrap_socket(raw, server_hostname=sni)  # FIX #1
        else:
            s = socket.create_connection((ip, port), timeout=timeout)

        if probe:
            s.sendall(probe)

        s.settimeout(timeout)
        for _ in range(6):
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                raw_data += chunk
                if len(raw_data) >= 4096:
                    break
            except socket.timeout:
                break
    except Exception:
        pass
    finally:
        if s:
            try: s.close()
            except Exception: pass

    return raw_data.decode("utf-8", errors="ignore").strip()


def _get_tls_info(ip: str, port: int, timeout: float, hostname: str = None) -> dict:
    """
    FIX #1: use domain name for SNI, not the IP address.
    FIX #12: include both DNS and IP Address SANs from the certificate.
    """
    sni  = hostname or ip          # FIX #1
    info = {}
    s    = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        raw  = socket.create_connection((ip, port), timeout=timeout)
        s    = ctx.wrap_socket(raw, server_hostname=sni)  # FIX #1
        cert = s.getpeercert()
        info["cipher"]      = s.cipher()[0] if s.cipher() else "N/A"
        info["tls_version"] = s.version()
        if cert:
            info["not_after"] = cert.get("notAfter", "N/A")
            # FIX #12: include IP Address SANs, not just DNS
            info["sans"] = [
                t + ":" + v
                for t, v in cert.get("subjectAltName", [])
                if t in ("DNS", "IP Address")
            ][:6]
    except Exception:
        pass
    finally:
        if s:
            try: s.close()
            except Exception: pass
    return info


def _detect_version(banner: str):
    for pattern, name in VERSION_PATTERNS:
        try:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                # FIX #3: use m.groups() — safe for patterns with no capture groups
                # (e.g. "Postfix\s+ESMTP" has no group → returns "" not IndexError)
                ver = m.group(1) if m.groups() else ""
                return name, ver
        except Exception:
            continue
    return None, None


def _icmp_checksum(data: bytes) -> int:
    """
    FIX #5: wrap every addition with & 0xFFFF to prevent integer overflow
    on large packets. Python ints are unbounded so without masking the
    result can exceed 16 bits and produce a wrong checksum.
    """
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        # FIX #5: mask after every addition
        s = (s + ((data[i] << 8) + data[i + 1])) & 0xFFFF
    if n:
        s = (s + (data[-1] << 8)) & 0xFFFF
    s  = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def _os_hint(ip: str) -> str:
    """
    Locale-independent OS fingerprinting via raw ICMP TTL.
    FIX #4: catch (PermissionError, OSError) — Linux raises OSError not PermissionError
            when raw sockets are blocked without root.
    """
    # ── Method 1: raw ICMP (reads TTL from IP header byte 8, no string parsing) ──
    try:
        proto = socket.IPPROTO_ICMP
        s     = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        s.settimeout(3)

        icmp_id  = os.getpid() & 0xFFFF
        payload  = b"slimescanner-ttlcheck"
        header   = struct.pack("bbHHH", 8, 0, 0, icmp_id, 1)
        checksum = _icmp_checksum(header + payload)
        packet   = struct.pack("bbHHH", 8, 0, checksum, icmp_id, 1) + payload

        s.sendto(packet, (ip, 0))
        recv, _ = s.recvfrom(1024)
        s.close()

        ttl = struct.unpack("B", recv[8:9])[0]
        if   ttl <= 64:  return "Linux / Unix  (TTL=" + str(ttl) + ")"
        elif ttl <= 128: return "Windows       (TTL=" + str(ttl) + ")"
        else:            return "Network Device (TTL=" + str(ttl) + ")"

    # FIX #4: Linux raises OSError("Operation not permitted"), not just PermissionError
    except (PermissionError, OSError):
        pass
    except Exception:
        pass

    # ── Method 2: subprocess ping fallback (locale-safe) ──────────────────────
    try:
        import subprocess, platform
        cmd = ["ping", "-n" if platform.system() == "Windows" else "-c", "1", ip]
        raw = subprocess.check_output(cmd, timeout=5, stderr=subprocess.DEVNULL)
        out = raw.decode("utf-8", errors="replace")
        # TTL digits are locale-independent — only surrounding text differs
        m   = re.search(r"ttl[=:\s]+(\d+)", out, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if   ttl <= 64:  return "Linux / Unix  (TTL=" + str(ttl) + ")"
            elif ttl <= 128: return "Windows       (TTL=" + str(ttl) + ")"
            else:            return "Network Device (TTL=" + str(ttl) + ")"
    except Exception:
        pass

    return "Unknown (run as admin for raw ICMP detection)"


def run_service_detection(ip: str, open_ports: list,
                          timeout: float = 3.0,          # FIX #10: default 3s not 2s
                          hostname: str = None) -> dict:
    console.rule("[bold cyan]  PHASE 3 — SERVICE & VERSION DETECTION  ")
    console.print()

    if not open_ports:
        console.print("  [yellow][~][/yellow] No open ports to probe.")
        console.print()
        return {}

    os_hint = _os_hint(ip)
    console.print(f"  [bold green][+][/bold green] OS Fingerprint       : [bold magenta]{os_hint}[/bold magenta]")
    console.print()

    # FIX #1: build probes using hostname so Host header is correct
    probes   = _build_probes(hostname or ip)
    services = {}

    for port in open_ports:
        # FIX #1: pass hostname through so TLS SNI uses domain not IP
        banner   = _grab_banner(ip, port, timeout, probes, hostname=hostname)
        svc, ver = _detect_version(banner)
        tls_info = _get_tls_info(ip, port, timeout, hostname=hostname) if port in TLS_PORTS else {}

        final_svc = svc or PORT_SERVICE_MAP.get(port, "unknown")
        final_ver = ver or ""

        services[port] = {
            "port":     port,
            "service":  final_svc,
            "version":  final_ver,
            "banner":   banner[:200],
            "tls_info": tls_info,
            "os_hint":  os_hint,
        }

        ver_str = f"[bold white]{final_ver}[/bold white]" if final_ver else "[dim]version unknown[/dim]"
        tls_str = f" [dim][TLS: {tls_info.get('tls_version','?')}][/dim]" if tls_info else ""
        console.print(
            f"  [bold green][+][/bold green]"
            f" Port [bold yellow]{port:<6}[/bold yellow] ->"
            f" [bold cyan]{final_svc:<22}[/bold cyan] {ver_str}{tls_str}"
        )
        if tls_info.get("not_after"):
            console.print(f"               [dim]Cert Expires : {tls_info['not_after']}[/dim]")
        if tls_info.get("sans"):
            console.print(f"               [dim]SANs         : {', '.join(tls_info['sans'])}[/dim]")

    console.print()
    return services


# ─────────────────────────────────────────────
#  PHASE 4 — CVE LOOKUP
# ─────────────────────────────────────────────

NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DB_PATH   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_cache.db")

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
SEV_COLOR = {
    "CRITICAL": "bold red", "HIGH": "red",
    "MEDIUM":   "bold yellow", "LOW": "yellow", "NONE": "dim",
}

# Maps detected service name -> (NVD vendor, NVD product) for CPE search
# FIX #7: CPE-based search is far more precise than keyword search
CPE_MAP = {
    "openssh":          ("openbsd",      "openssh"),
    "nginx":            ("nginx",        "nginx"),
    "apache httpd":     ("apache",       "http_server"),
    "apache tomcat":    ("apache",       "tomcat"),
    "microsoft iis":    ("microsoft",    "internet_information_services"),
    "iis":              ("microsoft",    "internet_information_services"),
    "lighttpd":         ("lighttpd",     "lighttpd"),
    "litespeed":        ("litespeedtech","litespeed_web_server"),
    "php":              ("php",          "php"),
    "mysql":            ("mysql",        "mysql"),
    "mariadb":          ("mariadb",      "mariadb"),
    "postgresql":       ("postgresql",   "postgresql"),
    "redis":            ("redis",        "redis"),
    "mongodb":          ("mongodb",      "mongodb"),
    "elasticsearch":    ("elastic",      "elasticsearch"),
    "memcached":        ("memcached",    "memcached"),
    "vsftpd":           ("beasts",       "vsftpd"),
    "proftpd":          ("proftpd",      "proftpd"),
    "filezilla server": ("filezilla-project", "filezilla_server"),
    "exim":             ("exim",         "exim"),
    "postfix":          ("postfix",      "postfix"),
    "dovecot":          ("dovecot",      "dovecot"),
    "openssl":          ("openssl",      "openssl"),
    "weblogic":         ("oracle",       "weblogic_server"),
}

# Keyword fallback for services not in CPE_MAP
CVE_KEYWORD_MAP = {
    "openssh":       "OpenSSH",
    "nginx":         "nginx",
    "apache httpd":  "Apache HTTP Server",
    "apache tomcat": "Apache Tomcat",
    "microsoft iis": "Microsoft IIS",
    "php":           "PHP",
    "mysql":         "MySQL",
    "mariadb":       "MariaDB",
    "postgresql":    "PostgreSQL",
    "redis":         "Redis",
    "mongodb":       "MongoDB",
    "elasticsearch": "Elasticsearch",
    "memcached":     "Memcached",
    "vsftpd":        "vsftpd",
    "proftpd":       "ProFTPD",
    "exim":          "Exim",
    "postfix":       "Postfix",
    "dovecot":       "Dovecot",
    "openssl":       "OpenSSL",
    "weblogic":      "Oracle WebLogic",
}

# ── NVD rolling-window rate limiter ─────────────────────────────────────────
_nvd_request_times: list = []
_nvd_rate_lock = threading.Lock()

def _nvd_rate_wait(api_key: str = None):
    """Block until we're within the NVD rolling rate limit."""
    limit  = 50 if api_key else 5
    window = 30.0
    while True:
        with _nvd_rate_lock:
            now = time.time()
            _nvd_request_times[:] = [t for t in _nvd_request_times if now - t < window]
            if len(_nvd_request_times) < limit:
                _nvd_request_times.append(now)
                return
            oldest    = _nvd_request_times[0]
            wait_secs = window - (now - oldest) + 0.3
        console.print(f"  [dim][~] NVD rate limit ({limit} req/30s) — waiting {wait_secs:.1f}s ...[/dim]")
        time.sleep(wait_secs)


def _db_init():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS cache (q TEXT PRIMARY KEY, data TEXT, ts INTEGER)")
    conn.commit()
    conn.close()

def _db_get(q: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        row  = conn.execute("SELECT data, ts FROM cache WHERE q=?", (q,)).fetchone()
        conn.close()
        if row and time.time() - row[1] < 86400:
            return json.loads(row[0])
    except Exception:
        pass
    return None

def _db_set(q: str, data: list):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?)",
                     (q, json.dumps(data), int(time.time())))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _parse_cve_list(vuln_list: list, product_name: str) -> list:
    """Parse NVD vulnerabilities response into clean dicts, filter to product."""
    results = []
    for v in vuln_list:
        cve    = v.get("cve", {})
        cve_id = cve.get("id", "N/A")
        desc   = next((d["value"] for d in cve.get("descriptions", [])
                       if d["lang"] == "en"), "No description.")
        desc   = (desc[:200] + "...") if len(desc) > 200 else desc

        metrics  = cve.get("metrics", {})
        score    = "N/A"
        severity = "NONE"
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metrics.get(key):
                m_data   = metrics[key][0]
                cvss_d   = m_data.get("cvssData", {})
                score    = cvss_d.get("baseScore", "N/A")
                severity = m_data.get("baseSeverity",
                                      cvss_d.get("baseSeverity", "NONE")).upper()
                break

        refs    = cve.get("references", [])
        ref_url = (refs[0]["url"] if refs
                   else "https://nvd.nist.gov/vuln/detail/" + cve_id)

        entry = {
            "id":          cve_id,
            "description": desc,
            "cvss_score":  score,
            "severity":    severity,
            "reference":   ref_url,
        }

        # Anti-false-positive: description must mention the product
        prod_words = [w for w in product_name.lower().split() if len(w) >= 3]
        if any(w in desc.lower() for w in prod_words):
            results.append(entry)

    results.sort(
        key=lambda c: float(c["cvss_score"])
            if str(c["cvss_score"]).replace(".", "").isdigit() else 0.0,
        reverse=True,
    )
    return results


def _fetch_cves_cpe(vendor: str, product: str, version: str,
                    api_key: str = None) -> list:
    """
    FIX #7 — primary method: CPE-based NVD search.
    cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
    Much more precise than keyword search — only returns CVEs that
    match the exact product/version in the official CPE dictionary.
    """
    cpe_str   = "cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
    cache_key = "cpe_" + vendor + "_" + product + "_" + version
    cached    = _db_get(cache_key)
    if cached is not None:
        return cached

    headers = {"User-Agent": _random_ua()}
    if api_key:
        headers["apiKey"] = api_key

    try:
        _nvd_rate_wait(api_key)
        resp = requests.get(
            NVD_API,
            params={"cpeName": cpe_str, "resultsPerPage": 10},
            headers=headers,
            timeout=15,
        )
        if resp.status_code in (403, 429):
            console.print("  [bold red][!][/bold red] NVD rate limit hit — waiting 35s ...")
            time.sleep(35)
            _nvd_rate_wait(api_key)
            resp = requests.get(
                NVD_API,
                params={"cpeName": cpe_str, "resultsPerPage": 10},
                headers=headers,
                timeout=15,
            )
        resp.raise_for_status()
        results = _parse_cve_list(resp.json().get("vulnerabilities", []),
                                  product.replace("_", " "))
        _db_set(cache_key, results)
        return results
    except requests.exceptions.ConnectionError:
        return []
    except requests.exceptions.Timeout:
        return []
    except Exception:
        return []


def _fetch_cves_keyword(keyword_product: str, version: str,
                        api_key: str = None) -> list:
    """
    FIX #7 — fallback: keyword search when no CPE entry available.
    Still more accurate than bare keyword because we filter results
    through _parse_cve_list which checks product name in description.
    """
    if not version:
        return []

    keyword   = keyword_product + " " + version
    cache_key = "kw_" + keyword.lower().replace(" ", "_")
    cached    = _db_get(cache_key)
    if cached is not None:
        return cached

    headers = {"User-Agent": _random_ua()}
    if api_key:
        headers["apiKey"] = api_key

    try:
        _nvd_rate_wait(api_key)
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": 10},
            headers=headers,
            timeout=15,
        )
        if resp.status_code in (403, 429):
            console.print("  [bold red][!][/bold red] NVD rate limit hit — waiting 35s ...")
            time.sleep(35)
            _nvd_rate_wait(api_key)
            resp = requests.get(
                NVD_API,
                params={"keywordSearch": keyword, "resultsPerPage": 10},
                headers=headers,
                timeout=15,
            )
        resp.raise_for_status()
        results = _parse_cve_list(resp.json().get("vulnerabilities", []),
                                  keyword_product)
        _db_set(cache_key, results)
        return results
    except requests.exceptions.ConnectionError:
        console.print("  [yellow][~][/yellow] No internet — CVE lookup skipped")
        return []
    except requests.exceptions.Timeout:
        console.print("  [yellow][~][/yellow] NVD API timeout — CVE lookup skipped")
        return []
    except Exception as e:
        console.print(f"  [yellow][~][/yellow] CVE fetch error: {e}")
        return []


def run_cve_lookup(services: dict, severity: str = "all",
                   api_key: str = None) -> dict:
    console.rule("[bold cyan]  PHASE 4 — CVE VULNERABILITY LOOKUP  ")
    console.print()
    _db_init()

    if not services:
        console.print("  [yellow][~][/yellow] No services to check.")
        console.print()
        return {}

    if api_key:
        console.print("  [bold green][+][/bold green] NVD API key active — 50 req/30s limit")
    else:
        console.print("  [yellow][~][/yellow] No NVD API key — 5 req/30s limit  (--api-key to speed up)")
    console.print()

    cve_results = {}
    total       = 0
    skipped     = 0
    min_level   = SEV_ORDER.get(severity.upper(), 0) if severity != "all" else 0

    for port, info in services.items():
        raw_svc = info.get("service", "")
        ver     = info.get("version", "")

        if not raw_svc or raw_svc.lower() == "unknown":
            continue

        if not ver:
            console.print(
                f"  [dim][~] Port {port} [{raw_svc}] — version unknown, skipping"
                " (use --timeout 3 for better detection)[/dim]"
            )
            skipped += 1
            continue

        svc_key = raw_svc.lower()
        console.print(f"  [bold yellow][*][/bold yellow] CVE check : [bold cyan]{raw_svc} {ver}[/bold cyan] ...")

        # FIX #7: try CPE search first (precise), fall back to keyword search
        cpe_entry = CPE_MAP.get(svc_key)
        if cpe_entry:
            cves = _fetch_cves_cpe(cpe_entry[0], cpe_entry[1], ver, api_key=api_key)
            if not cves:
                # CPE version string might not match NVD exactly — try keyword too
                kw = CVE_KEYWORD_MAP.get(svc_key, raw_svc)
                cves = _fetch_cves_keyword(kw, ver, api_key=api_key)
        else:
            kw   = CVE_KEYWORD_MAP.get(svc_key, raw_svc)
            cves = _fetch_cves_keyword(kw, ver, api_key=api_key)

        filtered = [c for c in cves if SEV_ORDER.get(c["severity"], 0) >= min_level]

        if filtered:
            cve_results[port] = filtered
            total += len(filtered)
            for cve in filtered:
                color = SEV_COLOR.get(cve["severity"], "white")
                console.print(
                    f"    [{color}]  !  {cve['id']:<22}"
                    f"  CVSS {str(cve['cvss_score']):<5}"
                    f"  [{cve['severity']}][/{color}]"
                )
                console.print(f"    [dim]     {cve['description']}[/dim]")
                console.print(f"    [dim]     Ref: {cve['reference']}[/dim]")
        else:
            console.print(f"    [bold green]  OK  No matching CVEs for {raw_svc} {ver}[/bold green]")

        console.print()

    if skipped:
        console.print(f"  [dim][~] {skipped} service(s) skipped — version unknown[/dim]")
        console.print()

    if total:
        console.print(f"  [bold red][!][/bold red] Total confirmed vulnerabilities : [bold red]{total}[/bold red]")
    else:
        console.print("  [bold green][OK][/bold green] No confirmed vulnerabilities in versioned services")

    console.print()
    return cve_results


# ─────────────────────────────────────────────
#  PHASE 5 — FINAL REPORT
# ─────────────────────────────────────────────

SEV_EMOJI = {
    "CRITICAL": "[CRIT]", "HIGH": "[HIGH]",
    "MEDIUM":   "[MED]",  "LOW":  "[LOW]",  "NONE": "[ ]",
}


def print_final_report(recon_data: dict, services: dict,
                       cve_results: dict, output_file: str = None):
    console.rule("[bold cyan]  FINAL REPORT — SLIME N SCANNER  ")
    console.print()

    # ── Recon summary ───────────────────────────────────────────────────
    fields = [
        ("Target",       recon_data.get("target",      "N/A"), "bold white"),
        ("IP",           recon_data.get("ip",           "N/A"), "bold yellow"),
        ("Reverse DNS",  recon_data.get("reverse_dns",  "N/A"), "cyan"),
        ("ASN",          recon_data.get("asn",          "N/A"), "magenta"),
        ("IP Range",     recon_data.get("ip_range",     "N/A"), "bold cyan"),
        ("Organisation", recon_data.get("org",          "N/A"), "cyan"),
        ("Country",      recon_data.get("country",      "N/A"), "cyan"),
        ("Registrar",    recon_data.get("registrar",    "N/A"), "dim"),
        ("Created",      recon_data.get("created",      "N/A"), "dim"),
        ("Expires",      recon_data.get("expires",      "N/A"), "dim"),
    ]
    os_hint = next((v.get("os_hint", "") for v in services.values()), "")
    if os_hint:
        fields.append(("OS Hint", os_hint, "bold magenta"))

    for label, value, color in fields:
        if str(value) not in ("N/A", "None", ""):
            console.print(f"  [bold]{label:<14}:[/bold]  [{color}]{value}[/{color}]")
    console.print()

    # ── Ports & Services table ───────────────────────────────────────────
    if services:
        tbl = Table(box=box.ROUNDED, header_style="bold cyan", border_style="cyan",
                    title="[bold white]Open Ports & Services[/bold white]")
        tbl.add_column("PORT",    style="bold yellow", width=7)
        tbl.add_column("SERVICE", style="bold cyan",   width=22)
        tbl.add_column("VERSION", style="bold white",  width=18)
        tbl.add_column("TLS",     style="dim",         width=10)
        tbl.add_column("CVEs",    style="bold red",    width=36)

        for port, info in sorted(services.items()):
            pcves = cve_results.get(port, [])
            if pcves:
                top      = pcves[0]
                cve_cell = top["id"] + " CVSS " + str(top["cvss_score"])
                if len(pcves) > 1:
                    cve_cell += " (+" + str(len(pcves) - 1) + " more)"
            else:
                ver      = info.get("version", "")
                cve_cell = ("[green]Clean[/green]" if ver
                            else "[dim]No version — not checked[/dim]")

            tls_ver = info.get("tls_info", {}).get("tls_version", "—")
            tbl.add_row(str(port), info.get("service", "?"),
                        info.get("version", "—") or "—", tls_ver, cve_cell)
        console.print(tbl)
        console.print()

    # ── CVE detail table ─────────────────────────────────────────────────
    all_cves = [(p, c) for p, cves in cve_results.items() for c in cves]
    if all_cves:
        vtbl = Table(box=box.ROUNDED, header_style="bold red", border_style="red",
                     title="[bold red]Confirmed Vulnerabilities[/bold red]")
        vtbl.add_column("PORT",        style="bold yellow", width=6)
        vtbl.add_column("CVE ID",      style="bold red",    width=20)
        vtbl.add_column("CVSS",        style="bold white",  width=7)
        vtbl.add_column("SEVERITY",    width=12)
        vtbl.add_column("DESCRIPTION", style="dim white",   width=55)

        for port, cve in all_cves:
            color = SEV_COLOR.get(cve["severity"], "white")
            vtbl.add_row(
                str(port), cve["id"], str(cve["cvss_score"]),
                f"[{color}]{cve['severity']}[/{color}]",
                cve["description"][:120],
            )
        console.print(vtbl)
        console.print()

        critical = sum(1 for _, c in all_cves if c["severity"] == "CRITICAL")
        high     = sum(1 for _, c in all_cves if c["severity"] == "HIGH")
        medium   = sum(1 for _, c in all_cves if c["severity"] == "MEDIUM")
        console.print(f"  [bold red][!] TOTAL CONFIRMED VULNERABILITIES : {len(all_cves)}[/bold red]")
        if critical: console.print(f"  [bold red]    CRITICAL : {critical}[/bold red]")
        if high:     console.print(f"  [red]    HIGH     : {high}[/red]")
        if medium:   console.print(f"  [bold yellow]    MEDIUM   : {medium}[/bold yellow]")
    else:
        console.print("  [bold green][OK] No confirmed vulnerabilities found.[/bold green]")

    console.print()
    if output_file:
        _export(output_file, recon_data, services, cve_results)


# ─────────────────────────────────────────────
#  EXPORT
# ─────────────────────────────────────────────

class _DatetimeEncoder(json.JSONEncoder):
    """FIX #8: ensures datetime objects in WHOIS data are serialised as strings."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def _export(path: str, recon_data, services, cve_results):
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".json":
            report = {
                "scan_time":       datetime.now().isoformat(),
                "scanner":         "SLIME N SCANNER",
                "author":          "magician slime",
                "github":          "https://github.com/magicianKaif",
                "recon":           recon_data,
                "services":        {str(k): v for k, v in services.items()},
                "vulnerabilities": {str(k): v for k, v in cve_results.items()},
            }
            with open(path, "w", encoding="utf-8") as f:
                # FIX #8: use custom encoder so datetime objects don't crash json.dump
                json.dump(report, f, indent=2, ensure_ascii=False, cls=_DatetimeEncoder)
            console.print(f"  [bold green][+][/bold green] JSON report saved -> [bold white]{path}[/bold white]")

        elif ext == ".html":
            with open(path, "w", encoding="utf-8") as f:
                f.write(_html_report(recon_data, services, cve_results))
            console.print(f"  [bold green][+][/bold green] HTML report saved -> [bold white]{path}[/bold white]")

        else:
            console.print(f"  [yellow][~][/yellow] Unknown extension '{ext}' — saving as JSON")
            _export(path + ".json", recon_data, services, cve_results)

    except OSError as e:
        console.print(f"  [bold red][-][/bold red] Could not save report: {e}")


def _html_report(recon_data, services, cve_results) -> str:
    now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sc_map   = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44aaff","NONE":"#888"}
    all_cves = [(p, c) for p, cves in cve_results.items() for c in cves]

    rows_list = []
    for p, i in sorted(services.items()):
        svc = i.get("service", "")
        ver = i.get("version", "") or "—"
        if cve_results.get(p):
            badge = '<span style="color:#ff4444">&#9888; ' + str(len(cve_results[p])) + " CVE(s)</span>"
        elif ver == "—":
            badge = '<span style="color:#888">— not checked</span>'
        else:
            badge = '<span style="color:#44ff88">&#10003; Clean</span>'
        rows_list.append(
            "<tr><td>" + str(p) + "</td><td>" + svc + "</td><td>" + ver +
            "</td><td>" + badge + "</td></tr>"
        )
    rows = "".join(rows_list) or "<tr><td colspan='4'>No services detected</td></tr>"

    cve_rows_list = []
    for p, c in all_cves:
        col = sc_map.get(c["severity"], "#888")
        cve_rows_list.append(
            "<tr><td>" + str(p) + "</td>"
            + "<td style='color:#ff6666'>" + c["id"] + "</td>"
            + "<td>" + str(c["cvss_score"]) + "</td>"
            + "<td style='color:" + col + "'>" + c["severity"] + "</td>"
            + "<td>" + c["description"][:150] + "</td>"
            + "<td><a href='" + c["reference"] + "' target='_blank'>Link</a></td></tr>"
        )
    cve_rows = "".join(cve_rows_list) or (
        "<tr><td colspan='6' style='color:#44ff88'>No vulnerabilities found</td></tr>"
    )

    return (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        "<meta http-equiv='Content-Type' content='text/html; charset=utf-8'>"
        "<title>SLIME N SCANNER - Report</title>"
        "<style>"
        "body{background:#0d0d0d;color:#eee;font-family:monospace;padding:2rem;max-width:1400px;margin:0 auto}"
        "h1{color:#00ff88}h2{color:#00ccff;border-bottom:1px solid #333;padding-bottom:.4rem;margin-top:2rem}"
        "table{width:100%;border-collapse:collapse;margin-bottom:2rem}"
        "th{background:#1a1a2e;color:#00ccff;padding:.6rem;text-align:left;border:1px solid #333}"
        "td{padding:.5rem;border:1px solid #1a1a1a}"
        "tr:hover{background:#111}"
        "a{color:#00ccff}a:hover{color:#00ff88}"
        ".footer{text-align:center;margin-top:3rem;color:#555;padding:1rem;border-top:1px solid #222}"
        "</style></head><body>"
        "<h1>SLIME N SCANNER - Scan Report</h1>"
        "<p style='color:#aaa'>Generated: " + now
        + " &nbsp;|&nbsp; Target: " + str(recon_data.get("target", ""))
        + " &nbsp;|&nbsp; IP: "     + str(recon_data.get("ip",     "")) + "</p>"
        "<h2>Reconnaissance</h2>"
        "<table><tr><th>Field</th><th>Value</th></tr>"
        "<tr><td>ASN</td><td>"          + str(recon_data.get("asn",         "N/A")) + "</td></tr>"
        "<tr><td>IP Range</td><td>"     + str(recon_data.get("ip_range",    "N/A")) + "</td></tr>"
        "<tr><td>Organisation</td><td>" + str(recon_data.get("org",         "N/A")) + "</td></tr>"
        "<tr><td>Country</td><td>"      + str(recon_data.get("country",     "N/A")) + "</td></tr>"
        "<tr><td>Reverse DNS</td><td>"  + str(recon_data.get("reverse_dns", "N/A")) + "</td></tr>"
        "<tr><td>Registrar</td><td>"    + str(recon_data.get("registrar",   "N/A")) + "</td></tr>"
        "<tr><td>Created</td><td>"      + str(recon_data.get("created",     "N/A")) + "</td></tr>"
        "<tr><td>Expires</td><td>"      + str(recon_data.get("expires",     "N/A")) + "</td></tr>"
        "</table>"
        "<h2>Open Ports &amp; Services</h2>"
        "<table><tr><th>Port</th><th>Service</th><th>Version</th><th>CVE Status</th></tr>"
        + rows + "</table>"
        "<h2>Confirmed Vulnerabilities</h2>"
        "<table><tr><th>Port</th><th>CVE ID</th><th>CVSS</th>"
        "<th>Severity</th><th>Description</th><th>Ref</th></tr>"
        + cve_rows + "</table>"
        "<div class='footer'>"
        "<p>Developed by <strong style='color:#00ff88'>magician slime</strong></p>"
        "<p><a href='https://github.com/magicianKaif' target='_blank'>https://github.com/magicianKaif</a></p>"
        "</div></body></html>"
    )


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SLIME N SCANNER - Network Recon & Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target",
        help="Target domain or IP address")
    parser.add_argument("--ports", choices=["top1000", "full"], default="top1000",
        help="Port range: top1000 (default) or full (1-65535)")
    # FIX #10: default timeout raised to 3s for better service detection
    parser.add_argument("--timeout", type=float, default=3.0,
        help="Socket timeout in seconds (default: 3)")
    parser.add_argument("--threads", type=int, default=100,
        help="Concurrent scan threads (default: 100)")
    parser.add_argument("--output", metavar="FILE",
        help="Save report as FILE.json or FILE.html")
    parser.add_argument("--severity",
        choices=["all", "critical", "high", "medium"], default="all",
        help="Minimum CVE severity to show (default: all)")
    parser.add_argument("--no-cve", action="store_true",
        help="Skip CVE lookup entirely")
    parser.add_argument("--api-key", metavar="KEY", default=None,
        help="NVD API key — 50 req/30s instead of 5 req/30s\n"
             "Get free key: https://nvd.nist.gov/developers/request-an-api-key")

    args = parser.parse_args()

    print_banner()

    recon_data = run_recon(args.target)
    if not recon_data:
        print_footer()
        sys.exit(1)

    open_ports = run_port_scan(
        recon_data["ip"],
        ports=args.ports,
        timeout=args.timeout,
        threads=args.threads,
    )

    # FIX #1: pass original target (domain) as hostname so TLS SNI works correctly
    services = run_service_detection(
        recon_data["ip"],
        open_ports,
        timeout=args.timeout,
        hostname=args.target,        # FIX #1
    )

    cve_results = {}
    if not args.no_cve:
        cve_results = run_cve_lookup(
            services,
            severity=args.severity,
            api_key=args.api_key,
        )

    print_final_report(recon_data, services, cve_results, args.output)
    print_footer()


if __name__ == "__main__":
    main()
