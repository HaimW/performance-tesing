#!/usr/bin/env python3
"""
find_origin.py — Discover the real origin IP behind a CDN (e.g. Cloudflare)
using passive OSINT techniques only (no active scanning).

Usage:
    python3 scripts/find_origin.py example.com

Techniques used (same as white-hat recon):
  1. Direct A record — is it already exposed?
  2. www subdomain — sometimes not proxied
  3. MX records    — mail servers often share the same host
  4. SPF TXT record — often contains the sending IP (= origin server)
  5. Common subdomains — staging, dev, mail, ftp, cpanel, etc.
  6. Certificate transparency (crt.sh) — all subdomains ever issued a cert
"""

import sys
import socket
import ipaddress
import json
import subprocess
import urllib.request
import urllib.error

# Cloudflare's published IPv4 CIDR ranges (https://www.cloudflare.com/ips-v4)
_CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22",   "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",   "172.64.0.0/13",   "131.0.72.0/22",
]
_CF_NETS = [ipaddress.ip_network(r) for r in _CF_RANGES]

_COMMON_SUBS = [
    "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "cpanel", "whm", "plesk", "admin",
    "direct", "origin", "server", "host",
    "dev", "staging", "beta", "test",
    "api", "ns1", "ns2", "vpn", "remote",
]


def is_cloudflare(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CF_NETS)
    except ValueError:
        return False


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _dig(qtype: str, name: str) -> list[str]:
    try:
        r = subprocess.run(
            ["dig", "+short", qtype, name],
            capture_output=True, text=True, timeout=8,
        )
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def mx_ips(domain: str) -> list[tuple[str, str]]:
    results = []
    for line in _dig("MX", domain):
        parts = line.split()
        if len(parts) >= 2:
            host = parts[-1].rstrip(".")
            ip = resolve(host)
            if ip:
                results.append((host, ip))
    return results


def spf_ips(domain: str) -> list[str]:
    ips = []
    for record in _dig("TXT", domain):
        if "v=spf1" in record:
            for token in record.split():
                if token.startswith("ip4:"):
                    ips.append(token[4:].split("/")[0])
    return ips


def crtsh_subdomains(domain: str) -> set[str]:
    subs: set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "python-loadtest/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            for entry in json.loads(resp.read()):
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") and name != domain:
                        subs.add(name)
    except (urllib.error.URLError, json.JSONDecodeError, Exception):
        print("    (crt.sh unreachable — skipping CT log step)")
    return subs


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/find_origin.py <domain>")
        sys.exit(1)

    raw = sys.argv[1].lower()
    for prefix in ("https://", "http://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    domain = raw.split("/")[0]

    print(f"\n  Target : {domain}")
    print(f"  Method : passive OSINT only (no active scanning)\n")

    candidates: dict[str, list[str]] = {}

    def check(ip: str | None, label: str) -> None:
        if not ip:
            return
        cf = is_cloudflare(ip)
        tag = " (Cloudflare — proxied)" if cf else "  ← CANDIDATE"
        print(f"    {ip:<20} {tag}  [{label}]")
        if not cf:
            candidates.setdefault(ip, []).append(label)

    # ── 1. Direct A record ────────────────────────────────────────────────────
    print("[1] Direct A record")
    check(resolve(domain), f"A {domain}")
    check(resolve(f"www.{domain}"), f"A www.{domain}")

    # ── 2. MX records ─────────────────────────────────────────────────────────
    print("\n[2] MX records (mail servers often share the origin host)")
    rows = mx_ips(domain)
    if rows:
        for host, ip in rows:
            check(ip, f"MX {host}")
    else:
        print("    (none found)")

    # ── 3. SPF record ─────────────────────────────────────────────────────────
    print("\n[3] SPF TXT record (sending IP = often the web server)")
    ips = spf_ips(domain)
    if ips:
        for ip in ips:
            check(ip, "SPF ip4")
    else:
        print("    (no ip4: tokens found)")

    # ── 4. Common subdomains ─────────────────────────────────────────────────
    print("\n[4] Common subdomains (staging, dev, cpanel, etc.)")
    for sub in _COMMON_SUBS:
        ip = resolve(f"{sub}.{domain}")
        if ip:
            check(ip, f"subdomain {sub}.{domain}")

    # ── 5. Certificate transparency ──────────────────────────────────────────
    print("\n[5] Certificate transparency logs via crt.sh (all-time subdomains)")
    ct_subs = crtsh_subdomains(domain)
    print(f"    Found {len(ct_subs)} historical subdomains")
    for sub in sorted(ct_subs):
        ip = resolve(sub)
        if ip:
            check(ip, f"CT subdomain {sub}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═' * 60}")
    if candidates:
        print("CANDIDATE ORIGIN IPs (not behind Cloudflare):\n")
        for ip, sources in candidates.items():
            print(f"  {ip}")
            for s in sources:
                print(f"    via {s}")
        first_ip = next(iter(candidates))
        print(f"""
Add to config.yaml to bypass the CDN:

  origin_url: "http://{first_ip}"
  host_header: "{domain}"
  tls_verify: false
""")
    else:
        print("No non-Cloudflare IPs found via passive methods.\n")
        print("Next steps (require free account):")
        print(f"  Shodan  : https://www.shodan.io/search?query=hostname%3A{domain}")
        print(f"  Censys  : https://search.censys.io/search?q={domain}")
        print( "  Both search real SSL certs indexed from live scans of the entire internet.")
        print( "  Look for an IP whose HTTPS cert contains your domain — that's the origin.\n")


if __name__ == "__main__":
    main()
