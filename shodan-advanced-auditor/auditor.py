#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Shodan Multi-Target Security Auditor (CLI)
Usage examples:
  python auditor.py -t 8.8.8.8
  python auditor.py -t example.com -t 1.2.3.4
  python auditor.py -f targets.txt
Output:
  - Terminal: ringkasan tabel
  - File: shodan_audit.json (default) containing list of audit objects
"""

import os
import sys
import json
import argparse
import socket
import ipaddress
from datetime import datetime

# third-party
try:
    import shodan
except Exception:
    raise SystemExit("Module 'shodan' not found. Install with: pip install shodan")

try:
    from tabulate import tabulate
    _HAS_TABULATE = True
except Exception:
    _HAS_TABULATE = False

# Risky/common vulnerable ports (modifiable)
RISKY_PORTS = {21, 22, 23, 139, 445, 3389}  # FTP, SSH, Telnet, SMB, RDP, etc.

# Banner keywords to label services (lowercase)
BANNER_KEYWORDS = {
    'ftp': 'FTP',
    'ssh': 'SSH',
    'rdp': 'RDP',
    'ms-sql': 'MSSQL',
    'smtp': 'SMTP',
    'http': 'HTTP',
    'https': 'HTTPS',
    'telnet': 'Telnet',
    'smb': 'SMB',
    'vnc': 'VNC',
    'mysql': 'MySQL',
    'postgres': 'PostgreSQL',
    'rdp': 'RDP',
    'nginx': 'nginx',
    'apache': 'Apache'
}

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def resolve(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def collect_host(api: shodan.Shodan, ip: str):
    """Call api.host and return dict or exception info."""
    try:
        return api.host(ip)
    except shodan.APIError as e:
        return {"_error": str(e)}
    except Exception as e:
        return {"_error": repr(e)}

def search_hostname(api: shodan.Shodan, hostname: str, limit=5):
    """Fallback: use api.search('hostname:\"...\"')"""
    q = f'hostname:"{hostname}"'
    try:
        return api.search(q, limit=limit)
    except shodan.APIError as e:
        return {"_error": str(e)}
    except Exception as e:
        return {"_error": repr(e)}

def analyze_services_from_host(host_data: dict):
    """Given host() result, extract services list, ports, location, OS"""
    if not isinstance(host_data, dict):
        return {"error": "invalid_host_data"}
    if "_error" in host_data:
        return {"error": host_data["_error"]}
    services = []
    ports = set()
    for d in host_data.get("data", []):
        p = d.get("port")
        if p:
            ports.add(int(p))
        services.append({
            "port": d.get("port"),
            "banner": d.get("data"),
            "product": d.get("product"),
            "timestamp": d.get("timestamp")
        })
    meta = host_data.get("os") if host_data.get("os") else None
    location = {
        "country": host_data.get("country_name"),
        "city": host_data.get("city"),
        "latitude": host_data.get("latitude"),
        "longitude": host_data.get("longitude")
    } if any(host_data.get(k) for k in ("country_name","city","latitude","longitude")) else {}
    return {
        "services": services,
        "ports": sorted(list(ports)),
        "os": meta,
        "location": location
    }

def label_banners(services: list):
    """Add labels based on banner keywords."""
    labeled = []
    for s in services:
        banner = (s.get("banner") or "") 
        banner_lower = banner.lower()
        labels = set()
        for kw, label in BANNER_KEYWORDS.items():
            if kw in banner_lower:
                labels.add(label)
        labeled.append({
            "port": s.get("port"),
            "banner": banner,
            "labels": sorted(list(labels))
        })
    return labeled

def audit_target(api: shodan.Shodan, target: str, hostname_search_limit=5):
    """Perform audit for a single target (IP or domain). Returns dict"""
    entry = {
        "target": target,
        "queried_at": datetime.utcnow().isoformat() + "Z",
        "resolved_ip": None,
        "os": None,
        "location": {},
        "open_ports": [],
        "risky_ports": [],
        "banners": [],
        "notes": []
    }

    # determine IP vs domain
    if is_ip(target):
        ip = target
    else:
        ip = resolve(target)
        entry["resolved_ip"] = ip

    if not ip:
        # If cannot resolve, try hostname search
        hs = search_hostname(api, target, limit=hostname_search_limit)
        if isinstance(hs, dict) and hs.get("_error"):
            entry["notes"].append(f"hostname_search_error: {hs.get('_error')}")
            return entry
        # collect matches
        matches = hs.get("matches", []) if isinstance(hs, dict) else []
        ports = set()
        services = []
        for m in matches:
            p = m.get("port")
            if p:
                ports.add(int(p))
            services.append({
                "port": m.get("port"),
                "banner": m.get("data")
            })
            # fill location from first match if available
            if not entry["location"]:
                loc = m.get("location", {})
                if loc:
                    entry["location"] = {
                        "country": loc.get("country_name"),
                        "city": loc.get("city"),
                        "latitude": loc.get("latitude"),
                        "longitude": loc.get("longitude")
                    }
        entry["open_ports"] = sorted(list(ports))
        entry["banners"] = label_banners(services)
        entry["risky_ports"] = sorted([p for p in entry["open_ports"] if p in RISKY_PORTS])
        return entry

    # call host endpoint
    host_raw = collect_host(api, ip)
    if isinstance(host_raw, dict) and host_raw.get("_error"):
        entry["notes"].append(f"host_error: {host_raw.get('_error')}")
        # attempt hostname search as fallback (if target is not an IP)
        if not is_ip(target):
            hs = search_hostname(api, target, limit=hostname_search_limit)
            if isinstance(hs, dict) and hs.get("_error"):
                entry["notes"].append(f"hostname_search_error: {hs.get('_error')}")
                return entry
            matches = hs.get("matches", [])
            ports = set()
            services = []
            for m in matches:
                if m.get("port"):
                    ports.add(int(m.get("port")))
                services.append({"port": m.get("port"), "banner": m.get("data")})
                if not entry["location"]:
                    loc = m.get("location", {})
                    if loc:
                        entry["location"] = {
                            "country": loc.get("country_name"),
                            "city": loc.get("city"),
                            "latitude": loc.get("latitude"),
                            "longitude": loc.get("longitude")
                        }
            entry["open_ports"] = sorted(list(ports))
            entry["banners"] = label_banners(services)
            entry["risky_ports"] = sorted([p for p in entry["open_ports"] if p in RISKY_PORTS])
            return entry
        else:
            return entry

    # if host_raw is successful, analyze
    analyzed = analyze_services_from_host(host_raw)
    if analyzed.get("error"):
        entry["notes"].append(f"analyze_error: {analyzed.get('error')}")
        return entry

    entry["os"] = analyzed.get("os")
    entry["location"] = analyzed.get("location") or {}
    entry["open_ports"] = analyzed.get("ports") or []
    entry["risky_ports"] = sorted([p for p in entry["open_ports"] if p in RISKY_PORTS])
    entry["banners"] = label_banners(analyzed.get("services") or [])
    return entry

def print_table(audits: list):
    rows = []
    for a in audits:
        target = a.get("target")
        os_ = a.get("os") or "-"
        ports = ",".join(map(str, a.get("open_ports") or [])) or "-"
        risky = ",".join(map(str, a.get("risky_ports") or [])) or "-"
        loc = a.get("location") or {}
        loc_str = ", ".join([v for v in (loc.get("country"), loc.get("city")) if v]) or "-"
        rows.append([target, os_, ports, risky, loc_str])
    headers = ["Target", "OS", "Open Ports", "Risk Ports", "Location"]
    if _HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        # fallback simple print
        print("\t".join(headers))
        for r in rows:
            print("\t".join(r))

def load_targets_from_file(path: str):
    t = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    t.append(s)
    except Exception as e:
        raise SystemExit(f"Failed reading target file: {e}")
    return t

def main():
    parser = argparse.ArgumentParser(description="Shodan Multi-Target Security Auditor")
    parser.add_argument("-t", "--target", action="append", help="target IP or domain (can be used multiple times)")
    parser.add_argument("-f", "--file", help="text file with targets (one per line)")
    parser.add_argument("-k", "--api-key", help="Shodan API key (optional; env SHODAN_API_KEY used if not provided)")
    parser.add_argument("-o", "--out", default="shodan_audit.json", help="output JSON file (default shodan_audit.json)")
    parser.add_argument("-l", "--limit", type=int, default=5, help="hostname search limit (fallback) default=5")
    args = parser.parse_args()

    targets = []
    if args.target:
        targets.extend(args.target)
    if args.file:
        targets.extend(load_targets_from_file(args.file))
    # dedupe while preserving order
    seen = set()
    uniq_targets = []
    for it in targets:
        if it not in seen:
            seen.add(it)
            uniq_targets.append(it)
    if not uniq_targets:
        parser.print_help()
        sys.exit(1)

    api_key = args.api_key or os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise SystemExit("Shodan API key not provided. Set SHODAN_API_KEY env var or use -k.")

    api = shodan.Shodan(api_key)

    audits = []
    for tgt in uniq_targets:
        print(f"[+] Auditing: {tgt}")
        try:
            a = audit_target(api, tgt, hostname_search_limit=args.limit)
        except Exception as e:
            a = {
                "target": tgt,
                "queried_at": datetime.utcnow().isoformat() + "Z",
                "notes": [f"unexpected_error: {repr(e)}"]
            }
        audits.append(a)

    # write JSON
    out = {"generated_at": datetime.utcnow().isoformat() + "Z", "audits": audits}
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)
        print(f"[+] Written results to: {args.out}")
    except Exception as e:
        print("Failed to write output:", e)
        sys.exit(1)

    # print table summary
    print("\nSummary:")
    print_table(audits)

if __name__ == "__main__":
    main()
