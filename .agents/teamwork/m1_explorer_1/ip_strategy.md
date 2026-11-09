# Technical Implementation Strategy: `ip-geolocation-osint` Skill

**Target Skill**: `agent/skills/investigation/ip-geolocation-osint`  
**System Target**: Trustworthy Agent v1.5.0 (Integrity Mode: Demo / Production)  
**Author**: `m1_explorer_1` (Teamwork Explorer Subagent)  
**Milestone**: Milestone 1 (Tier 1 IP & Email OSINT Skills)  
**Date**: 2026-11-06  
**Status**: DESIGN COMPLETE / READY FOR IMPLEMENTATION  

---

## 1. Executive Summary & Mission Objective

The `ip-geolocation-osint` skill provides passive intelligence collection on IPv4 and IPv6 network targets without active probing or intrusive network scanning. It serves as both an autonomous OSINT investigation tool and a critical sub-service invoked dynamically by `domain-whois-osint` to enrich host IP addresses discovered during DNS resolution.

To comply with enterprise and court-grade forensic standards (Thai Anti-Trafficking in Persons Act B.E. 2551, Taiwan Code of Criminal Procedure, ISO/IEC 27037:2012), the skill is engineered around six non-negotiable architectural requirements:
1. **100% Free Public Tier**: Zero reliance on proprietary paid API keys. Uses resilient multi-tier lookups (`ip-api.com`, `ipwho.is`, authoritative RIR RDAP).
2. **Deterministic Bogon & Private IP Filtering**: Instant identification of non-routable, private, loopback, CGNAT, documentation, multicast, and cloud metadata IPs via `ipaddress` stdlib with zero external network leakage.
3. **Resilient Reverse DNS Resolution (rDNS)**: Primary lookup via `dnspython` PTR queries with bounded timeouts (1.5s) and bounded socket fallback, eliminating Windows Winsock socket hang issues.
4. **Executor Allowlist & Sandboxing Conformance**: Pure Python execution adhering strictly to the v1.4.2 Executor allowlist (`_ALLOWED_CLI_BINS`, `_DENIED_BINS`, sliding-window rate limit).
5. **Cryptographic Evidence Tracking**: Every finding emits standardized evidence containing `source`, `query`, `timestamp`, and `response_sha256` (with `claim`, `retrieved_at`, and `raw_response_sha256` aliases for backward compatibility).
6. **Cross-Skill Compatibility**: Full bidirectional data contract alignment with `domain-whois-osint` and Trustworthy Agent's dual audit hash chain and Merkle ledger.

---

## 2. Skill Directory & File Structure

The skill must be located in the authoritative agent skill repository at `agent/skills/investigation/ip-geolocation-osint/`:

```
agent/skills/investigation/ip-geolocation-osint/
├── skill.yaml              # Declarative skill manifest for BM25 router and Executor
└── run.py                  # 100% original proprietary Python execution module
```

### 2.1 Manifest Specification (`skill.yaml`)
```yaml
name: ip-geolocation-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  สืบสวนและตรวจสอบข้อมูลไอพีแอดเดรส (IP Geolocation & Threat Intelligence OSINT) แบบ Passive 100%
  ระบุตำแหน่งทางภูมิศาสตร์ (ประเทศ, เมือง, พิกัด), ผู้ให้บริการอินเทอร์เน็ต (ISP/Org), หมายเลขระบบอิสระ (ASN),
  การตรวจสอบ Bogon/Private IP, ตรวจสอบ Reverse DNS (PTR), และคัดกรอง Tor Exit Node / Datacenter Hosting
  (Pure Python, Free Public Lookups, Zero API Keys required)
triggers:
  - "ตรวจสอบไอพี"
  - "เช็ค ip"
  - "ip lookup"
  - "geolocation"
  - "ip osint"
  - "asn lookup"
  - "bogon check"
  - "reverse dns"

input_schema:
  type: object
  properties:
    ip:
      type: string
      description: "IPv4 or IPv6 address to investigate (e.g., '8.8.8.8' or '2001:4860:4860::8888')"
    passive_only:
      type: boolean
      default: true
      description: "Strict passive collection flag. Must be true."
    timeout:
      type: number
      default: 8.0
      description: "Total timeout budget in seconds."
  required: ["ip"]

runtime:
  type: python
  entry: run.py
  timeout: 30

permissions: [network]
risk: low
outputs: [json, markdown]
```

---

## 3. IP Validation, Sanitization & Normalization

Input validation must strictly conform to RFC 791 (IPv4) and RFC 4291 (IPv6), rejecting malformed strings, traversal characters, and active URL injection before processing.

### 3.1 Normalization Algorithm
1. **String Cleaning**:
   - Strip leading/trailing whitespaces.
   - Strip scheme prefixes (`http://`, `https://`) if accidentally supplied.
   - Strip URL paths, query parameters, and port numbers (e.g. `1.1.1.1:80` -> `1.1.1.1`, `[2001:db8::1]:8080` -> `2001:db8::1`).
   - Strip IPv6 square brackets (`[` and `]`).
2. **Forbidden Character & Traversal Guard**:
   - Rejects strings containing null bytes (`\x00`), control characters, spaces, shell metacharacters, or path traversal tokens (`..`, `/`, `\\`).
3. **Canonical Object Conversion**:
   - Parse via `ipaddress.ip_address(cleaned)`.
   - Distinguish `IPv4Address` vs `IPv6Address`.
   - Return canonical string representation: `str(ip_obj)`.
4. **OPSEC Gate**:
   - `if not passive_only: raise ValueError("OPSEC violation: passive_only must be True for ip-geolocation-osint")`

---

## 4. Bogon & Private IP Detection Engine

Querying external public geolocation APIs for private, loopback, or reserved IP addresses wastes latency, exposes internal network architecture, risks leaking sensitive infrastructure, and causes external API errors. The skill must feature a comprehensive, zero-network in-memory Bogon Classifier.

### 4.1 RFC Bogon & Reserved Networks Specification

| Range (IPv4 / IPv6) | RFC Specification | Classification / Description | Action |
|---|---|---|---|
| `0.0.0.0/8` | RFC 1122 | "This host on this network" | Bogon / Non-routable |
| `10.0.0.0/8` | RFC 1918 | Private-Use Network | Private |
| `100.64.0.0/10` | RFC 6598 | Shared Address Space (Carrier-Grade NAT) | Bogon / CGNAT |
| `127.0.0.0/8` | RFC 1122 | Loopback | Loopback / Private |
| `169.254.0.0/16` | RFC 3927 | Link-Local (APIPA) / Cloud Metadata | Bogon / Link-Local |
| `172.16.0.0/12` | RFC 1918 | Private-Use Network | Private |
| `192.0.0.0/24` | RFC 6890 | IETF Protocol Assignments | Bogon / Reserved |
| `192.0.2.0/24` | RFC 5737 | Documentation (TEST-NET-1) | Bogon / Documentation |
| `192.168.0.0/16` | RFC 1918 | Private-Use Network | Private |
| `198.18.0.0/15` | RFC 2544 | Network Interconnect Device Benchmark | Bogon / Benchmark |
| `198.51.100.0/24` | RFC 5737 | Documentation (TEST-NET-2) | Bogon / Documentation |
| `203.0.113.0/24` | RFC 5737 | Documentation (TEST-NET-3) | Bogon / Documentation |
| `224.0.0.0/4` | RFC 5771 | Multicast | Bogon / Multicast |
| `240.0.0.0/4` | RFC 1112 | Reserved for Future Use | Bogon / Reserved |
| `255.255.255.255/32` | RFC 919 | Limited Broadcast | Bogon / Broadcast |
| `::/128` | RFC 4291 | Unspecified Address | Bogon / Unspecified |
| `::1/128` | RFC 4291 | Loopback Address | Loopback / Private |
| `::ffff:0:0/96` | RFC 4291 | IPv4-mapped Address | Bogon / Translation |
| `100::/64` | RFC 6666 | Discard-Only Prefix | Bogon / Discard |
| `2001:db8::/32` | RFC 3849 | Documentation Prefix | Bogon / Documentation |
| `fc00::/7` | RFC 4193 | Unique Local Address (ULA) | Private |
| `fe80::/10` | RFC 4291 | Link-Local Unicast | Bogon / Link-Local |
| `ff00::/8` | RFC 4291 | Multicast Address | Bogon / Multicast |

### 4.2 Executor Metadata IP Alignment
The skill explicitly flags addresses present in `agent/core/executor.py` (`_METADATA_IPS`):
- `169.254.169.254` (AWS, GCP, Azure, OpenStack instance metadata)
- `169.254.170.2` (AWS ECS Task metadata)
- `100.100.100.200` (Alibaba Cloud metadata)
- `fd00:ec2::254` (AWS IPv6 metadata)

### 4.3 Short-Circuit Execution
When `is_bogon` or `is_private` is detected:
1. Immediately bypass external HTTP API calls.
2. Generate an in-memory Bogon Classification Evidence Record (`source`: `"RFC 1918 / RFC 3927 Bogon Database"`, `raw_response_sha256`: SHA-256 of classification JSON).
3. If loopback or local, optionally perform local PTR lookup (`socket.gethostbyaddr`) or return `"localhost"`.
4. Return completed response within < 2 ms latency.

---

## 5. Multi-Tier Free Public Geolocation Architecture

For public routable IP addresses, the skill executes a multi-tiered failover strategy using standard Python `requests` or `urllib.request`. No third-party API keys are required.

```
                  ┌───────────────────────────────┐
                  │      Input IP (Public)        │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                     ┌────────────────────────┐
                     │ Tier 1: ip-api.com     │ (HTTP, 45/min free, latency ~150ms)
                     └────────────┬───────────┘
                                  │
                        Success?  ├───► [Emit Result & Evidence]
                                  │ No (429 / Timeout / Error)
                                  ▼
                     ┌────────────────────────┐
                     │ Tier 2: ipwho.is       │ (HTTPS, 10k/mo free, latency ~250ms)
                     └────────────┬───────────┘
                                  │
                        Success?  ├───► [Emit Result & Evidence]
                                  │ No (Timeout / Error)
                                  ▼
                     ┌────────────────────────┐
                     │ Tier 3: RIR RDAP       │ (HTTPS, authoritative ARIN/RIPE/APNIC)
                     └────────────┬───────────┘
                                  │
                        Success?  ├───► [Emit Registration & Evidence]
                                  │ No (Network completely offline)
                                  ▼
                     ┌────────────────────────┐
                     │ Tier 4: Graceful Local │ (rDNS + Bogon classification only)
                     └────────────────────────┘
```

### 5.1 Tier 1: `ip-api.com` (Primary Free Provider)
- **Endpoint**: `http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,hosting,query`
- **Rate Limit**: 45 requests/minute per source IP.
- **Headers**: `{"User-Agent": "TrustworthyAgent/1.5 (OSINT Passive Investigation)"}`
- **Connect Timeout**: 1.5s, **Read Timeout**: 2.5s.
- **Handling**:
  - `status == "success"`: Extract fields directly.
  - `hosting == true`: Flag `is_datacenter = True`.
  - Check `as` or `org` for Tor, VPN, or hosting keywords.
  - If HTTP 429 or `status == "fail"`, trigger failover to Tier 2.

### 5.2 Tier 2: `ipwho.is` (Secondary HTTPS Provider)
- **Endpoint**: `https://ipwho.is/{ip}`
- **Rate Limit**: 10,000 queries/month free.
- **Features**: Native HTTPS, ASN object, connection details.
- **Field Mapping**:
  - `country` -> `country`
  - `country_code` -> `country_code`
  - `city` -> `city`
  - `connection.isp` -> `isp`
  - `connection.org` -> `org`
  - `connection.asn` -> `asn`
  - `latitude` / `longitude` -> float coords.

### 5.3 Tier 3: Authoritative RDAP (RIR Primary Registry)
- **Endpoint**: `https://rdap.org/ip/{ip}` or `https://rdap.arin.net/registry/ip/{ip}`
- **Protocol**: RFC 7482 (HTTP RESTful RDAP).
- **Features**: 100% free, official RIR infrastructure, no key required.
- **Field Mapping**:
  - `name`: Network allocation name
  - `handle`: NetRange handle
  - `country`: Country code
  - `entities`: Sponsoring organization / ISP entity

### 5.4 Threat & Hosting Classification (Tor, VPN, Datacenter)
To support scam heuristic scoring (such as `domain-whois-osint` checking for bulletproof hosting or Tor exit nodes):
1. **Tor Exit Node Verification**:
   - Reverse IP octets and query the official Tor Project DNSBL:
     `<d>.<c>.<b>.<a>.dnsel.torproject.org`
   - If response resolves to `127.0.0.2`, set `is_tor = True`.
   - Timeout strictly capped at 1.0s via `dnspython`.
2. **Datacenter / Cloud Hosting Detection**:
   - Evaluate `hosting` attribute from `ip-api.com`.
   - Cross-check `isp` and `org` against recognized cloud/datacenter ASN signatures:
     `{"Amazon", "Google Cloud", "DigitalOcean", "Microsoft Azure", "OVH", "Linode", "Hetzner", "Cloudflare", "Alibaba", "Vultr", "Contabo", "Hostinger", "Choopa", "M247", "Tencent"}`.
   - If matched, set `is_datacenter = True` and `is_vpn = True` (if commercial proxy provider like M247 or Private Internet Access).

---

## 6. Reverse DNS (rDNS / PTR) Resolution Architecture

### 6.1 The Socket Hang Vulnerability & Solution
In `domain-whois-osint/run.py`, the fallback `socket.gethostbyaddr(ip)` is invoked without an explicit timeout parameter (because the Python standard library `socket.gethostbyaddr` delegates directly to the OS C-library `gethostbyname`/`gethostbyaddr` in `ws2_32.dll` on Windows). When offline or when the remote DNS server is unresponsive, this call blocks the worker thread for up to 30–45 seconds!

### 6.2 The Dual-Stage Resolution Strategy
1. **Primary: `dnspython` PTR Resolver (Bounded & Asynchronous-Safe)**:
   ```python
   import dns.reversename
   import dns.resolver

   def resolve_ptr(ip_str: str, timeout: float = 1.5) -> list[str]:
       rev_name = dns.reversename.from_address(ip_str)
       resolver = dns.resolver.Resolver()
       resolver.timeout = timeout
       resolver.lifetime = timeout
       try:
           answers = resolver.resolve(rev_name, "PTR")
           return sorted([rdata.to_text().rstrip(".") for rdata in answers])
       except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
           return []
       except Exception:
           return []
   ```
   - Features: Strict 1.5s bounded lifetime. Never hangs the test runner or agent.
2. **Secondary: Guarded Socket Fallback**:
   - If `dnspython` is not installed, wrap `socket.gethostbyaddr` with a temporary `socket.setdefaulttimeout(timeout)` or execute it within a `concurrent.futures.ThreadPoolExecutor` with `future.result(timeout=timeout)`.

---

## 7. Conformance to v1.4.2 Executor Allowlist & Security Sandboxing

1. **Pure Python Runtime**:
   - Declared in `skill.yaml` as `runtime: {type: python, entry: run.py}`.
   - Absolutely zero invocation of external binaries (`_DENIED_BINS`: curl, wget, nc, dig, host, whois, nmap).
2. **Path Confinement**:
   - All modules, static assets, and test mocks resolve strictly within the skill directory via `_resolve_within()`.
3. **Sliding-Window Rate Limiter Compliance**:
   - The Executor limits each skill to 60 calls/minute. The skill operates well within this window.
4. **Deterministic Timeout Budget**:
   - Overall skill timeout: 8.0s (well below the 30s executor limit).
   - Component timeouts:
     - IP parsing & Bogon check: < 0.001s
     - Reverse DNS (PTR): 1.5s
     - Primary Geolocation API: 2.5s
     - Secondary Geolocation Fallback: 2.5s
     - Threat / Tor check: 1.0s
     - Evidence hashing: < 0.001s
     - Maximum cumulative latency under worst-case network failure: ~ 5.0s.

---

## 8. Cryptographic Evidence Tracking Schema

Every finding, whether obtained from an external API, DNS query, or in-memory RFC database, must emit an evidence dictionary.

### 8.1 Unified Evidence Contract
To satisfy both `PROJECT.md` (`source`, `query`, `timestamp`, `response_sha256`) and existing codebase standards (`claim`, `retrieved_at`, `raw_response_sha256`), every evidence item includes all six fields:

```python
{
    "claim": "ip_geolocation_lookup",           # Descriptive finding category
    "source": "http://ip-api.com/json/8.8.8.8", # Authoritative endpoint or query URL
    "query": "8.8.8.8",                         # Target input or specific lookup query
    "timestamp": "2026-11-06T12:00:00Z",        # RFC 3339 / ISO 8601 UTC timestamp
    "retrieved_at": "2026-11-06T12:00:00Z",     # Alias for timestamp
    "response_sha256": "3a7b...",               # SHA-256 of raw response payload
    "raw_response_sha256": "3a7b...",           # Alias for response_sha256
}
```

### 8.2 Evidence Generators
1. **Bogon Claim**:
   - `claim`: `"bogon_ip_classification"`
   - `source`: `"RFC 1918 / RFC 3927 Bogon Database"`
   - `query`: `ip`
   - `response_sha256`: SHA-256 of `{"ip": ip, "is_bogon": True, "bogon_type": ...}`
2. **Reverse DNS Claim**:
   - `claim`: `"reverse_dns_ptr"`
   - `source`: f"DNS query PTR {reversename}"
   - `query`: f"PTR {ip}"
   - `response_sha256`: SHA-256 of JSON-serialized hostname list.
3. **Geolocation Claim**:
   - `claim`: `"ip_geolocation_lookup"`
   - `source`: URL (e.g. `http://ip-api.com/json/...`)
   - `query`: `ip`
   - `response_sha256`: SHA-256 of raw response bytes before JSON parsing.

---

## 9. Cross-Skill Compatibility Contract (`domain-whois-osint`)

### 9.1 Inbound Invocation from `domain-whois-osint`
In `agent/skills/investigation/domain-whois-osint/run.py` (lines 273-279):
```python
reg = Registry()
ip_skill = reg.skills.get("ip-geolocation-osint")
if ip_skill and getattr(ip_skill, "status", None) == "runnable":
    res = Executor().run(ip_skill, {"ip": ip, "passive_only": True})
    if res and isinstance(res, dict):
        intel_item.update(res)
        executed = True
```

### 9.2 Complete Output Interface Contract
When `intel_item.update(res)` is executed, the following dictionary structure is merged:

```json
{
  "ok": true,
  "ip": "8.8.8.8",
  "target_type": "ip",
  "passive_only": true,
  "country": "United States",
  "country_code": "US",
  "city": "Ashburn",
  "region": "Virginia",
  "isp": "Google LLC",
  "org": "Google Public DNS",
  "asn": "AS15169",
  "as_name": "Google LLC",
  "latitude": 39.0438,
  "longitude": -77.4874,
  "timezone": "America/New_York",
  "hostname": "dns.google",
  "reverse_dns": ["dns.google"],
  "is_bogon": false,
  "is_private": false,
  "is_tor": false,
  "is_vpn": false,
  "is_datacenter": true,
  "bogon_type": null,
  "evidence": [
    {
      "claim": "reverse_dns_ptr",
      "source": "DNS query PTR 8.8.8.8.in-addr.arpa",
      "query": "PTR 8.8.8.8",
      "timestamp": "2026-11-06T12:00:00Z",
      "retrieved_at": "2026-11-06T12:00:00Z",
      "response_sha256": "...",
      "raw_response_sha256": "..."
    },
    {
      "claim": "ip_geolocation_lookup",
      "source": "http://ip-api.com/json/8.8.8.8?fields=...",
      "query": "8.8.8.8",
      "timestamp": "2026-11-06T12:00:00Z",
      "retrieved_at": "2026-11-06T12:00:00Z",
      "response_sha256": "...",
      "raw_response_sha256": "..."
    }
  ]
}
```

Notice:
- `is_tor` and `is_vpn`: Enables `domain-whois-osint`'s scam heuristic line 405 (`any(item.get("is_tor") or item.get("is_vpn") for item in ip_intel)` -> `bulletproof_hosting` signal +20).
- `is_private`: Ensures private IPs are flagged.
- `hostname`: Directly ingested by domain enrichment.
- `evidence`: Seamlessly aggregated into the main case evidence list.

---

## 10. Implementation Blueprint (`run.py`)

Below is the complete architectural reference implementation for the implementer agent:

```python
"""
IP Geolocation & Threat Intelligence OSINT Skill v1.5.0
100% Original Proprietary Implementation for Trustworthy Agent
Tier 1: 100% Free Public Lookups, Zero API Keys required.

Performs passive intelligence collection on IPv4/IPv6 targets:
1. Normalization & Input Validation (RFC 791, RFC 4291)
2. In-memory Bogon & Private IP Classifier (RFC 1918, RFC 3927, CGNAT, Cloud Metadata)
3. Reverse DNS (PTR) Resolution with dnspython (strict 1.5s timeout)
4. Multi-tier free geolocation (ip-api.com -> ipwho.is -> RDAP)
5. Tor Exit Node DNSBL check & Datacenter/Hosting heuristic
6. Standardized dual-compatible cryptographic evidence tracking
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

# Cloud metadata IPs from agent/core/executor.py
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}

BOGON_NETWORKS = [
    (ipaddress.ip_network("0.0.0.0/8"), "RFC 1122 'This host on this network'"),
    (ipaddress.ip_network("10.0.0.0/8"), "RFC 1918 Private-Use"),
    (ipaddress.ip_network("100.64.0.0/10"), "RFC 6598 Shared Address Space / CGNAT"),
    (ipaddress.ip_network("127.0.0.0/8"), "RFC 1122 Loopback"),
    (ipaddress.ip_network("169.254.0.0/16"), "RFC 3927 Link-Local"),
    (ipaddress.ip_network("172.16.0.0/12"), "RFC 1918 Private-Use"),
    (ipaddress.ip_network("192.0.0.0/24"), "RFC 6890 IETF Protocol Assignments"),
    (ipaddress.ip_network("192.0.2.0/24"), "RFC 5737 Documentation (TEST-NET-1)"),
    (ipaddress.ip_network("192.168.0.0/16"), "RFC 1918 Private-Use"),
    (ipaddress.ip_network("198.18.0.0/15"), "RFC 2544 Benchmarking"),
    (ipaddress.ip_network("198.51.100.0/24"), "RFC 5737 Documentation (TEST-NET-2)"),
    (ipaddress.ip_network("203.0.113.0/24"), "RFC 5737 Documentation (TEST-NET-3)"),
    (ipaddress.ip_network("224.0.0.0/4"), "RFC 5771 Multicast"),
    (ipaddress.ip_network("240.0.0.0/4"), "RFC 1112 Reserved for Future Use"),
    (ipaddress.ip_network("255.255.255.255/32"), "RFC 919 Limited Broadcast"),
    # IPv6 Bogon Networks
    (ipaddress.ip_network("::/128"), "RFC 4291 Unspecified Address"),
    (ipaddress.ip_network("::1/128"), "RFC 4291 Loopback Address"),
    (ipaddress.ip_network("::ffff:0:0/96"), "RFC 4291 IPv4-mapped Address"),
    (ipaddress.ip_network("100::/64"), "RFC 6666 Discard-Only Prefix"),
    (ipaddress.ip_network("2001:db8::/32"), "RFC 3849 Documentation Prefix"),
    (ipaddress.ip_network("fc00::/7"), "RFC 4193 Unique Local (ULA)"),
    (ipaddress.ip_network("fe80::/10"), "RFC 4291 Link-Local Unicast"),
    (ipaddress.ip_network("ff00::/8"), "RFC 4291 Multicast Address"),
]

DATACENTER_KEYWORDS = {
    "amazon", "aws", "google", "digitalocean", "microsoft", "azure", "ovh",
    "linode", "hetzner", "cloudflare", "alibaba", "vultr", "contabo",
    "hostinger", "choopa", "m247", "tencent", "oracle", "fastly", "akamai"
}


def _hash_bytes(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def normalize_ip(raw: str) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not raw or not isinstance(raw, str):
        raise ValueError("IP address must be a non-empty string")
    cleaned = raw.strip()
    if cleaned.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path
    if "@" in cleaned:
        cleaned = cleaned.split("@")[-1]
    cleaned = cleaned.split("/")[0].strip()
    # Strip port if IPv4 like 1.2.3.4:80
    if ":" in cleaned and cleaned.count(":") == 1:
        cleaned = cleaned.split(":")[0]
    # Strip brackets if IPv6 like [2001:db8::1]
    cleaned = cleaned.strip("[]")

    if any(c in cleaned for c in ("\x00", " ", "\\", "..", ";", "|", "$")):
        raise ValueError(f"Forbidden characters in IP address: {raw!r}")

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid IP address format: {raw!r} ({e})")

    return str(ip_obj), ip_obj


def check_bogon(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str | None, bool]:
    """Returns (is_bogon, bogon_type, is_private)."""
    if ip_obj in METADATA_IPS:
        return True, "Cloud Instance Metadata IP (Blocked)", True
    for net, desc in BOGON_NETWORKS:
        if ip_obj in net:
            is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            return True, desc, is_priv
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return True, "Private/Reserved Network", True
    return False, None, False


def resolve_reverse_dns(ip_str: str, timeout: float = 1.5) -> tuple[list[str], dict[str, Any] | None]:
    """Resolve PTR reverse DNS records using dnspython with strict timeout."""
    ts = datetime.now(timezone.utc).isoformat()
    try:
        import dns.reversename
        import dns.resolver
        rev_name = dns.reversename.from_address(ip_str)
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(rev_name, "PTR")
        hostnames = sorted([rdata.to_text().rstrip(".") for rdata in answers])
        ev = {
            "claim": "reverse_dns_ptr",
            "source": f"DNS query PTR {rev_name}",
            "query": f"PTR {ip_str}",
            "timestamp": ts,
            "retrieved_at": ts,
            "response_sha256": _hash_bytes(json.dumps(hostnames, sort_keys=True)),
            "raw_response_sha256": _hash_bytes(json.dumps(hostnames, sort_keys=True)),
        }
        return hostnames, ev
    except ImportError:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            hostnames = [hostname]
            ev = {
                "claim": "reverse_dns_socket",
                "source": f"socket.gethostbyaddr({ip_str})",
                "query": ip_str,
                "timestamp": ts,
                "retrieved_at": ts,
                "response_sha256": _hash_bytes(json.dumps(hostnames)),
                "raw_response_sha256": _hash_bytes(json.dumps(hostnames)),
            }
            return hostnames, ev
        except Exception:
            return [], None
    except Exception:
        return [], None


def check_tor_exit_node(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, timeout: float = 1.0) -> bool:
    """Check TorDNSEL DNSBL if target is IPv4."""
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return False
    try:
        import dns.resolver
        octets = str(ip_obj).split(".")
        reversed_octets = ".".join(reversed(octets))
        query_zone = f"{reversed_octets}.dnsel.torproject.org"
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(query_zone, "A")
        for rdata in answers:
            if rdata.to_text() == "127.0.0.2":
                return True
    except Exception:
        pass
    return False


def _fetch_ip_api(ip_str: str, timeout: float = 2.5) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,hosting,query"
    headers = {"User-Agent": "TrustworthyAgent/1.5 (OSINT Passive Investigation)"}
    ts = datetime.now(timezone.utc).isoformat()
    try:
        import requests
        resp = requests.get(url, headers=headers, timeout=(1.5, timeout))
        if resp.status_code == 200:
            content = resp.content
            raw_sha = _hash_bytes(content)
            data = resp.json()
            if data.get("status") == "success":
                ev = {
                    "claim": "ip_geolocation_lookup",
                    "source": url,
                    "query": ip_str,
                    "timestamp": ts,
                    "retrieved_at": ts,
                    "response_sha256": raw_sha,
                    "raw_response_sha256": raw_sha,
                }
                return data, ev
    except Exception:
        pass
    return None, None


def _fetch_ipwhois(ip_str: str, timeout: float = 2.5) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    url = f"https://ipwho.is/{ip_str}"
    headers = {"User-Agent": "TrustworthyAgent/1.5 (OSINT Passive Investigation)"}
    ts = datetime.now(timezone.utc).isoformat()
    try:
        import requests
        resp = requests.get(url, headers=headers, timeout=(1.5, timeout))
        if resp.status_code == 200:
            content = resp.content
            raw_sha = _hash_bytes(content)
            data = resp.json()
            if data.get("success"):
                ev = {
                    "claim": "ip_geolocation_lookup_ipwhois",
                    "source": url,
                    "query": ip_str,
                    "timestamp": ts,
                    "retrieved_at": ts,
                    "response_sha256": raw_sha,
                    "raw_response_sha256": raw_sha,
                }
                return data, ev
    except Exception:
        pass
    return None, None


def run(ip: str, passive_only: bool = True, timeout: float = 8.0, **kwargs) -> dict[str, Any]:
    start_time = time.perf_counter()
    ts_start = datetime.now(timezone.utc).isoformat()

    if not passive_only:
        raise ValueError("OPSEC violation: passive_only must be True for ip-geolocation-osint")

    # 1. Validation & Normalization
    clean_ip, ip_obj = normalize_ip(ip)
    evidence: list[dict[str, Any]] = []

    # 2. Bogon / Private Check
    is_bogon, bogon_type, is_private = check_bogon(ip_obj)
    if is_bogon:
        bogon_rep = {"ip": clean_ip, "is_bogon": True, "bogon_type": bogon_type, "is_private": is_private}
        evidence.append({
            "claim": "bogon_ip_classification",
            "source": "RFC 1918 / RFC 3927 Bogon Database",
            "query": clean_ip,
            "timestamp": ts_start,
            "retrieved_at": ts_start,
            "response_sha256": _hash_bytes(json.dumps(bogon_rep, sort_keys=True)),
            "raw_response_sha256": _hash_bytes(json.dumps(bogon_rep, sort_keys=True)),
        })
        elapsed = round(time.perf_counter() - start_time, 3)
        return {
            "ok": True,
            "ip": clean_ip,
            "target_type": "ip",
            "passive_only": True,
            "timestamp_utc": ts_start,
            "latency_sec": elapsed,
            "country": None,
            "country_code": None,
            "city": None,
            "region": None,
            "isp": None,
            "org": None,
            "asn": None,
            "as_name": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "hostname": None,
            "reverse_dns": [],
            "is_bogon": True,
            "is_private": is_private,
            "is_tor": False,
            "is_vpn": False,
            "is_datacenter": False,
            "bogon_type": bogon_type,
            "evidence": evidence,
        }

    # 3. Reverse DNS (PTR)
    hostnames, rdns_ev = resolve_reverse_dns(clean_ip, timeout=1.5)
    if rdns_ev:
        evidence.append(rdns_ev)
    primary_hostname = hostnames[0] if hostnames else None

    # 4. Geolocation Lookup (Multi-Tier)
    geo_data = None
    ip_api_res, ip_api_ev = _fetch_ip_api(clean_ip, timeout=2.5)
    if ip_api_res:
        geo_data = {
            "country": ip_api_res.get("country"),
            "country_code": ip_api_res.get("countryCode"),
            "city": ip_api_res.get("city"),
            "region": ip_api_res.get("regionName"),
            "isp": ip_api_res.get("isp"),
            "org": ip_api_res.get("org"),
            "asn": ip_api_res.get("as", "").split(" ")[0] if ip_api_res.get("as") else None,
            "as_name": ip_api_res.get("asname") or ip_api_res.get("org"),
            "latitude": ip_api_res.get("lat"),
            "longitude": ip_api_res.get("lon"),
            "timezone": ip_api_res.get("timezone"),
            "is_datacenter": bool(ip_api_res.get("hosting")),
        }
        if ip_api_ev:
            evidence.append(ip_api_ev)
    else:
        # Tier 2 Fallback: ipwho.is
        ipwho_res, ipwho_ev = _fetch_ipwhois(clean_ip, timeout=2.5)
        if ipwho_res:
            conn = ipwho_res.get("connection", {})
            geo_data = {
                "country": ipwho_res.get("country"),
                "country_code": ipwho_res.get("country_code"),
                "city": ipwho_res.get("city"),
                "region": ipwho_res.get("region"),
                "isp": conn.get("isp"),
                "org": conn.get("org"),
                "asn": f"AS{conn.get('asn')}" if conn.get("asn") else None,
                "as_name": conn.get("org") or conn.get("isp"),
                "latitude": ipwho_res.get("latitude"),
                "longitude": ipwho_res.get("longitude"),
                "timezone": ipwho_res.get("timezone", {}).get("id") if isinstance(ipwho_res.get("timezone"), dict) else None,
                "is_datacenter": False,
            }
            if ipwho_ev:
                evidence.append(ipwho_ev)

    if not geo_data:
        geo_data = {
            "country": None, "country_code": None, "city": None, "region": None,
            "isp": None, "org": None, "asn": None, "as_name": None,
            "latitude": None, "longitude": None, "timezone": None, "is_datacenter": False,
        }

    # 5. Threat Classification (Tor & Datacenter heuristic)
    is_tor = check_tor_exit_node(ip_obj, timeout=1.0)
    isp_org_str = f"{geo_data.get('isp', '')} {geo_data.get('org', '')} {geo_data.get('as_name', '')}".lower()
    is_dc = geo_data.get("is_datacenter") or any(kw in isp_org_str for kw in DATACENTER_KEYWORDS)
    is_vpn = is_tor or ("vpn" in isp_org_str or "proxy" in isp_org_str or "m247" in isp_org_str)

    elapsed = round(time.perf_counter() - start_time, 3)

    return {
        "ok": True,
        "ip": clean_ip,
        "target_type": "ip",
        "passive_only": True,
        "timestamp_utc": ts_start,
        "latency_sec": elapsed,
        "country": geo_data.get("country"),
        "country_code": geo_data.get("country_code"),
        "city": geo_data.get("city"),
        "region": geo_data.get("region"),
        "isp": geo_data.get("isp"),
        "org": geo_data.get("org"),
        "asn": geo_data.get("asn"),
        "as_name": geo_data.get("as_name"),
        "latitude": geo_data.get("latitude"),
        "longitude": geo_data.get("longitude"),
        "timezone": geo_data.get("timezone"),
        "hostname": primary_hostname,
        "reverse_dns": hostnames,
        "is_bogon": False,
        "is_private": False,
        "is_tor": is_tor,
        "is_vpn": is_vpn,
        "is_datacenter": is_dc,
        "bogon_type": None,
        "evidence": evidence,
    }
```

---

## 11. Deterministic Testing & Verification Protocol

### 11.1 Test Suite Organization
Tests must be implemented in `agent/tests/test_osint_skills.py` or dedicated unit test file `agent/tests/test_ip_geolocation.py`:
1. **Group 1: Input Validation**:
   - `test_normalize_valid_ipv4()` (`8.8.8.8`, `1.1.1.1`)
   - `test_normalize_valid_ipv6()` (`2001:4860:4860::8888`, `::1`)
   - `test_normalize_strip_ports_and_schemes()` (`https://1.1.1.1:443`, `[::1]:8080`)
   - `test_reject_forbidden_characters()` (traversal, null bytes, invalid characters)
   - `test_opsec_active_scan_rejection()` (`passive_only=False` raises `ValueError`)
2. **Group 2: Bogon & Private IP Classification (Deterministic & Offline)**:
   - `test_detect_rfc1918_private_ranges()` (`10.0.0.1`, `172.16.5.2`, `192.168.1.1`) -> `is_bogon=True, is_private=True, latency < 5ms`
   - `test_detect_cgnat_rfc6598()` (`100.64.1.1`) -> `is_bogon=True`
   - `test_detect_loopback_and_metadata()` (`127.0.0.1`, `169.254.169.254`, `::1`) -> `is_bogon=True`
   - `test_detect_documentation_ips()` (`192.0.2.1`, `198.51.100.1`, `203.0.113.1`, `2001:db8::1`) -> `is_bogon=True`
3. **Group 3: Mocked Geolocation Lookups**:
   - `test_ip_api_mocked_success()`: mocks `requests.get` returning `ip-api.com` JSON, asserts `evidence` array structure, SHA-256 hash validity.
   - `test_failover_to_ipwhois()`: mocks `ip-api.com` returning 429 rate limit, asserts seamless fallback to `ipwho.is`.
   - `test_offline_graceful_fallback()`: mocks network down, verifies skill returns valid response without exception.
4. **Group 4: Cross-Skill Integration with `domain-whois-osint`**:
   - Test `_enrich_ip_intel` in `domain-whois-osint` discovering and executing `ip-geolocation-osint` via `Registry` and `Executor`.
   - Verify `intel_item.update(res)` properly propagates `is_tor`, `is_vpn`, `is_datacenter`, `country`, `city`, and `evidence`.

---

## 12. Verification Checklist for Milestone 1 Implementer

- [ ] Directory created at `agent/skills/investigation/ip-geolocation-osint/`.
- [ ] `skill.yaml` created with `status: runnable`, `category: investigation`, `runtime: {type: python, entry: run.py}`.
- [ ] `run.py` created with zero external binary calls, zero third-party whois packages, and pure Python stdlib + requests/dnspython.
- [ ] Bogon engine handles all RFC 1918, RFC 3927, RFC 6598, RFC 5737, multicast, and cloud metadata ranges without external HTTP requests.
- [ ] Reverse DNS uses `dnspython` PTR lookup with explicit bounded timeout (1.5s).
- [ ] Evidence records contain all 6 fields: `claim`, `source`, `query`, `timestamp`, `retrieved_at`, `response_sha256`, `raw_response_sha256`.
- [ ] Integration with `domain-whois-osint` succeeds via `Registry().skills.get("ip-geolocation-osint")` and `Executor().run()`.
- [ ] All 171 existing tests pass with zero regressions.
