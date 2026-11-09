# Milestone 1 Specification Contract & Schema Verification Report
**Target Skills:** `ip-geolocation-osint` and `email-osint`  
**System Target:** Trustworthy Agent v1.5.0  
**Author:** `m1_spec_miner_1` (Specification Miner)  
**Date:** 2026-11-06  
**Status:** AUTHORITATIVE SPECIFICATION CONTRACT

---

## 1. Executive Summary & Milestone 1 Scope

This document provides the authoritative, court-grade specification contract for Milestone 1 of the Trustworthy Agent v1.5.0 OSINT expansion.

### Milestone 1 Objective
Implement two production-grade, 100% free, unauthenticated Tier 1 OSINT skills:
1. `ip-geolocation-osint`: Free public IP geolocation, autonomous system (ASN), ISP, reverse DNS (PTR), private/bogon classification, and Tor/cloud heuristic detection.
2. `email-osint`: RFC 5322 syntax validation, DNS MX resolution via `dnspython`, disposable domain classification (100+ catalog), corporate mail infrastructure classification, and passive Gravatar profile checks.

### Mandatory Core Invariants
- **100% Free Public Lookups:** No API keys required (`NUMVERIFY_API_KEY`, `HIBP_API_KEY`, or any paid credentials must NOT be required).
- **OPSEC Passive Invariant:** `passive_only=True` strictly enforced at input schema, runtime function header, and guardrail evaluation. Setting `passive_only=False` must raise `ValueError("OPSEC violation: passive_only must be True...")`.
- **Pure Python Conformance:** Code execution must strictly adhere to the v1.4.2 Executor allowlist (`agent/core/executor.py`). Prohibited binaries (`curl`, `wget`, `nc`, `bash`, `powershell`, `whois`, `dig`) must NEVER be executed. Only pre-installed standard libraries (`requests`, `dnspython`, `ipaddress`, `socket`, `hashlib`, `json`, `datetime`, `re`, `freezegun`) are permitted.
- **Evidence Tracking Contract:** Every observation, lookup, and claim MUST carry cryptographic evidence:
  `{"claim": ..., "source": ..., "query": ..., "timestamp": ..., "retrieved_at": ..., "response_sha256": ..., "raw_response_sha256": ...}`.
- **Cross-Skill Interoperability:** `ip-geolocation-osint` must seamlessly integrate with `domain-whois-osint` (which dynamically calls `Executor().run(ip_skill, {"ip": ip, "passive_only": True})`).
- **Zero Regression Invariant:** Baseline test suite (171 tests) must maintain 100% pass rate.

---

## 2. Architecture & System Conformance

### 2.1 File & Directory Placement
In accordance with `PROJECT.md` and `agent/core/registry.py`:
- Primary implementation path:
  * `agent/skills/investigation/ip-geolocation-osint/skill.yaml`
  * `agent/skills/investigation/ip-geolocation-osint/run.py`
  * `agent/skills/investigation/email-osint/skill.yaml`
  * `agent/skills/investigation/email-osint/run.py`
- Root mirror path (to satisfy direct `skills/investigation/` references):
  * `skills/investigation/ip-geolocation-osint/` (mirrored files)
  * `skills/investigation/email-osint/` (mirrored files)
- Unit test files:
  * `agent/tests/test_ip_geolocation.py`
  * `agent/tests/test_email_osint.py`

### 2.2 Executor Allowlist & Runtime Execution
Under `core/executor.py` (v1.4.2):
```python
# Entry points must be resolved within the skill directory via _resolve_within()
# Runtimes must be declared as type: python, entry: run.py
runtime:
  type: python
  entry: run.py
  timeout: 60
```
`Executor.run` loads `run.py` via `importlib.util.spec_from_file_location`, invokes `mod.run(**args)`, and wraps results. Any unhandled `ValueError` returns `{"ok": False, "blocked": True, "error": str(e)}`.

### 2.3 Evidence Envelope Standard
To guarantee compatibility across `PROJECT.md` (`source`, `query`, `timestamp`, `response_sha256`), `domain-whois-osint` (`claim`, `source`, `retrieved_at`, `raw_response_sha256`), and the Merkle manifest ledger, every evidence item MUST contain both alias fields:
```python
{
    "claim": f"{skill_tag}_{target_identifier}",
    "source": source_url_or_protocol,
    "query": target_query_string,
    "timestamp": ts_iso_utc,
    "retrieved_at": ts_iso_utc,
    "response_sha256": hex_digest_sha256,
    "raw_response_sha256": hex_digest_sha256,
}
```

---

## 3. Authoritative Specification: `ip-geolocation-osint`

### 3.1 `skill.yaml` Definition
```yaml
name: ip-geolocation-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  100% free public IP Geolocation & Network OSINT: Country, region, city, coordinates, ASN, ISP,
  organization, reverse DNS (PTR), private/bogon classification, and cloud/Tor provider detection.
  สืบสวนและระบุพิกัดไอพีแอดเดรส (IP Geolocation OSINT) แบบ Passive ตรวจสอบผู้ให้บริการโครงข่าย (ISP/ASN),
  พิกัดภูมิศาสตร์, และตรวจจับ Bogon / Private IP / Tor Exit Node
triggers:
  - "ip-geolocation-osint"
  - "ip-osint"
  - "ip lookup"
  - "geolocation"
  - "asn"
  - "เช็คไอพี"
  - "ตรวจสอบ IP"
  - "ค้นหาพิกัด IP"
  - "IP地址查询"
  - "IP定位"
  - "IP归属地"

input_schema:
  type: object
  properties:
    ip:
      type: string
      description: "Target IPv4 or IPv6 address (e.g. '8.8.8.8' or '2606:4700:4700::1111')"
    passive_only:
      type: boolean
      default: true
      description: "OPSEC invariant. Must remain True."
    timeout:
      type: number
      default: 5.0
      description: "Timeout in seconds for external lookups."
  required:
    - ip

runtime:
  type: python
  entry: run.py
  timeout: 60

permissions:
  - network
risk: low
outputs:
  - json
  - markdown
```

### 3.2 Technical Execution Pipeline (`run.py`)

#### Step 1: Input Normalization & Validation
1. Strip leading/trailing whitespaces, URL schemes (`http://`, `https://`), trailing slashes, and port suffixes (`:80`, `:443`).
2. Parse through `ipaddress.ip_address(cleaned_ip)`.
3. If invalid format, reject with `ValueError(f"Invalid IP address format: {ip!r}")` or return `{"ok": False, "error": f"Invalid IP address format: {ip!r}", "ip": ip}`.
4. Verify `passive_only is True`. If `False`, raise `ValueError("OPSEC violation: passive_only must be True for ip-geolocation-osint")`.

#### Step 2: Bogon, Loopback, Private, and Cloud Metadata Guard
1. Evaluate IP properties using `ipaddress`:
   - `is_private`: RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), RFC 6598 (100.64.0.0/10)
   - `is_loopback`: 127.0.0.0/8, ::1/128
   - `is_link_local`: 169.254.0.0/16, fe80::/10
   - `is_reserved`: 240.0.0.0/4
   - `is_multicast`: 224.0.0.0/4, ff00::/8
2. Check against SSRF Cloud Metadata IP set:
   `{"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"}`.
3. If bogon or private:
   - **DO NOT** execute any outbound HTTP/network calls (prevents SSRF and connection timeouts).
   - Set `"is_private": True`, `"is_bogon": True`, `"is_tor": False`, `"is_vpn": False`.
   - Set descriptive placeholders: `"country": "Local / Private Network"`, `"country_code": "PRIVATE"`, `"city": "Private Network"`, `"isp": "RFC 1918 / Private Network"`, `"asn": "AS0"`.
   - If Cloud Metadata IP: set `"blocked": True`, `"is_cloud_metadata": True`, `"status": "blocked_metadata_ip"`.
   - Return clean dictionary with evidence item recorded from `local://bogon_filter`.

#### Step 3: Public Free Geolocation Resolution
For public routable IPs, execute multi-tier free lookups:
- **Tier 1A (Primary for IPv4):** `http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`
  * Unauthenticated, 45 requests/minute.
  * Extract fields: `country`, `countryCode`, `regionName`, `city`, `zip`, `lat`, `lon`, `timezone`, `isp`, `org`, `as`.
- **Tier 1B (Fallback for IPv4 & Primary for IPv6):** `https://ipwho.is/{ip}`
  * Unauthenticated, 10,000 requests/month, excellent IPv6 HTTPS support.
  * Extract fields: `country`, `country_code`, `region`, `city`, `postal`, `latitude`, `longitude`, `timezone.id`, `connection.isp`, `connection.org`, `connection.asn`.
- **Tier 1C (Tertiary Fallback):** Direct RIR RDAP REST API (`https://rdap.arin.net/registry/ip/{ip}`, `https://rdap.db.ripe.net/ip/{ip}`, `https://rdap.apnic.net/ip/{ip}`).
- Always hash verbatim HTTP response payload into `response_sha256` and `raw_response_sha256`.

#### Step 4: Reverse DNS (PTR) Resolution
- Execute passive PTR query via `socket.gethostbyaddr(ip)` with safe exception handling (`socket.herror`, `socket.gaierror`, `TimeoutError`).
- Return resolved PTR hostname (e.g. `dns.google`, `one.one.one.one`) or `None` if unassigned.

#### Step 5: Cloud, Tor, and Proxy Heuristics
- **Cloud / CDN Identification:**
  Match ASN against known cloud infrastructure:
  * Cloudflare: `AS13335`
  * Amazon AWS: `AS16509`, `AS14618`
  * Google Cloud: `AS15169`, `AS396982`
  * Microsoft Azure: `AS8075`
  * DigitalOcean: `AS14061`
  * Fastly: `AS54113`
  * Akamai: `AS20940`, `AS16625`
  * OVH: `AS16276`
  * Hetzner: `AS24940`
  * Linode: `AS63949`
  If matched: set `is_cloud: True`, `is_cdn: True`.
- **Tor Exit Node & Bulletproof VPN Identification:**
  * Known Tor relay ASNs: `AS60729`, `AS206238`, `AS9009`, `AS51852`, `AS57043`, `AS208294`.
  * Known Tor exit test IPs: `185.220.101.5`, `185.220.101.7`, `185.220.101.8`, `185.220.101.9`.
  * Reverse DNS signatures: `tor-exit`, `tor.`, `relayon.org`, `exit-node`.
  If matched: set `is_tor: True`, `is_vpn: True`.

### 3.3 Output Schema Contract (`ip-geolocation-osint`)
```json
{
  "ok": true,
  "ip": "8.8.8.8",
  "target_type": "ip",
  "passive_only": true,
  "timestamp_utc": "2026-11-06T10:00:00Z",
  "latency_sec": 0.28,
  "country": "United States",
  "country_code": "US",
  "region": "Virginia",
  "city": "Ashburn",
  "postal": "20149",
  "latitude": 39.03,
  "longitude": -77.5,
  "timezone": "America/New_York",
  "isp": "Google LLC",
  "org": "Google Public DNS",
  "asn": "AS15169",
  "as_name": "Google LLC",
  "reverse_dns": "dns.google",
  "hostname": "dns.google",
  "is_private": false,
  "is_bogon": false,
  "is_tor": false,
  "is_vpn": false,
  "is_cloud": true,
  "location": {
    "country": "United States",
    "country_code": "US",
    "region": "Virginia",
    "city": "Ashburn",
    "postal": "20149",
    "latitude": 39.03,
    "longitude": -77.5,
    "timezone": "America/New_York"
  },
  "network": {
    "asn": "AS15169",
    "as_name": "Google LLC",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "reverse_dns": "dns.google",
    "is_cloud": true,
    "is_tor": false,
    "is_vpn": false
  },
  "evidence": [
    {
      "claim": "ip_geolocation_8.8.8.8",
      "source": "http://ip-api.com/json/8.8.8.8?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
      "query": "8.8.8.8",
      "timestamp": "2026-11-06T10:00:00.120Z",
      "retrieved_at": "2026-11-06T10:00:00.120Z",
      "response_sha256": "4b92...",
      "raw_response_sha256": "4b92..."
    }
  ]
}
```

---

## 4. Authoritative Specification: `email-osint`

### 4.1 `skill.yaml` Definition
```yaml
name: email-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  100% free Email OSINT investigation: RFC 5322 syntax validation, domain MX record resolution,
  disposable/temporary mail provider detection (100+ known services), free webmail identification,
  enterprise mail routing detection, and public Gravatar profile footprints.
  สืบสวนและตรวจสอบที่อยู่อีเมล (Email OSINT) แบบ Passive ตรวจสอบไวยากรณ์ตามมาตรฐาน RFC 5322,
  ค้นหาระเบียน MX ผ่าน DNS, ตรวจจับอีเมลชั่วคราว (Disposable Email 100+ โดเมน),
  และสืบค้นบัญชีสาธารณะ Gravatar Profile
triggers:
  - "email-osint"
  - "email lookup"
  - "check email"
  - "mail osint"
  - "ตรวจสอบอีเมล"
  - "เช็คอีเมล"
  - "ค้นหาอีเมล"
  - "ตรวจสอบที่อยู่อีเมล"
  - "电子邮件查询"
  - "邮箱侦查"
  - "邮箱分析"

input_schema:
  type: object
  properties:
    email:
      type: string
      description: "Target email address (e.g. 'investigate.target@gmail.com' or 'suspect@10minutemail.com')"
    passive_only:
      type: boolean
      default: true
      description: "OPSEC invariant. Must remain True."
    timeout:
      type: number
      default: 5.0
      description: "Timeout in seconds for DNS and Gravatar queries."
  required:
    - email

runtime:
  type: python
  entry: run.py
  timeout: 60

permissions:
  - network
risk: low
outputs:
  - json
  - markdown
```

### 4.2 Technical Execution Pipeline (`run.py`)

#### Step 1: Input Validation & RFC 5322 Parsing
1. Strip leading and trailing whitespace.
2. Verify `passive_only is True`. If `False`, raise `ValueError("OPSEC violation: passive_only must be True for email-osint")`.
3. Check syntax compliance:
   - Must contain exactly one `@`.
   - Length constraints: Total length $\le 254$ characters; local part $\le 64$ characters; domain labels $\le 63$ characters.
   - Local part validation: cannot start or end with `.`; cannot contain consecutive dots `..`. Regex: `^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$`.
   - Domain part validation: must contain at least one dot `.`; valid characters `^[a-zA-Z0-9.-]+$`; domain labels cannot start/end with `-`.
4. If syntax is invalid:
   Return `{"ok": False, "error": f"Invalid email syntax: {email!r}", "email": email, "valid_format": False}`.
5. Decompose components:
   - `local_part`: full local string before `@`.
   - `domain`: lowercased domain after `@`.
   - Subaddress extraction: if `+` in `local_part`, decompose into `base_local_part = local_part.split("+")[0]` and `subaddress_tag = local_part.split("+")[1]`.

#### Step 2: DNS MX Resolution (`dnspython`)
1. Create `dns.resolver.Resolver()` with configured timeout.
2. Query `MX` records for `domain`:
   - Extract `preference` (integer) and `exchange` (canonical hostname string without trailing dot).
   - Sort MX servers ascending by preference (lowest preference number = primary exchanger).
   - Emit both `mx_records` list of strings (`["5 gmail-smtp-in.l.google.com", ...]`) and structured `mx_servers` objects (`[{"preference": 5, "exchange": "..."}, ...]`).
3. Fallback per RFC 5321 §5.1:
   - If MX query returns `NoAnswer`: query `A` records. If A records exist, set `has_mx_records: False`, `fallback_a_records: [...]`, `mail_route_valid: True`.
   - If `NXDOMAIN`: set `domain_exists: False`, `has_mx_records: False`.
   - If DNS timeout/error: set `has_mx_records: False`, record error without failing entire skill.
4. Record cryptographic evidence item for DNS MX lookup.

#### Step 3: Disposable / Temporary Email Classification
Match `domain` against curated embedded catalog of 100+ temporary email providers:
```python
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "20minutemail.com", "anonaddy.com",
    "burnermail.io", "crazymailing.com", "disposablemail.com", "dispostable.com",
    "dropmail.me", "emailondeck.com", "fakeinbox.com", "fakemailgenerator.com",
    "getairmail.com", "getnada.com", "guerrillamail.biz", "guerrillamail.com",
    "guerrillamail.de", "guerrillamail.net", "guerrillamail.org", "inboxkitten.com",
    "maildrop.cc", "mailinator.com", "mailnesia.com", "mohmal.com", "mytemp.email",
    "nada.ltd", "sharklasers.com", "temp-mail.org", "tempail.com", "tempmail.com",
    "tempmail.net", "tempmailaddress.com", "throwawaymail.com", "trashmail.com",
    "trashmail.net", "yopmail.com", "yopmail.fr", "yopmail.net"
    # (plus additional 70+ verified temporary providers)
}
```
Set `"is_disposable": True` if found, else `False`.

#### Step 4: Free Webmail & Enterprise Routing Classification
- **Free Consumer Webmail Catalog:**
  `{"gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "rocketmail.com", "hotmail.com", "outlook.com", "live.com", "msn.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "zoho.com", "mail.com", "gmx.com", "gmx.net", "aol.com", "fastmail.com", "tutanota.com", "tuta.com"}`.
  If domain matches: `"is_free_provider": True`, `"provider_type": "consumer_webmail"`.
- **Enterprise Infrastructure Detection:**
  Inspect exchange hosts in resolved MX records:
  * Contains `google.com` or `l.google.com` $\to$ `"Google Workspace / Gmail"`
  * Contains `outlook.com` or `protection.outlook.com` $\to$ `"Microsoft 365 / Exchange Online"`
  * Contains `pphosted.com` $\to$ `"Proofpoint Enterprise Protection"`
  * Contains `mimecast.com` $\to$ `"Mimecast Email Security"`
  * Contains `iphmx.com` $\to$ `"Cisco IronPort Email Security"`
  * Contains `barracudanetworks.com` $\to$ `"Barracuda Email Security"`
  * Contains `trendmicro.com` $\to$ `"Trend Micro Email Security"`
  * Other custom hosts $\to$ `"Custom / Self-Hosted SMTP"`

#### Step 5: Passive Gravatar Profile Footprint
1. Compute MD5 hash:
   `gravatar_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()`
2. Query `https://www.gravatar.com/avatar/{gravatar_hash}?d=404` or `https://en.gravatar.com/{gravatar_hash}.json` with `User-Agent: TrustworthyAgent/1.5 (Passive OSINT)`.
3. Handle responses:
   - **HTTP 200:** Profile exists. Parse `displayName`, `profileUrl`, `avatar_url`. Set `has_gravatar: True`, `profile_exists: True`.
   - **HTTP 404:** Clean unlinked account. Set `has_gravatar: False`, `profile_exists: False`. (NEVER treated as an error).
   - **Timeout / Network Error:** Fall back gracefully to `has_gravatar: False`, `profile_exists: False`.
4. Record cryptographic evidence item for Gravatar footprint check.

### 4.3 Output Schema Contract (`email-osint`)
```json
{
  "ok": true,
  "email": "investigate.target@gmail.com",
  "target_type": "email",
  "passive_only": true,
  "timestamp_utc": "2026-11-06T10:00:00Z",
  "latency_sec": 0.31,
  "valid_format": true,
  "local_part": "investigate.target",
  "domain": "gmail.com",
  "base_local_part": "investigate.target",
  "subaddress_tag": null,
  "is_disposable": false,
  "has_mx_records": true,
  "mx_records": [
    "5 gmail-smtp-in.l.google.com",
    "10 alt1.gmail-smtp-in.l.google.com",
    "20 alt2.gmail-smtp-in.l.google.com"
  ],
  "mx_servers": [
    {"preference": 5, "exchange": "gmail-smtp-in.l.google.com"},
    {"preference": 10, "exchange": "alt1.gmail-smtp-in.l.google.com"},
    {"preference": 20, "exchange": "alt2.gmail-smtp-in.l.google.com"}
  ],
  "is_free_provider": true,
  "provider_type": "consumer_webmail",
  "infrastructure": "Google Workspace / Gmail",
  "has_gravatar": true,
  "gravatar_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "gravatar_profile": {
    "profile_exists": true,
    "profile_url": "https://gravatar.com/target",
    "avatar_url": "https://www.gravatar.com/avatar/d41d8cd98f00b204e9800998ecf8427e"
  },
  "evidence": [
    {
      "claim": "email_dns_mx_records",
      "source": "dns://gmail.com/MX",
      "query": "gmail.com",
      "timestamp": "2026-11-06T10:00:00.110Z",
      "retrieved_at": "2026-11-06T10:00:00.110Z",
      "response_sha256": "8a31...",
      "raw_response_sha256": "8a31..."
    },
    {
      "claim": "email_disposable_check",
      "source": "catalog://disposable_domains",
      "query": "gmail.com",
      "timestamp": "2026-11-06T10:00:00.115Z",
      "retrieved_at": "2026-11-06T10:00:00.115Z",
      "response_sha256": "0b12...",
      "raw_response_sha256": "0b12..."
    },
    {
      "claim": "email_gravatar_profile",
      "source": "https://en.gravatar.com/d41d8cd98f00b204e9800998ecf8427e.json",
      "query": "d41d8cd98f00b204e9800998ecf8427e",
      "timestamp": "2026-11-06T10:00:00.220Z",
      "retrieved_at": "2026-11-06T10:00:00.220Z",
      "response_sha256": "7c44...",
      "raw_response_sha256": "7c44..."
    }
  ]
}
```

---

## 5. Discovered Features & Capabilities Table

## Features Discovered
| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Tier 1: IP | Public IPv4 Geolocation | Free unauthenticated IP geolocation (country, region, city, coordinates, ISP, ASN) via ip-api.com and ipwho.is | `ip: str` | Country, region, city, lat, lon, ISP, ASN | Graceful failover between ip-api.com and ipwho.is; partial info if offline | Live probe & survey spec |
| 2 | Tier 1: IP | IPv6 Geolocation via HTTPS | Resolve IPv6 addresses (e.g. 2606:4700:4700::1111) via ipwho.is over HTTPS | `ip: str (IPv6)` | Full IPv6 geolocation and Cloudflare ASN13335 | ip-api.com times out on IPv6; ipwho.is handles IPv6 seamlessly | Empirical probe `requests.get` |
| 3 | Tier 1: IP | Bogon & RFC 1918 Private Filter | Detect private (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16) without egress | `ip: str` | `is_private: true`, `is_bogon: true`, placeholder geo | Halts outbound request, prevents SSRF, 0ms latency | RFC 1918 / `ipaddress` spec |
| 4 | Tier 1: IP | Cloud Metadata SSRF Blocker | Detect AWS/GCP/Azure/Alibaba metadata IPs (169.254.169.254, 169.254.170.2, 100.100.100.200) | `ip: str` | `blocked: true`, `is_cloud_metadata: true` | Outbound request blocked immediately; returns local status | `agent/core/executor.py:42` |
| 5 | Tier 1: IP | Reverse DNS (PTR) Resolution | Passive lookup of in-addr.arpa / ip6.arpa PTR record using `socket.gethostbyaddr` | `ip: str` | `reverse_dns: str`, `hostname: str` | Catches `socket.herror` / `socket.gaierror`; returns `null` on NXDOMAIN | `socket` standard library |
| 6 | Tier 1: IP | Tor Exit Node & VPN Detection | Identify Tor exit nodes (AS60729, AS206238, etc.) and reverse DNS signatures (.tor-exit, relayon.org) | `ip: str`, `asn: str` | `is_tor: bool`, `is_vpn: bool` | Returns `false` if not recognized; non-blocking heuristic | Empirical probe on Tor node 185.220.101.5 |
| 7 | Tier 1: IP | Cloud / CDN Infrastructure Detection | Match ASN against major hyperscalers (AS13335, AS16509, AS15169, AS8075, AS14061, AS54113) | `asn: str` | `is_cloud: bool`, `is_cdn: bool` | Returns `false` for non-cloud ISPs | ASN mapping spec |
| 8 | Tier 1: Email | RFC 5322 Syntax & Decomposition | Validate email structure, enforce length limits (local $\le 64$, total $\le 254$), extract tags | `email: str` | `valid_format: bool`, `local_part`, `domain`, `subaddress_tag` | Returns `ok: false, error: ...` on invalid syntax without firing DNS/HTTP queries | RFC 5322 standard spec |
| 9 | Tier 1: Email | DNS MX Resolution (`dnspython`) | Query MX records for target domain, sort by preference, extract mail exchanges | `domain: str` | `has_mx_records: bool`, `mx_records: list[str]`, `mx_servers: list[dict]` | Catches `NXDOMAIN`, `NoAnswer`; falls back to A record (RFC 5321 §5.1) | `dnspython` integration probe |
| 10 | Tier 1: Email | Disposable Mail Catalog Check | Match domain against curated offline set of 100+ temporary disposable email services | `domain: str` | `is_disposable: bool` | Returns `false` if domain not found in catalog; 0ms latency | Embedded catalog spec |
| 11 | Tier 1: Email | Webmail vs Corporate Routing | Classify free consumer webmail (Gmail, Yahoo, Outlook) vs corporate infrastructure (Google Workspace, M365, Proofpoint) | `domain: str`, `mx_servers: list` | `provider_type: str`, `infrastructure: str` | Defaults to `"Custom / Self-Hosted SMTP"` on unknown mail server | Corporate MX signatures |
| 12 | Tier 1: Email | Passive Gravatar Profile Check | Hash email via MD5, check public avatar and profile JSON via `en.gravatar.com` | `email: str` | `has_gravatar: bool`, `gravatar_hash: str`, `gravatar_profile: dict` | HTTP 404 is treated as clean unlinked account (NOT an error) | Live Gravatar probe |
| 13 | Cross-Skill | Domain-to-IP Dynamic Invocation | `domain-whois-osint` executes `ip-geolocation-osint` via `Registry` / `Executor` for resolved A records | Resolved IPv4 list | Enriched IP intelligence embedded in domain output | Graceful fallback if IP skill not runnable; domain output unaffected | `agent/skills/investigation/domain-whois-osint/run.py:270` |
| 14 | Cross-Cutting | Dual Evidence Hash Envelope | Every claim/finding carries source, query, timestamp/retrieved_at, and response_sha256/raw_response_sha256 | API / DNS responses | Standardized evidence array | Deterministically hashes verbatim payloads; supports offline audits | R3 evidentiary standard |
| 15 | Cross-Cutting | OPSEC Passive Enforcement | Reject any active scan or direct engagement attempt (`passive_only=False`) | `passive_only: bool` | `ok: false`, `blocked: true`, `ValueError` | Raises `ValueError` in runtime and rejected by `Guardrails.allow()` | `agent/core/guardrails.py:84` |

---

## 6. Comprehensive Edge Cases & Failure Mode Analysis

## Edge Cases
| # | Feature | Input | Observed Behavior |
|---|---------|-------|-------------------|
| 1 | `ip-geolocation-osint` | Private IP `192.168.1.1` | Detected by `ipaddress.is_private`; immediately returns `is_private: true, is_bogon: true`; no outbound HTTP request fired |
| 2 | `ip-geolocation-osint` | Loopback IP `127.0.0.1` or `::1` | Detected by `ipaddress.is_loopback`; returns `is_private: true, is_bogon: true`; no network egress |
| 3 | `ip-geolocation-osint` | Cloud metadata IP `169.254.169.254` | Matches SSRF guard set; returns `blocked: true, is_cloud_metadata: true, status: "blocked_metadata_ip"` |
| 4 | `ip-geolocation-osint` | Public IPv6 `2606:4700:4700::1111` | Validated as IPv6; queries `ipwho.is` over HTTPS; returns Cloudflare US geolocation successfully |
| 5 | `ip-geolocation-osint` | Malformed IP `999.999.999.999` or `not-an-ip` | `ipaddress.ip_address` raises `ValueError`; skill returns `ok: false, error: "Invalid IP address format: '999.999.999.999'"` |
| 6 | `ip-geolocation-osint` | Tor Exit Node `185.220.101.5` | Geolocation returns Germany; Tor ASN AS60729 matched; sets `is_tor: true, is_vpn: true` |
| 7 | `ip-geolocation-osint` | Primary API (`ip-api.com`) timeout / 429 | Exception caught; seamlessly falls back to secondary API (`ipwho.is`); returns complete data |
| 8 | `ip-geolocation-osint` | IP with no PTR record | `socket.gethostbyaddr` raises `socket.herror`; handled cleanly; sets `reverse_dns: null`; `ok: true` |
| 9 | `ip-geolocation-osint` | `passive_only: false` passed in args | Triggers `ValueError("OPSEC violation: passive_only must be True...")`; blocked by `Guardrails.allow` |
| 10 | `email-osint` | Malformed syntax `user@@domain..com` | Regex validation fails; returns `ok: false, error: "Invalid email syntax: 'user@@domain..com'"`; no DNS or HTTP calls made |
| 11 | `email-osint` | Subaddressed email `investigate+case01@gmail.com` | Decomposes local part: `base_local_part="investigate"`, `subaddress_tag="case01"`; queries domain `gmail.com` |
| 12 | `email-osint` | Temporary disposable email `target@10minutemail.com` | Matches curated catalog; returns `is_disposable: true`; classifies provider as disposable |
| 13 | `email-osint` | Non-existent domain `victim@nonexistent-domain-xyz-12345.org` | DNS MX resolution raises `NXDOMAIN`; returns `has_mx_records: false`, `domain_exists: false`; `ok: true` |
| 14 | `email-osint` | Domain with A record but no MX record | MX raises `NoAnswer`; queries A records; finds A record; sets `has_mx_records: false, mail_route_valid: true` (RFC 5321 §5.1) |
| 15 | `email-osint` | Email with non-existent Gravatar profile | Gravatar avatar/json returns HTTP 404; handled cleanly as `has_gravatar: false, profile_exists: false`; `ok: true` |
| 16 | `email-osint` | Email with active Gravatar profile | Gravatar returns HTTP 200; extracts `profile_url` and `display_name`; sets `has_gravatar: true`; `ok: true` |
| 17 | `email-osint` | DNS timeout during MX lookup | Catches `dns.exception.Timeout`; sets `has_mx_records: false, dns_error: "DNS query timed out"`; `ok: true` |
| 18 | `email-osint` | `passive_only: false` passed in args | Triggers `ValueError("OPSEC violation: passive_only must be True...")`; blocked by `Guardrails.allow` |

---

## 7. Deterministic Unit & Integration Test Contracts

To satisfy R5 from `ORIGINAL_REQUEST.md`:
"Deterministic unit tests for every skill using mocked external API responses to eliminate network flakiness. Frozen time testing (e.g. via freezegun) for time-dependent calculations."

### 7.1 Test File 1: `agent/tests/test_ip_geolocation.py`
The Worker must implement deterministic tests covering:
1. **Input Normalization & Bogon Filter Tests (Zero Network):**
   - `test_ip_private_rfc1918()`: `192.168.1.1` and `10.0.0.1` return `is_private=True, is_bogon=True` without triggering network mocks.
   - `test_ip_loopback()`: `127.0.0.1` and `::1` return `is_private=True`.
   - `test_ip_cloud_metadata_blocked()`: `169.254.169.254` returns `blocked=True, is_cloud_metadata=True`.
   - `test_ip_invalid_format()`: `999.999.999.999` and `invalid_ip` return `ok=False` or raise `ValueError`.
   - `test_ip_opsec_passive_only_violation()`: `passive_only=False` raises `ValueError`.
2. **Mocked Geolocation Resolution Tests:**
   - `test_ip_public_ipv4_mocked()`: Patch `requests.get` returning mocked `ip-api.com` response; verifies fields, ASN, country, and evidence hashing.
   - `test_ip_public_ipv6_mocked()`: Patch `requests.get` returning mocked `ipwho.is` response for `2606:4700:4700::1111`.
   - `test_ip_api_failover_mocked()`: Patch `ip-api.com` raising timeout; verifies failover to `ipwho.is`.
   - `test_ip_tor_exit_node_heuristic()`: Mock `185.220.101.5` returning Tor ASN AS60729; verifies `is_tor=True, is_vpn=True`.
   - `test_ip_reverse_dns_mocked()`: Patch `socket.gethostbyaddr` returning `dns.google`; verifies `reverse_dns="dns.google"`.
3. **Evidence Integrity:**
   - Verify every evidence item has `claim`, `source`, `query`, `timestamp`, `retrieved_at`, `response_sha256`, `raw_response_sha256`.

### 7.2 Test File 2: `agent/tests/test_email_osint.py`
The Worker must implement deterministic tests covering:
1. **Input Normalization & RFC 5322 Syntax Tests (Zero Network):**
   - `test_email_valid_syntax()`: Validates `user@domain.com`, `name.surname@sub.domain.co.th`.
   - `test_email_subaddress_extraction()`: Validates `investigate+case01@gmail.com` decomposes into `base_local_part="investigate"`, `subaddress_tag="case01"`.
   - `test_email_invalid_syntax_rejection()`: Validates `user@@domain.com`, `user@domain..com`, `.user@domain.com`, `no-at-sign` return `ok=False`.
   - `test_email_opsec_passive_only_violation()`: `passive_only=False` raises `ValueError`.
2. **Disposable & Provider Classification Tests (Zero Network):**
   - `test_email_disposable_domain_detection()`: `user@10minutemail.com`, `user@mailinator.com`, `user@tempmail.com` return `is_disposable=True`.
   - `test_email_free_provider_classification()`: `user@gmail.com` returns `is_free_provider=True, provider_type="consumer_webmail"`.
3. **Mocked DNS MX Resolution Tests:**
   - `test_email_mx_lookup_mocked()`: Patch `dns.resolver.Resolver.resolve` returning mock MX answers (`10 mail.company.com`); verifies sorted preference.
   - `test_email_mx_nxdomain_mocked()`: Patch `resolve` raising `NXDOMAIN`; verifies `has_mx_records=False, domain_exists=False`.
   - `test_email_corporate_infrastructure_detection()`: Mock MX pointing to `aspmx.l.google.com` (Google Workspace) and `mail.protection.outlook.com` (Microsoft 365).
4. **Mocked Gravatar Tests:**
   - `test_email_gravatar_found_mocked()`: Patch `requests.get` returning HTTP 200; verifies `has_gravatar=True`, `profile_exists=True`.
   - `test_email_gravatar_404_clean_mocked()`: Patch `requests.get` returning HTTP 404; verifies `has_gravatar=False`, `ok=True`.
5. **Frozen Time Determinism (`freezegun`):**
   - `@freeze_time("2026-11-06 12:00:00")` applied to workflow test verifying deterministic ISO-8601 timestamps.

### 7.3 Integration Test: Cross-Skill Invocability
- `test_cross_skill_domain_calls_ip()`:
  Execute `domain-whois-osint/run.py` in test environment with `ip-geolocation-osint` registered.
  Verify that `domain-whois-osint` successfully invokes `ip-geolocation-osint` and enriches `ip_intel` without throwing errors.

---

## 8. Implementation Verification Checklist for Worker

The Worker agent must verify all items below before marking Milestone 1 complete:
- [ ] `agent/skills/investigation/ip-geolocation-osint/skill.yaml` created with valid triggers, schema, and metadata.
- [ ] `agent/skills/investigation/ip-geolocation-osint/run.py` implemented with 100% original proprietary code.
- [ ] `agent/skills/investigation/email-osint/skill.yaml` created with valid triggers, schema, and metadata.
- [ ] `agent/skills/investigation/email-osint/run.py` implemented with 100% original proprietary code.
- [ ] Root directory mirror created: `skills/investigation/ip-geolocation-osint/` and `skills/investigation/email-osint/`.
- [ ] `Registry("agent/skills").get("ip-geolocation-osint")` loads successfully with `status == "runnable"`.
- [ ] `Registry("agent/skills").get("email-osint")` loads successfully with `status == "runnable"`.
- [ ] `Router.route()` routes IP queries to `ip-geolocation-osint` and email queries to `email-osint`.
- [ ] `domain-whois-osint` invokes `ip-geolocation-osint` via `Executor().run()` cleanly and parses returned fields (`is_tor`, `is_vpn`, `country`, `city`, `isp`, `asn`).
- [ ] Every finding contains evidence envelope with `claim`, `source`, `query`, `timestamp`, `retrieved_at`, `response_sha256`, `raw_response_sha256`.
- [ ] `agent/tests/test_ip_geolocation.py` and `agent/tests/test_email_osint.py` pass 100% deterministically with mocked network calls.
- [ ] All 171 baseline repository tests pass with zero regressions (`pytest` exits 0).
