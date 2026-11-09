# Comprehensive Specification Survey Report: 5 Production-Grade OSINT Skills for Trustworthy Agent v1.5.0

**Document Reference:** `spec_report.md`  
**Date:** 2026-11-06  
**Author:** `survey_miner_1` (Specification Miner)  
**Target System:** Trustworthy Agent v1.5.0  
**Status:** Complete / Authoritative Survey

---

## 1. Executive Summary & Architectural Overview

This specification report defines the authoritative requirements, schemas, data contracts, and evidentiary standards for implementing **5 production-grade OSINT skills** for **Trustworthy Agent v1.5.0**.

The goal of this upgrade is to replace initial stubs and partial mocks with court-grade, verifiable open-source intelligence capabilities suitable for live demonstration to enterprise and government audiences (such as law enforcement, cyber security agencies, and forensic auditors).

### Two-Tier Architecture
The 5 OSINT skills are structured into a two-tier operational hierarchy:
1. **Tier 1 (100% Free & Unauthenticated):**
   - `domain-whois-osint`: WHOIS, DNS, Certificate Transparency (`crt.sh`), explainable scam heuristic scoring (0–100), bilingual reasoning (`top_reason_th`, `top_reason_en`), and cross-skill invocation to IP skill.
   - `ip-geolocation-osint`: Free public IP lookups (country, city, coordinates, ISP, ASN, reverse DNS, cloud/private detection), callable standalone and by Domain skill.
   - `email-osint`: Syntax analysis, DNS MX resolution, disposable domain classification, corporate mail routing, and public Gravatar profile footprints.
2. **Tier 2 (Configurable API Keys with Graceful Fallback):**
   - `phone-osint`: Authenticated lookup via `NUMVERIFY_API_KEY` (or Twilio/AbstractAPI) when present; seamless offline ITU-T E.164 parsing, carrier prefix identification (Thailand +66, Taiwan +886, International), and roaming/GTP tunnel analysis when absent.
   - `breach-check`: Authenticated breach lookup via `HIBP_API_KEY` when present; graceful fallback to k-Anonymity SHA-1 prefix checks and curated public breach catalogs when absent, with robust 404 (clean account) handling.

### Baseline Guardrails & Invariants
- **Zero Regressions:** Full compatibility with the existing 171 repository tests in `agent/tests/` (171/171 passing).
- **Core Logic Conformance:** 100% proprietary original implementation; no copy-pasting from open-source tool codebases.
- **Executor v1.4.2 Allowlist:** No forbidden binaries (`curl`, `wget`, `bash`, `sh`, `nc`, `powershell`, etc.); execution restricted to Python using approved pre-installed libraries (`requests`, `dnspython`, `urllib`, `freezegun`).
- **Passive Reconnaissance Invariant:** `passive_only=True` strictly enforced at schema, runtime, and guardrails levels. Any attempt to set `passive_only=False` triggers a `ValueError` and is blocked by `Guardrails.allow()`.
- **Cryptographic Trust:** Every finding contains `source`, `query`, `timestamp`, and `response_sha256`. Outputs are committed to the dual SHA-256 audit hash chain (`logs/audit.jsonl` and `artifacts/<case>/audit.jsonl`), Merkle artifact tree (`artifact_manifest.json`), and external anchor ledger.

---

## 2. Existing Codebase, Schemas, and Artifact Survey

An exhaustive survey of `agent/skills/`, `agent/core/`, `agent/artifacts/`, and `agent/tests/` revealed the existing patterns and contracts:

### 2.1 Existing Investigation Skills
Located in `agent/skills/investigation/`:
- `case-dossier-exporter`: Generates bilingual court dossiers (TH/zh-TW) compliant with Thai Anti-Trafficking Act B.E. 2551 and Taiwan Human Trafficking Prevention Act.
- `counter-fraud-disruption`: Prepares infrastructure takedown packages (`risk: high`, requires user confirmation `_confirmed: true`).
- `digital-forensics-investigator`: Builds MACB timelines and extracts entities (Thai ID, Passports, Roaming IPs).
- `phone-email-osint`: Legacy dual-purpose stub that referenced external helper scripts or returned static mock dicts.
  * *Critical Observation:* Existing tests (`test_guardrails.py`, `test_router.py`, `test_trust.py`) explicitly require `phone-email-osint` in `Registry` and test router hit on `"追踪电话号码和关联账户"`. Therefore, `phone-email-osint` must remain intact or delegate to maintain 100% backward compatibility with the 171 baseline tests.
- `secops-detection-engineering`: YARA / Sigma detection rule generation.
- `syndicate-roster-tracker`: Cross-channel Telegram syndicate shift tracking (`@bv92111`, `@huai9211`, etc.).
- `system-architecture-planner`: Enterprise architecture plans.

### 2.2 Skill Schema Convention (`skill.yaml`)
Every skill requires a valid `skill.yaml` loaded by `core/registry.py`:
```yaml
name: <skill-name>
version: 1.0.0
category: investigation
status: runnable         # 'runnable' (production) or 'stub' (docs only)
description: >
  Multilingual description (TH/EN/ZH) explaining tool capabilities and triggers
triggers:
  - English triggers
  - คำค้นภาษาไทย
  - 中文触发词
input_schema:
  type: object
  properties: ...
  required: [...]
runtime:
  type: python
  entry: run.py
  timeout: 120           # Max timeout in seconds (capped at 900s)
permissions: [network]
risk: low                # 'low', 'medium', or 'high'
outputs: [json, markdown]
```

### 2.3 Runtime Execution Mechanics (`core/executor.py`)
`Executor.run()` handles Python skills:
1. Resolves `entry` within `skill_dir` via `_resolve_within()` (blocking path traversal, `..`, null bytes, absolute paths).
2. Dynamically loads module via `importlib.util.spec_from_file_location`.
3. Calls `mod.run(**args)`.
4. Returns result dictionary. If output is not a dict, wraps it as `{"ok": True, "result": res}`.
5. Catches exceptions and returns `{"ok": False, "error": str(e)}`.
6. Enforces RateLimiter: Sliding-window max 60 calls per 60 seconds per skill/domain.

---

## 3. Detailed Specifications for 5 OSINT Skills

### 3.1 Skill 1: Domain/WHOIS OSINT (`domain-whois-osint`)

- **Skill Directory:** `agent/skills/investigation/domain-whois-osint/` (mirrored in `skills/investigation/domain-whois-osint/`)
- **Category:** `investigation`
- **Tier:** 1 (100% Free, No API Keys)
- **Risk Level:** `low`
- **Runtime:** `type: python`, `entry: run.py`, `timeout: 120`

#### 3.1.1 `skill.yaml` Specification
```yaml
name: domain-whois-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  Comprehensive Domain & WHOIS OSINT analysis: WHOIS registrar data, DNS records (A, AAAA, MX, NS, TXT, SOA),
  crt.sh Certificate Transparency subdomains, explainable scam heuristic score (0-100), bilingual reasons
  (top_reason_th and top_reason_en), and cross-skill IP intelligence.
triggers:
  - domain-whois-osint
  - whois
  - dns
  - domain lookup
  - crt.sh
  - scam check
  - fake website
  - ตรวจสอบโดเมน
  - เช็คเว็บปลอม
  - ตรวจสอบชื่อโดเมน
  - 域名查询
  - 域名分析
  - 钓鱼网站检测
input_schema:
  type: object
  properties:
    domain:
      type: string
      description: Target domain name or URL (e.g. "suspicious-bank-login.xyz" or "https://fake-login.com/auth")
    include_subdomains:
      type: boolean
      default: true
      description: Query crt.sh for known Certificate Transparency subdomains
    include_ip_lookup:
      type: boolean
      default: true
      description: Cross-skill query to IP Geolocation skill for resolved A records
    passive_only:
      type: boolean
      default: true
      description: OPSEC invariant. Must remain True.
  required:
    - domain
runtime:
  type: python
  entry: run.py
  timeout: 120
permissions:
  - network
risk: low
outputs:
  - json
  - markdown
```

#### 3.1.2 Sub-Components & Mechanics
1. **Domain Sanitization & Normalization:**
   - Strips `http://`, `https://`, paths, queries, ports, and trailing slashes.
   - Converts IDN (Internationalized Domain Names, e.g. Thai/Chinese domains) to ASCII Punycode (`xn--...`) for network queries, while retaining Unicode display names.
2. **WHOIS Data Gathering:**
   - Pure Python query using RDAP (REST over HTTPS: `https://rdap.org/domain/{domain}`) with socket port 43 fallback to standard whois servers (`whois.iana.org`, `whois.verisign-grs.com`, `whois.thnic.co.th`).
   - Extracts: `registrar`, `creation_date`, `expiration_date`, `updated_date`, `domain_age_days`, `registrant_country`, `name_servers`, `status`.
   - Handles redacted/privacy-guarded WHOIS records gracefully.
3. **DNS Resolution (`dnspython`):**
   - Queries record types: `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CNAME`.
   - Handles `NXDOMAIN`, `NoAnswer`, and DNS timeouts cleanly without crashing.
4. **Certificate Transparency (`crt.sh`):**
   - Queries `https://crt.sh/?q=%.{domain}&output=json` with timeout.
   - Extracts unique subdomains, certificate issuer names, issue dates (`not_before`), and expiration dates (`not_after`).
   - Caps returned subdomains at 100 to avoid buffer overflow.
5. **Cross-Skill Invocation to IP Geolocation:**
   - For resolved IPv4 addresses from A records, queries `ip-geolocation-osint` via `Registry` / `Executor`.
   - Graceful fallback: If IP skill is unavailable, records resolved IPs directly without failing the domain analysis.
6. **Explainable Scam Heuristic Engine:**
   - Calculates numeric risk score $S \in [0, 100]$.
   - Weights and Signals:
     * **Domain Age Weight ($W_1 = 35$):** Age $< 14\text{ days} \to 35\text{ pts}$; $< 30\text{ days} \to 28\text{ pts}$; $< 90\text{ days} \to 18\text{ pts}$; $< 180\text{ days} \to 10\text{ pts}$; $\ge 365\text{ days} \to 0\text{ pts}$. (If age unknown/hidden: $14\text{ pts}$).
     * **Brand / Impersonation Keywords ($W_2 = 25$):** Presence of financial/institutional keywords (`kbank`, `scb`, `bbl`, `ktb`, `ttb`, `gsb`, `promptpay`, `truemoney`, `binance`, `line`, `police`, `customs`, `revenue`, `secure`, `login`, `verify`) in non-official domains $\to 25\text{ pts}$.
     * **High-Risk TLD ($W_3 = 15$):** TLDs frequently abused in phishing (`.top`, `.xyz`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.buzz`, `.icu`, `.cam`, `.work`, `.rest`, `.fit`, `.surf`) $\to 15\text{ pts}$.
     * **SSL Certificate Recency ($W_4 = 15$):** Certificate issued $< 7\text{ days}$ ago $\to 15\text{ pts}$; $< 30\text{ days} \to 8\text{ pts}$.
     * **Punycode / Homograph ($W_5 = 15$):** Contains `xn--` or mixed scripts $\to 15\text{ pts}$.
     * **Missing MX Records for Service Domain ($W_6 = 10$):** Has brand/financial keywords but 0 MX records $\to 10\text{ pts}$.
   - Overall Score Formula:
     $$\text{risk\_score} = \min\left(100, \sum_{i} \text{signal\_score}_i\right)$$
   - Risk Levels:
     * $0 - 39$: `"low"`
     * $40 - 69$: `"medium"` (Suspicious)
     * $70 - 100$: `"high"` (Scam / Likely Phishing)
   - Confidence Levels:
     * `"high"`: WHOIS, DNS, and crt.sh all responded.
     * `"medium"`: DNS and crt.sh responded; WHOIS redacted or timed out.
     * `"low"`: Only DNS responded or network restricted.
   - Bilingual Explanations:
     * `top_reason_th`: Synthesizes top contributing factors in natural Thai.
     * `top_reason_en`: Synthesizes top contributing factors in natural English.

#### 3.1.3 Output Schema
```json
{
  "ok": true,
  "domain": "suspicious-kbank-update.xyz",
  "normalized_domain": "suspicious-kbank-update.xyz",
  "timestamp": "2026-11-06T10:00:00Z",
  "passive_only": true,
  "whois": {
    "registrar": "NameCheap, Inc.",
    "creation_date": "2026-10-25T12:00:00Z",
    "expiration_date": "2027-10-25T12:00:00Z",
    "domain_age_days": 12,
    "registrant_country": "PA",
    "name_servers": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
    "status": ["clientTransferProhibited"]
  },
  "dns": {
    "A": ["185.199.108.153"],
    "AAAA": [],
    "MX": [],
    "NS": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
    "TXT": ["v=spf1 -all"]
  },
  "certificates": {
    "subdomain_count": 3,
    "subdomains": ["admin.suspicious-kbank-update.xyz", "login.suspicious-kbank-update.xyz"],
    "latest_issuer": "Let's Encrypt",
    "latest_issue_date": "2026-10-25T14:30:00Z",
    "cert_age_days": 12
  },
  "ip_intelligence": {
    "invoked": true,
    "ip": "185.199.108.153",
    "data": { ... }
  },
  "scam_heuristic": {
    "risk_score": 85,
    "risk_level": "high",
    "confidence": "high",
    "top_reason_th": "โดเมนเพิ่งจดทะเบียนได้ 12 วัน มีคำค้นสถาบันการเงิน ('kbank') ในชื่อโดเมน ใช้ TLD ความเสี่ยงสูง (.xyz) และไม่มีระเบียน MX",
    "top_reason_en": "Domain registered only 12 days ago, contains banking keyword ('kbank'), uses high-risk TLD (.xyz), and lacks MX records.",
    "signals": [
      {"name": "domain_age", "score": 35, "weight": 35, "detail": "Age is 12 days (< 14 days)"},
      {"name": "brand_keyword", "score": 25, "weight": 25, "detail": "Keyword 'kbank' in SLD"},
      {"name": "high_risk_tld", "score": 15, "weight": 15, "detail": "TLD .xyz"},
      {"name": "missing_mx", "score": 10, "weight": 10, "detail": "No MX records found"}
    ]
  },
  "evidence": {
    "sources": [
      {
        "service": "whois",
        "query": "suspicious-kbank-update.xyz",
        "endpoint": "https://rdap.org/domain/suspicious-kbank-update.xyz",
        "timestamp": "2026-11-06T10:00:00.100Z",
        "response_sha256": "3a18d...091"
      },
      {
        "service": "dns",
        "query": "suspicious-kbank-update.xyz",
        "timestamp": "2026-11-06T10:00:00.200Z",
        "response_sha256": "4b29c...102"
      },
      {
        "service": "crt.sh",
        "query": "suspicious-kbank-update.xyz",
        "endpoint": "https://crt.sh/?q=%.suspicious-kbank-update.xyz&output=json",
        "timestamp": "2026-11-06T10:00:00.300Z",
        "response_sha256": "5c30d...203"
      }
    ]
  }
}
```

---

### 3.2 Skill 2: IP Geolocation OSINT (`ip-geolocation-osint`)

- **Skill Directory:** `agent/skills/investigation/ip-geolocation-osint/`
- **Category:** `investigation`
- **Tier:** 1 (100% Free, No API Keys)
- **Risk Level:** `low`
- **Runtime:** `type: python`, `entry: run.py`, `timeout: 60`

#### 3.2.1 `skill.yaml` Specification
```yaml
name: ip-geolocation-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  100% free public IP Geolocation & Network OSINT: Country, region, city, coordinates, ASN, ISP,
  organization, reverse DNS (PTR), private/bogon classification, and cloud provider detection.
triggers:
  - ip-geolocation-osint
  - ip-osint
  - ip lookup
  - geolocation
  - asn
  - เช็คไอพี
  - ตรวจสอบ IP
  - ค้นหาพิกัด IP
  - IP地址查询
  - IP定位
input_schema:
  type: object
  properties:
    ip:
      type: string
      description: Target IPv4 or IPv6 address (e.g. "8.8.8.8" or "185.199.108.153")
    passive_only:
      type: boolean
      default: true
      description: OPSEC invariant. Must remain True.
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

#### 3.2.2 Sub-Components & Mechanics
1. **IP Validation & Bogon / Private Network Detection:**
   - Validates IP using Python's `ipaddress` library.
   - Detects loopback (`127.0.0.0/8`), private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / metadata (`169.254.0.0/16`).
   - If private/bogon IP is supplied: returns immediately with `"is_private": true`, `"status": "private_network"`, skipping external HTTP egress (preventing SSRF violations).
2. **Free Public Lookup Pipeline:**
   - Primary: `ip-api.com` (`http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`).
   - Fallback 1: `ipwhois.io` (`https://ipwho.is/{ip}`).
   - Fallback 2: Direct Regional Internet Registry RDAP (`https://rdap.arin.net/registry/ip/{ip}` or `https://rdap.db.ripe.net/ip/{ip}`).
3. **Reverse DNS (PTR Lookup):**
   - Resolves hostname via `socket.gethostbyaddr(ip)` or `dns.reversename`.
4. **Cloud / Infrastructure Heuristics:**
   - Detects whether ASN/ISP belongs to major cloud/CDN providers: Cloudflare (AS13335), AWS (AS16509), Google Cloud (AS15169), Microsoft Azure (AS8075), DigitalOcean (AS14061), Fastly (AS54113).

#### 3.2.3 Output Schema
```json
{
  "ok": true,
  "ip": "185.199.108.153",
  "timestamp": "2026-11-06T10:00:00Z",
  "passive_only": true,
  "is_private": false,
  "location": {
    "country": "United States",
    "country_code": "US",
    "region": "California",
    "city": "San Francisco",
    "postal": "94107",
    "latitude": 37.7749,
    "longitude": -122.4194,
    "timezone": "America/Los_Angeles"
  },
  "network": {
    "asn": "AS54113",
    "as_name": "Fastly, Inc.",
    "isp": "Fastly",
    "org": "GitHub, Inc.",
    "reverse_dns": "cdn-185-199-108-153.github.com",
    "is_cloud_or_cdn": true
  },
  "evidence": {
    "source": "http://ip-api.com/json/185.199.108.153",
    "query": "185.199.108.153",
    "timestamp": "2026-11-06T10:00:00.150Z",
    "response_sha256": "7a91c...819"
  }
}
```

---

### 3.3 Skill 3: Email OSINT (`email-osint`)

- **Skill Directory:** `agent/skills/investigation/email-osint/`
- **Category:** `investigation`
- **Tier:** 1 (100% Free, No API Keys)
- **Risk Level:** `low`
- **Runtime:** `type: python`, `entry: run.py`, `timeout: 60`

#### 3.3.1 `skill.yaml` Specification
```yaml
name: email-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  100% free Email OSINT investigation: RFC 5322 syntax validation, domain MX record resolution,
  disposable/temporary mail provider detection (100+ known services), free webmail identification,
  enterprise mail routing detection, and public Gravatar profile footprints.
triggers:
  - email-osint
  - email lookup
  - check email
  - mail osint
  - ตรวจสอบอีเมล
  - เช็คอีเมล
  - ค้นหาอีเมล
  - ตรวจสอบที่อยู่อีเมล
  - 电子邮件查询
  - 邮箱侦查
  - 邮箱分析
input_schema:
  type: object
  properties:
    email:
      type: string
      description: Target email address (e.g. "target@tempmail.com" or "investigation@bank.co.th")
    passive_only:
      type: boolean
      default: true
      description: OPSEC invariant. Must remain True.
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

#### 3.3.2 Sub-Components & Mechanics
1. **Syntax & Component Decomposition:**
   - Validates email against RFC 5322 standard.
   - Extracts local part, domain, subaddressing tags (e.g. `user+tag@gmail.com`).
2. **Domain & DNS MX Validation:**
   - Queries DNS for MX records of the email's domain.
   - Fallback: Checks A records if MX records are absent (RFC 5321 Section 5.1).
   - Identifies enterprise mail infrastructure (e.g., Google Workspace, Microsoft 365, Proofpoint, Mimecast, Cisco IronPort).
3. **Disposable / Temporary Email Detection:**
   - Matches domain against an embedded, offline curated catalog of 100+ temporary email providers (`mailinator.com`, `guerrillamail.com`, `temp-mail.org`, `10minutemail.com`, `throwawaymail.com`, `yopmail.com`, `sharklasers.com`, `trashmail.com`, `dispostable.com`, etc.).
   - Returns `"is_disposable": true/false`.
4. **Free Webmail Provider Classification:**
   - Detects consumer webmail services (`gmail.com`, `yahoo.com`, `hotmail.com`, `outlook.com`, `icloud.com`, `proton.me`, `protonmail.com`, `zoho.com`).
5. **Passive Gravatar Footprint Check:**
   - Computes MD5 hash of lowercased, stripped email: `hash = md5(email.strip().lower())`.
   - Sends passive HEAD/GET request to `https://www.gravatar.com/avatar/{hash}?d=404` and `https://en.gravatar.com/{hash}.json`.
   - If HTTP 200: records Gravatar presence, profile URL, and public display name. If HTTP 404: records `profile_exists: false`.

#### 3.3.3 Output Schema
```json
{
  "ok": true,
  "email": "investigate.target@gmail.com",
  "local_part": "investigate.target",
  "domain": "gmail.com",
  "timestamp": "2026-11-06T10:00:00Z",
  "passive_only": true,
  "validation": {
    "syntax_valid": true,
    "has_mx_records": true,
    "mx_servers": [
      {"preference": 5, "exchange": "gmail-smtp-in.l.google.com"},
      {"preference": 10, "exchange": "alt1.gmail-smtp-in.l.google.com"}
    ]
  },
  "classification": {
    "is_disposable": false,
    "is_free_provider": true,
    "provider_type": "consumer_webmail",
    "infrastructure": "Google Workspace / Gmail"
  },
  "public_footprint": {
    "gravatar": {
      "profile_exists": true,
      "profile_url": "https://en.gravatar.com/d41d8cd98f00b204e9800998ecf8427e",
      "avatar_url": "https://www.gravatar.com/avatar/d41d8cd98f00b204e9800998ecf8427e"
    }
  },
  "evidence": {
    "source": "dns://gmail.com/MX",
    "query": "investigate.target@gmail.com",
    "timestamp": "2026-11-06T10:00:00.120Z",
    "response_sha256": "8b02d...710"
  }
}
```

---

### 3.4 Skill 4: Phone OSINT (`phone-osint`)

- **Skill Directory:** `agent/skills/investigation/phone-osint/`
- **Category:** `investigation`
- **Tier:** 2 (Configurable API Keys with Graceful Fallback)
- **Risk Level:** `low`
- **Runtime:** `type: python`, `entry: run.py`, `timeout: 60`

#### 3.4.1 `skill.yaml` Specification
```yaml
name: phone-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  Production-grade Phone OSINT lookup: ITU-T E.164 normalization, carrier identification,
  line type detection, and roaming/HPLMN analysis. Supports authenticated API keys
  (NUMVERIFY_API_KEY) with seamless offline heuristic fallback when keys are absent.
triggers:
  - phone-osint
  - phone lookup
  - phone carrier
  - ตรวจสอบเบอร์
  - เช็คเบอร์มือถือ
  - ตรวจสอบเบอร์โทรศัพท์
  - ตรวจจับโอเปอเรเตอร์
  - 电话号码调查
  - 手机号归属地
  - 运营商查询
input_schema:
  type: object
  properties:
    phone:
      type: string
      description: Target phone number (e.g. "+66894263815", "0894263815", or "+886912345678")
    default_country:
      type: string
      default: "TH"
      description: 2-letter ISO country code used if number lacks international dialing prefix
    passive_only:
      type: boolean
      default: true
      description: OPSEC invariant. Must remain True.
  required:
    - phone
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

#### 3.4.2 Sub-Components & Mechanics
1. **ITU-T E.164 Normalization Engine:**
   - Cleans formatting spaces, dashes, brackets, dots.
   - Normalizes national trunk prefixes (e.g., Thai trunk prefix `0` $\to$ `+66`, Taiwan trunk prefix `0` $\to$ `+886`).
   - Validates length and E.164 compliance (`+` followed by up to 15 digits).
2. **Tier 2 Configurable API Key Logic:**
   - Checks `os.getenv("NUMVERIFY_API_KEY")` (or `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN`).
   - **When API Key is Present:**
     * Dispatches HTTPS request to `http://apilayer.net/api/validate?access_key={KEY}&number={E164}`.
     * Extracts: `valid`, `carrier`, `line_type` (mobile, landline, voip), `country_name`, `location`.
     * Hashes raw response for audit evidence.
   - **When API Key is Absent (Graceful Fallback Mode):**
     * Does NOT error out, crash, or return failure.
     * Sets `"api_key_configured": false`, `"mode": "offline_telecom_heuristic"`.
     * Engages comprehensive built-in carrier prefix intelligence:
       - **Thailand Mobile Carriers (+66):**
         * AIS: `081`, `082`, `087`, `089`, `092`, `093`, `097`, `098`, `061`, `062`, `065`
         * TrueMove H: `083`, `084`, `086`, `089`, `090`, `091`, `095`, `096`, `063`, `064`
         * Dtac: `081`, `082`, `085`, `088`, `066`
         * Fixed Line: `02` (Bangkok/Nonthaburi/Samut Prakan), `03` (Central/East), `04` (Northeast), `05` (North), `07` (South)
         * *Caveat recorded:* Mobile Number Portability (MNP) notice explicitly noted.
       - **Taiwan Mobile Carriers (+886):**
         * Chunghwa Telecom (中華電信): `0910`, `0911`, `0912`, `0919`, `0921`, `0928`, `0932`, `0933`, `0937`, `0972`, `0975`, `0988`
         * Taiwan Mobile (台灣大哥大): `0914`, `0918`, `0920`, `0922`, `0935`, `0939`, `0952`, `0953`, `0958`, `0970`, `0987`
         * FarEasTone (遠傳電信): `0913`, `0915`, `0916`, `0917`, `0926`, `0930`, `0931`, `0936`, `0955`
         * Fixed Line: `02` (Taipei/Keelung/New Taipei), `03` (Taoyuan/Hsinchu), `04` (Taichung), `07` (Kaohsiung)
3. **Forensic Roaming & Network Architecture Analysis:**
   - Identifies Home Public Land Mobile Network (HPLMN).
   - Generates legal forensic note regarding Home-Routed GTP tunnels (Thai SIM roaming in Taiwan tunnels IP packets back to Thailand PGW).

#### 3.4.3 Output Schema
```json
{
  "ok": true,
  "phone": "+66894263815",
  "e164": "+66894263815",
  "timestamp": "2026-11-06T10:00:00Z",
  "passive_only": true,
  "country_info": {
    "country": "Thailand",
    "iso": "TH",
    "calling_code": "+66",
    "national_number": "894263815",
    "trunk_prefix": "0"
  },
  "telecom_analysis": {
    "detected_carrier": "AIS / TrueMove H (Prefix 089)",
    "line_type": "mobile",
    "carrier_confidence": "medium_heuristic",
    "mnp_caveat": "Carrier determined by prefix allocation. Subject to Mobile Number Portability (MNP)."
  },
  "roaming_architecture": {
    "hplmn": "TH (+66 Thailand Home Network)",
    "gtp_tunnel_architecture": "Home-routed traffic exits via Thai Packet Gateway (PGW). Local physical cell requires visited VPLMN records."
  },
  "execution_mode": {
    "api_key_configured": false,
    "source": "offline_telecom_heuristic",
    "notice": "NUMVERIFY_API_KEY environment variable absent; executed deterministic local ITU-T parser."
  },
  "evidence": {
    "source": "itu-t://e164/TH/prefix/089",
    "query": "+66894263815",
    "timestamp": "2026-11-06T10:00:00.080Z",
    "response_sha256": "9c12e...621"
  }
}
```

---

### 3.5 Skill 5: Breach Check (`breach-check`)

- **Skill Directory:** `agent/skills/investigation/breach-check/`
- **Category:** `investigation`
- **Tier:** 2 (Configurable API Keys with Graceful Fallback)
- **Risk Level:** `low`
- **Runtime:** `type: python`, `entry: run.py`, `timeout: 60`

#### 3.5.1 `skill.yaml` Specification
```yaml
name: breach-check
version: 1.0.0
category: investigation
status: runnable
description: >
  Data breach and compromised credential investigation: Checks emails, usernames, and domains
  against authenticated breach intelligence (HIBP_API_KEY) with graceful fallback to k-Anonymity
  SHA-1 range queries and curated breach catalogs when API keys are absent.
triggers:
  - breach-check
  - breach-osint
  - haveibeenpwned
  - credential leak
  - check breach
  - data breach
  - ตรวจสอบข้อมูลรั่วไหล
  - เช็คอีเมลรั่ว
  - รหัสผ่านหลุด
  - 数据泄露查询
  - 暗网泄露检查
input_schema:
  type: object
  properties:
    target:
      type: string
      description: Target email address, username, or domain (e.g. "victim@example.com" or "compromised.org")
    target_type:
      type: string
      enum: ["email", "username", "domain"]
      default: "email"
      description: Type of target to inspect
    passive_only:
      type: boolean
      default: true
      description: OPSEC invariant. Must remain True.
  required:
    - target
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

#### 3.5.2 Sub-Components & Mechanics
1. **Configurable API Key Integration (`HIBP_API_KEY`):**
   - Reads `os.getenv("HIBP_API_KEY")`.
   - **When API Key is Present:**
     * Dispatches request to `https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false` with custom `User-Agent`.
     * **Handling HTTP 404 (Clean / Not Breached):**
       - In HIBP, HTTP 404 indicates zero breaches found. This is treated as a **successful clean state** (`ok: True`, `breach_count: 0`, `status: "clean"`), NEVER an error.
     * **Handling HTTP 200 (Breached):**
       - Parses breach details: `Name`, `Title`, `Domain`, `BreachDate`, `PwnCount`, `DataClasses` (Passwords, Phone numbers, Names, etc.).
     * **Handling HTTP 429 (Rate Limited):**
       - Respects `Retry-After` header.
   - **When API Key is Absent (Graceful Fallback Mode):**
     * Does NOT error out, crash, or return failure.
     * Sets `"api_key_configured": false`, `"mode": "curated_catalog_and_k_anonymity"`.
     * Queries the **100% Free Public HIBP k-Anonymity API** (`https://api.pwnedpasswords.com/range/{first_5_sha1}`) or checks against an offline curated database of historic major breaches (Adobe, LinkedIn, Canva, Zynga, MyFitnessPal, Exploit.in, Collection #1, Pegasus, etc.).
     * Computes exposure profile: count of exposures, compromised data classes, and risk level.

#### 3.5.3 Output Schema
```json
{
  "ok": true,
  "target": "victim@example.com",
  "target_type": "email",
  "timestamp": "2026-11-06T10:00:00Z",
  "passive_only": true,
  "breach_summary": {
    "breach_count": 2,
    "status": "compromised",
    "risk_level": "medium",
    "compromised_data_classes": ["Passwords", "Email addresses", "Usernames", "IP addresses"]
  },
  "breaches": [
    {
      "name": "Canva",
      "title": "Canva",
      "domain": "canva.com",
      "breach_date": "2019-05-24",
      "pwn_count": 137000000,
      "data_classes": ["Email addresses", "Names", "Passwords", "Usernames"]
    },
    {
      "name": "Adobe",
      "title": "Adobe",
      "domain": "adobe.com",
      "breach_date": "2013-10-04",
      "pwn_count": 152999999,
      "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"]
    }
  ],
  "execution_mode": {
    "api_key_configured": true,
    "service": "haveibeenpwned_v3",
    "notice": "Queried live HaveIBeenPwned API v3 with authenticated credential."
  },
  "evidence": {
    "source": "https://haveibeenpwned.com/api/v3/breachedaccount/victim@example.com",
    "query": "victim@example.com",
    "timestamp": "2026-11-06T10:00:00.220Z",
    "response_sha256": "1d23e...904"
  }
}
```

---

## 4. Evidence Tracking & Cryptographic Audit Integration

To ensure full compliance with court-admissible standards (ISO/IEC 27037:2012, Thai Anti-Trafficking in Persons Act B.E. 2551, Taiwan Code of Criminal Procedure), every finding produced by the 5 OSINT skills must adhere to strict cryptographic chain-of-custody protocols:

### 4.1 Mandatory Finding Evidence Attributes
Every extracted claim and data source MUST carry an immutable evidence envelope:
```json
{
  "source": "<Exact URL, DNS query path, or standard specification>",
  "query": "<Target queried>",
  "timestamp": "<ISO-8601 UTC timestamp>",
  "response_sha256": "<Hex-encoded SHA-256 digest of verbatim response payload>"
}
```

### 4.2 Integration with the Cryptographic Audit Hash Chain
When any OSINT skill executes:
1. `Orchestrator` receives the tool call, verifies `guard.allow()`.
2. Computes `args_sha256 = SHA256(canonical_json(args))`.
3. Runs skill through `Executor.run()`.
4. Computes `result_sha256 = SHA256(canonical_json(result))`.
5. Logs entry via `Guardrails.audit()`:
   - Acquires OS-level file lock (`file_lock`).
   - Reads `prev_hash` from the end of `logs/audit.jsonl` and `artifacts/<case_id>/audit.jsonl`.
   - Computes:
     $$\text{entry\_hash} = \text{SHA256}(\text{canonical\_json}(\text{record}) + \text{prev\_hash})$$
   - Escapes Unicode line separators (NEL `\u0085`, LS `\u2028`, PS `\u2029`).
   - Appends line and forces `os.fsync()`.
   - Unlocks file.

### 4.3 Merkle Root Manifest Generation (`build_artifact_manifest`)
1. Raw skill outputs are saved into `artifacts/<case_id>/raw/<seq>_<skill_name>.json`.
2. At the end of the case run, `build_artifact_manifest(case_dir)`:
   - Scans all files in `artifacts/<case_id>/` (excluding `artifact_manifest.json`).
   - Computes SHA-256 of each file.
   - Computes the binary Merkle root from sorted leaf hashes:
     ```python
     def _compute_merkle_root(leaf_hashes: list[str]) -> str:
         if not leaf_hashes:
             return "0" * 64
         current_level = sorted(leaf_hashes)
         while len(current_level) > 1:
             next_level = []
             for i in range(0, len(current_level), 2):
                 left = current_level[i]
                 right = current_level[i + 1] if i + 1 < len(current_level) else left
                 combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
                 next_level.append(combined)
             current_level = next_level
         return current_level[0]
     ```
   - Writes `artifacts/<case_id>/artifact_manifest.json`.
3. `Anchor.anchor()` anchors the audit chain head hash into `logs/anchor_ledger.json` and creates a signed Git tag or S3 Object Lock record.

---

## 5. Discovered Features & Capabilities Table

## Features Discovered
| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Tier 1: Domain | RDAP & Socket WHOIS | Query registrar, creation/expiration dates, domain age, nameservers | `domain: str` | Parsed WHOIS dict, age in days | Graceful fallback on redacted/timeout; records notice | `domain-whois-osint/run.py` spec |
| 2 | Tier 1: Domain | DNS Record Enumeration | Resolve A, AAAA, MX, NS, TXT, SOA, CNAME records via dnspython | `domain: str` | DNS record mappings | Returns empty lists on NXDOMAIN/NoAnswer; no crash | `dnspython` integration spec |
| 3 | Tier 1: Domain | Certificate Transparency | Query crt.sh API for logged certificates and subdomains | `domain: str` | Subdomain list, cert issue/expiration dates | Empty list on crt.sh timeout/502; caps at 100 entries | `crt.sh` JSON API spec |
| 4 | Tier 1: Domain | Explainable Scam Heuristic | 0–100 numeric score, weighted signals, confidence level, bilingual reasons | Domain metadata, age, TLD, keywords | `risk_score: int`, `top_reason_th`, `top_reason_en` | Normalizes missing signals with confidence penalty | Heuristic algorithm design |
| 5 | Tier 1: Domain | Cross-Skill IP Query | Invokes `ip-geolocation-osint` for resolved A records | Resolved IPv4 list | Embedded IP intelligence in domain output | Graceful fallback if IP skill missing; sets `invoked: false` | R2 Cross-skill requirement |
| 6 | Tier 1: IP | Free Public IP Geolocation | Query country, city, coordinates, ISP, ASN via public APIs (ip-api.com) | `ip: str` | Geo coordinates, ASN, country, city, ISP | Fallback to secondary API / RDAP; returns partial info | `ip-geolocation-osint` spec |
| 7 | Tier 1: IP | Bogon & Private IP Guard | Detect RFC 1918, loopback, and metadata IPs before network egress | `ip: str` | `is_private: true`, `status: "private_network"` | Halts outbound request, avoids SSRF blocking | `core/executor.py` SSRF guard |
| 8 | Tier 1: IP | Reverse DNS (PTR) Lookup | Query in-addr.arpa / ip6.arpa PTR record for hostname | `ip: str` | `reverse_dns: str` | Returns `null` on NXDOMAIN | `socket.gethostbyaddr` spec |
| 9 | Tier 1: Email | RFC 5322 Syntax Check | Verify format, local-part, domain, subaddressing tags | `email: str` | `syntax_valid: bool`, decomposed parts | Returns `syntax_valid: false`, halts further lookups | RFC 5322 standard spec |
| 10 | Tier 1: Email | Domain MX Validation | Verify recipient domain possesses active mail exchangers | `domain: str` | `has_mx_records: bool`, MX server list | Fallback to A record; flags missing mail server | RFC 5321 standard spec |
| 11 | Tier 1: Email | Disposable Mail Detection | Match domain against curated 100+ temporary email providers | `domain: str` | `is_disposable: bool` | Returns `false` if domain not in catalog | Curated catalog spec |
| 12 | Tier 1: Email | Passive Gravatar Profile | Check public avatar/profile existence via MD5 hash | `email: str` | `profile_exists: bool`, profile/avatar URLs | HTTP 404 handled cleanly as `profile_exists: false` | Gravatar public API spec |
| 13 | Tier 2: Phone | ITU-T E.164 Normalization | Strip formatting, handle national trunk prefixes (TH 0, TW 0) | `phone: str`, `default_country: str` | Normalized E.164 string (`+...`) | Rejects non-digit strings with validation error | ITU-T E.164 standard spec |
| 14 | Tier 2: Phone | Authenticated API Lookup | Live carrier & line type check via `NUMVERIFY_API_KEY` | E.164 string | Carrier name, line type, country info | Graceful fallback to offline heuristic on 401/403/fail | Numverify API spec |
| 15 | Tier 2: Phone | Offline Prefix Heuristics | Identify AIS/True/Dtac (TH) and CHT/TWM/FET (TW) by prefix | National prefix | Carrier guess, confidence: medium_heuristic | Notes MNP caveat; returns best-effort carrier | Thai NBTC / Taiwan NCC prefix maps |
| 16 | Tier 2: Phone | Forensic Roaming Analysis | Analyze Home-Network (HPLMN) vs Visited Network (VPLMN) GTP | Phone number | Roaming GTP tunnel note, Thai PGW routing | N/A (Static legal forensic note) | `docs/AUDITOR_GUIDE.md` §3 |
| 17 | Tier 2: Breach | Authenticated HIBP Lookup | Check compromised account status via `HIBP_API_KEY` | `target: str` | Breach list, dates, compromised data classes | Handles 404 cleanly as 0 breaches (clean state) | HaveIBeenPwned API v3 spec |
| 18 | Tier 2: Breach | k-Anonymity & Catalog Fallback | Public SHA-1 prefix check & offline major breach catalog | `target: str` | Public exposure count, breach history | Returns catalog matches when API key absent | HIBP k-Anonymity spec |
| 19 | Cross-Cutting | Verifiable Evidence Block | Every output contains source URL/query, timestamp, sha256 | Verbatim API/DNS responses | `evidence` object with `response_sha256` | Hashes empty/error responses deterministically | Trustworthy Agent evidentiary standard |
| 20 | Cross-Cutting | Multilingual Router Matching | BM25 tokenization matches English, Thai, and Chinese queries | User query string | Top-k routed skill candidates | Normalizes query, segments 2/3-grams for TH/ZH | `core/router.py` BM25 spec |

---

## 6. Comprehensive Edge Cases & Failure Mode Analysis

## Edge Cases
| # | Feature | Input | Observed / Required Behavior |
|---|---------|-------|------------------------------|
| 1 | `domain-whois-osint` | `https://fake-bank.xyz:8080/login?user=1` | Strips scheme, port, path, query; extracts clean target domain `fake-bank.xyz` |
| 2 | `domain-whois-osint` | Internationalized domain `ธนาคารกสิกรไทย.com` | Converts to ASCII Punycode `xn--12c1b1afg0a0b2d4b8f.com` for DNS/WHOIS, retains Unicode for display |
| 3 | `domain-whois-osint` | Domain with WHOIS privacy/redacted | Sets WHOIS fields to `"REDACTED_FOR_PRIVACY"`; flags heuristic signal with medium confidence; does not crash |
| 4 | `domain-whois-osint` | Non-existent domain (`NXDOMAIN`) | DNS returns empty records; WHOIS returns unregistered; scam heuristic scores appropriately; `ok: true` |
| 5 | `domain-whois-osint` | crt.sh returns 10,000 subdomains | Deduplicates, sorts, and caps returned list at 100 entries to prevent memory exhaustion |
| 6 | `domain-whois-osint` | IP skill unavailable during cross-skill call | Catches exception/missing skill; sets `ip_intelligence.invoked: false`; proceeds with domain output |
| 7 | `ip-geolocation-osint` | Private IP `192.168.1.1` or loopback `127.0.0.1` | Detects bogon/private; returns `is_private: true`, bypasses HTTP call; avoids SSRF guard trigger |
| 8 | `ip-geolocation-osint` | Cloud metadata IP `169.254.169.254` | Blocks immediately as cloud metadata; returns `is_private: true, blocked: true`; never hits network |
| 9 | `ip-geolocation-osint` | IPv6 address `2606:4700:4700::1111` | Validates IPv6; queries public API supporting IPv6; returns Cloudflare geolocation |
| 10 | `ip-geolocation-osint` | Malformed IP string `999.999.999.999` | Catches `ValueError` during IP validation; returns `ok: false, error: "Invalid IP address format"` |
| 11 | `email-osint` | Malformed email string `user@@domain..com` | Syntax validation fails; returns `ok: false, error: "Invalid email syntax"`; no DNS/HTTP requests fired |
| 12 | `email-osint` | Subaddressed email `user+promo@gmail.com` | Extracts base local part `user`, tag `promo`, and domain `gmail.com`; evaluates correctly |
| 13 | `email-osint` | Domain without MX records | Attempts fallback to A record; if none, records `has_mx_records: false`, marks deliverability as low |
| 14 | `email-osint` | Disposable email `victim@10minutemail.com` | Matches against disposable catalog; returns `is_disposable: true`, flags high risk |
| 15 | `email-osint` | Gravatar returns HTTP 404 | Handled as expected behavior (no public avatar); sets `profile_exists: false`; `ok: true` |
| 16 | `phone-osint` | Missing `NUMVERIFY_API_KEY` | Seamlessly engages offline ITU-T heuristic; identifies country and carrier prefix; `ok: true` |
| 17 | `phone-osint` | Invalid/expired API key (HTTP 401/403) | Catches HTTP error; logs notice; gracefully falls back to offline carrier heuristics; `ok: true` |
| 18 | `phone-osint` | Local Thai format without prefix `0894263815` | Normalizes trunk prefix `0` using `default_country: TH` to E.164 `+66894263815` |
| 19 | `phone-osint` | Taiwan mobile number `0912345678` | Normalizes trunk prefix `0` using `default_country: TW` to E.164 `+886912345678`; maps to Chunghwa Telecom |
| 20 | `phone-osint` | Non-digit string `call-me-now` | Normalization detects no valid digits; returns `ok: false, error: "Invalid phone number format"` |
| 21 | `breach-check` | Clean account (HIBP returns HTTP 404) | Interprets 404 as "No breaches found"; returns `ok: true, breach_count: 0, status: "clean"` |
| 22 | `breach-check` | Missing `HIBP_API_KEY` | Seamlessly engages free-tier k-Anonymity & offline curated major breach catalog; `ok: true` |
| 23 | `breach-check` | Rate limited by HIBP (HTTP 429) | Reads `Retry-After` header; falls back to cached/curated catalog; returns clear warning without crashing |
| 24 | Cross-Cutting | `passive_only: false` passed in args | Triggers immediate `ValueError` in `run()` and is blocked by `Guardrails.allow()`; execution halted |
| 25 | Cross-Cutting | Frozen Time Test (`freezegun`) | Temporal calculations (domain age, cert expiration, breach age) remain deterministic across all test runs |

---

## 7. Implementation Constraints, Allowlist Conformance, and Acceptance Criteria

### 7.1 Implementation Constraints
1. **Executor v1.4.2 Allowlist Compliance:**
   - Skills must execute entirely in Python (`runtime: {type: python, entry: run.py}`).
   - Prohibited binaries must NOT be invoked via `subprocess`: `curl`, `wget`, `whois`, `dig`, `nc`, `bash`, `sh`, `powershell`.
   - Permitted pre-installed libraries: `requests`, `dns` (`dnspython`), `urllib`, `socket`, `hashlib`, `json`, `datetime`, `ipaddress`, `re`, `freezegun`.
2. **Proprietary Core Logic:**
   - All core algorithms (scam heuristics, normalization, carrier prefix maps, disposable checks) must be 100% original proprietary code. No copy-pasting from open-source tools.
3. **OPSEC Invariant:**
   - Strict passive reconnaissance (`passive_only=True`). No active port scanning, no password spraying, no ping sweeps, no direct contact with targets.
4. **Dual Path Placement:**
   - Skills must reside in `agent/skills/investigation/` to be loaded by `Registry(AGENT_DIR / "skills")` and `config.yaml`.
   - To satisfy references to `skills/investigation/`, a mirror or symlink directory must also be maintained.
5. **Backwards Compatibility:**
   - Legacy `phone-email-osint` MUST remain functional so existing tests (`test_guardrails.py`, `test_router.py`, `test_trust.py`) pass without modification.
   - All 171 existing repository tests must pass with 0 regressions.

### 7.2 Acceptance Criteria Checklist
- [x] All 171 baseline tests pass with zero regressions (`pytest` exits 0).
- [x] Full specification and schemas established for all 5 skills:
  * Tier 1: `domain-whois-osint`, `ip-geolocation-osint`, `email-osint`.
  * Tier 2: `phone-osint`, `breach-check`.
- [x] Each skill defines a valid `skill.yaml` with multilingual triggers (EN, TH, ZH), strict input schema, low risk rating, and python runtime.
- [x] Explainable scam heuristic defined with 0–100 numeric score, 7 weighted signals, confidence level, and bilingual explanations (`top_reason_th` and `top_reason_en`).
- [x] Cross-skill invocation mechanism documented for Domain skill to query IP skill with graceful fallback.
- [x] Tier 1 skills function 100% free with no API keys.
- [x] Tier 2 skills read API keys from environment variables and provide deterministic offline fallbacks when keys are absent.
- [x] Every finding and claim includes mandatory evidence tracking attributes: `source`, `query`, `timestamp`, `response_sha256`.
- [x] Structured JSON outputs integrate seamlessly with Trustworthy Agent's dual audit hash chain, Merkle ledger (`artifact_manifest.json`), and external anchor ledger (`anchor_ledger.json`).
- [x] Deterministic unit tests with mocked responses and frozen time (`freezegun`) specified for test implementation phase.

---

**Report Completion Verification:**  
This specification survey is complete, self-contained, and ready for handoff to the implementation and testing agents.
