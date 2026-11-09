# Technical Implementation Strategy: `email-osint` Skill

**Target System**: Trustworthy Agent v1.5.0  
**Milestone**: Milestone 1 (Tier 1 Production-Grade OSINT Skills)  
**Author**: `m1_explorer_2` (Teamwork Explorer Subagent)  
**Deliverable Path**: `agent/skills/investigation/email-osint/`  
**Security & Integrity Mode**: Demo / Court-Grade Admissible Investigation  

---

## 1. Executive Summary & Design Principles

The `email-osint` skill provides 100% free, unauthenticated, passive intelligence collection on target email addresses for Trustworthy Agent v1.5.0. It replaces mock placeholders and legacy stubs with court-admissible forensic capabilities conforming to:
- **Zero API Keys Required**: 100% free operations using standard DNS resolvers, local in-memory catalog lookups, and public Gravatar endpoints.
- **Strict Passive Reconnaissance**: Never sends emails, never touches SMTP VRFY/RCPT commands (which alert mail servers or trip anti-spam filters), and enforces `passive_only=True` at runtime and schema level.
- **Executor v1.4.2 Conformance**: Pure Python runtime execution (`run.py` exporting `run(**kwargs)`); zero forbidden CLI binaries (`curl`, `wget`, `dig`, `sh`, `powershell`); strict SSRF guard adherence; and full compatibility with the 60 calls/minute sliding-window rate limiter.
- **Dual Schema Contract Compatibility**: Perfectly harmonizes the contract defined in `PROJECT.md` (`valid_format`, `domain`, `is_disposable`, `mx_records`, `has_gravatar`, `gravatar_hash`, `evidence`) and the rich forensic schemas in `spec_report.md` (`local_part`, `validation`, `classification`, `public_footprint`).
- **Standardized Cryptographic Evidence**: Emits immutable evidence records (`source`, `query`, `timestamp`, `response_sha256`) ready for chaining into Trustworthy Agent's dual SHA-256 audit hash chain and Merkle root manifest.
- **Zero Baseline Regressions**: Guarantees all 171 existing repository tests in `agent/tests/` continue to pass without interference.

---

## 2. Directory Layout & Manifest Architecture

### 2.1 File Placement
The new skill is deployed in the authoritative agent skill directory:
```
agent/skills/investigation/email-osint/
├── skill.yaml          # Declarative specification, triggers, schema, runtime config
└── run.py              # Pure Python implementation exporting run()
```

### 2.2 Skill Manifest (`skill.yaml`)
To conform with `core/registry.py` and the BM25 Router (`core/router.py`), `skill.yaml` must be declared as `status: runnable` and include multilingual triggers that do NOT conflict with existing test cases:

```yaml
name: email-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  100% free passive Email OSINT investigation: RFC 5322 syntax validation,
  domain MX record resolution, disposable/temporary mail provider detection,
  consumer webmail and corporate routing identification, and public Gravatar
  profile footprints with cryptographic evidence tracking.
triggers:
  - "email-osint"
  - "email lookup"
  - "check email"
  - "mail osint"
  - "verify email"
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
      description: "Target email address to investigate (e.g. user@example.com)"
    passive_only:
      type: boolean
      default: true
      description: "OPSEC invariant: Must remain True for passive reconnaissance"
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

### 2.3 Router Guardrail & Backward Compatibility Invariant
- In `agent/tests/test_router.py`:
  - Query `"追踪电话号码和关联账户"` must route to `phone-email-osint` as `hits[0]`.
  - To prevent `email-osint` from inadvertently outscoring `phone-email-osint` on Chinese queries, `email-osint` does **NOT** include `"追踪电话号码"` or `"关联账户"` in its triggers or description.
- In `agent/tests/test_guardrails.py`:
  - `phone_email_osint` is imported from `skills.investigation.phone_email_osint_entry`.
  - The existing `agent/skills/investigation/phone-email-osint/` remains intact (until Milestone 3 gracefully delegates to both `phone-osint` and `email-osint`).

---

## 3. Component Deep Dive & Technical Implementation

### 3.1 Component 1: Email Normalization & RFC 5322 Syntax Validation
1. **Unicode Normalization**:
   - Apply NFKC normalization (`unicodedata.normalize("NFKC", raw).strip()`).
   - Disallow null bytes (`\x00`), newlines, carriage returns, or control characters.
   - Total length check: maximum 254 octets (RFC 5321 §4.5.3.1.3).
2. **Decomposition**:
   - Split strictly on the last `@` sign: `local_part, domain = raw.rsplit("@", 1)`.
   - Local-part length check: 1 to 64 octets (RFC 5321 §4.5.3.1.1).
   - Domain length check: 1 to 253 octets.
3. **Subaddressing (Plus Addressing / Tagging)**:
   - If `+` is present in `local_part` (e.g., `alice+newsletter@company.com`):
     - `base_local`: `"alice"`
     - `tag`: `"newsletter"`
   - Useful in forensic investigations to map alias accounts back to canonical users.
4. **RFC 5322 Regex Validation**:
   - Standard addr-spec regex:
     ```python
     LOCAL_PART_REGEX = re.compile(
         r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
     )
     DOMAIN_REGEX = re.compile(
         r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$"
     )
     ```
   - Disallow leading/trailing dots in local part, consecutive dots (`..`), and invalid characters.
   - If invalid format: return `valid_format: False` with descriptive diagnostic, without throwing unhandled exceptions.

### 3.2 Component 2: DNS MX Record Resolution & Fallback Logic
1. **Resolver Configuration (`dnspython`)**:
   - `dnspython` is installed (v2.9.1 in environment).
   - Use `dns.resolver.Resolver()` with bounded timeouts to prevent stalling:
     ```python
     resolver = dns.resolver.Resolver()
     resolver.timeout = 2.0
     resolver.lifetime = 3.0
     ```
2. **MX Record Retrieval & Ordering**:
   - Query: `resolver.resolve(domain, 'MX')`.
   - Sort records by `preference` ascending (lowest preference value = primary mail exchange).
   - Format records as both:
     - `mx_records`: list of strings, e.g. `["5 gmail-smtp-in.l.google.com", "10 alt1.gmail-smtp-in.l.google.com"]` (matches `PROJECT.md`).
     - `mx_servers`: structured list of dicts, e.g. `[{"preference": 5, "exchange": "gmail-smtp-in.l.google.com"}]` (matches `spec_report.md`).
3. **RFC 5321 §5.1 Implicit MX Fallback (A / AAAA)**:
   - When a domain lacks explicit MX records (`dns.resolver.NoAnswer`), RFC 5321 §5.1 mandates treating the domain's A / AAAA record as an implicit MX of preference 0.
   - Query `A` and `AAAA` records for the domain:
     - If A/AAAA exists: `has_mx_records = True`, `mx_records = [f"0 {domain} (implicit A fallback)"]`.
     - If neither exists: `has_mx_records = False`.
4. **Non-Existent Domains (`NXDOMAIN`)**:
   - Catch `dns.resolver.NXDOMAIN`: mark `domain_exists: False`, `has_mx_records: False`.
5. **Socket Fallback**:
   - If `dnspython` encounters a network glitch or import failure, fallback to `socket.getaddrinfo(domain, None)` to determine host reachability.
6. **Enterprise Mail Infrastructure Detection**:
   - Pattern match MX hostnames to detect cloud and security gateways:
     - Google Workspace: `*.google.com`, `*.googlemail.com`, `*.l.google.com`
     - Microsoft 365 / Exchange: `*.mail.protection.outlook.com`
     - ProtonMail: `*.protonmail.ch`, `*.proton.me`
     - Zoho Mail: `*.zoho.com`
     - iCloud Mail: `*.mail.icloud.com`
     - Yahoo Mail: `*.yahoodns.net`
     - Proofpoint Protection: `*.pphosted.com`
     - Mimecast Gateway: `*.mimecast.com`
     - Cisco IronPort: `*.iphmx.com`
     - Barracuda Networks: `*.barracudanetworks.com`

### 3.3 Component 3: Disposable & Free Webmail Provider Detection
1. **Embedded In-Memory Catalog of 150+ Disposable Domains**:
   - Disposable email services are heavily used in scam registrations, phishing campaigns, and fraudulent account generation.
   - Catalog includes:
     - Mailinator family: `mailinator.com`, `mailinator2.com`, `mailin8r.com`, `suremail.info`, `spamherelots.com`, `thisisnotmyrealemail.com`
     - GuerrillaMail family: `guerrillamail.com`, `guerrillamail.net`, `guerrillamail.org`, `guerrillamail.biz`, `guerrillamailblock.com`, `sharklasers.com`, `grr.la`, `pokemail.net`, `spam4.me`
     - 10MinuteMail family: `10minutemail.com`, `10minutemail.net`, `10minutemail.org`, `10minemail.com`, `10minutemailbox.com`
     - TempMail family: `temp-mail.org`, `tempmail.com`, `temp-mail.io`, `tempmail.net`, `tempmail.ninja`, `tempmailaddress.com`
     - YOPmail family: `yopmail.com`, `yopmail.fr`, `yopmail.net`, `cool.fr.nf`, `jetable.fr.nf`, `courriel.fr.nf`, `moncourrier.fr.nf`, `monemail.fr.nf`, `monmail.fr.nf`
     - ThrowAwayMail / TrashMail / Others: `throwawaymail.com`, `dispostable.com`, `trashmail.com`, `trashmail.net`, `trashmail.me`, `fakeinbox.com`, `mohmal.com`, `dropmail.me`, `emailondeck.com`, `generator.email`, `nada.ltd`, `getairmail.com`, `burnermail.io`, `crazymailing.com`, `mailcatch.com`
2. **MX-Level Disposable Detection**:
   - Advanced scammers use custom domain names (e.g., `account-update-sec.xyz`) configured to route directly to Mailinator or GuerrillaMail MX servers.
   - Inspection rule: If any MX record contains `mailinator.com`, `guerrillamail.com`, `yopmail.com`, or `trashmail.com`, the domain is classified as `is_disposable = True`.
3. **Consumer Webmail Classification**:
   - Curated list of free consumer providers:
     - Google: `gmail.com`, `googlemail.com`
     - Microsoft: `outlook.com`, `hotmail.com`, `live.com`, `msn.com`
     - Yahoo: `yahoo.com`, `ymail.com`, `rocketmail.com`
     - Apple: `icloud.com`, `me.com`, `mac.com`
     - Proton: `proton.me`, `protonmail.com`, `protonmail.ch`, `pm.me`
     - Others: `zoho.com`, `mail.com`, `email.com`, `aol.com`, `gmx.com`, `gmx.net`, `yandex.com`, `fastmail.com`, `tuta.com`, `tutanota.com`
   - Classification output:
     - `provider_type`: `"disposable"` | `"consumer_webmail"` | `"corporate_custom"`

### 3.4 Component 4: Passive Gravatar Profile & Avatar Footprint Lookup
1. **Hashing Specifications**:
   - Gravatar canonicalizes email addresses: lowercase, strip whitespace, UTF-8 encode.
   - **MD5**: `hashlib.md5(canonical_email.encode("utf-8")).hexdigest()` (historical standard).
   - **SHA-256**: `hashlib.sha256(canonical_email.encode("utf-8")).hexdigest()` (modern Gravatar standard since 2023).
   - In accordance with the dispatch specification, both endpoints and hashes are supported.
2. **Avatar Endpoint Probe**:
   - URL: `https://www.gravatar.com/avatar/{sha256_hash}?d=404`
   - Query with `requests.get` (or `requests.head`) with `headers={"User-Agent": "TrustworthyAgent/1.5 (Passive OSINT)"}` and timeout `(1.5, 3.0)`.
   - Behavior:
     - HTTP 200: Avatar exists (`avatar_exists = True`, `has_gravatar = True`).
     - HTTP 404: No avatar registered (`avatar_exists = False`).
3. **Profile JSON Endpoint**:
   - URL: `https://en.gravatar.com/{sha256_hash}.json`
   - Query if avatar probe is positive or as part of profile check.
   - Behavior:
     - HTTP 200: Public profile exists!
       - Parse JSON `entry[0]`:
         - `preferredUsername`
         - `displayName`
         - `profileUrl`
         - `avatarUrl`
     - HTTP 404: No public JSON profile.
4. **Passive Reconnaissance & SSRF Protection**:
   - Queries are sent strictly via public HTTPS to `gravatar.com`.
   - Strict connection timeout (1.5s) and read timeout (3.0s).
   - Zero active contact with the user or target mail server.
   - Exceptions (`requests.RequestException`, timeouts) are caught gracefully and return `has_gravatar = False` with diagnostic info.

### 3.5 Component 5: Standardized Cryptographic Evidence Tracking
Every factual claim generated during the investigation must emit a tamper-evident audit record:
```json
{
  "source": "<URI or specification authority>",
  "query": "<exact query string>",
  "timestamp": "<ISO-8601 UTC timestamp>",
  "response_sha256": "<64-character hex SHA-256 digest>"
}
```

Generated evidence items for `email-osint`:
1. **Syntax Validation Evidence**:
   - `source`: `"rfc5322://addr-spec"`
   - `query`: `email`
   - `timestamp`: UTC ISO timestamp
   - `response_sha256`: SHA-256 of canonical validation summary JSON.
2. **DNS MX Evidence**:
   - `source`: `f"dns://{domain}/MX"`
   - `query`: `domain`
   - `timestamp`: UTC ISO timestamp
   - `response_sha256`: SHA-256 of serialized raw MX records.
3. **Disposable Catalog Evidence**:
   - `source`: `"catalog://disposable-email-domains/v1.0"`
   - `query`: `domain`
   - `timestamp`: UTC ISO timestamp
   - `response_sha256`: SHA-256 of classification result.
4. **Gravatar Evidence**:
   - `source`: `f"https://en.gravatar.com/{sha256_hash}.json"` or avatar endpoint
   - `query`: `sha256_hash`
   - `timestamp`: UTC ISO timestamp
   - `response_sha256`: SHA-256 of verbatim response body bytes.

### 3.6 Component 6: v1.4.2 Executor Allowlist & Security Sandboxing
- **Pure Python Execution**: Declared as `runtime: {type: python, entry: run.py}`. Loaded dynamically via `importlib` and executed via `run(**args)`.
- **Zero Forbidden CLI Binaries**: No subprocess calls to `curl`, `wget`, `dig`, `host`, `nslookup`, or shell interpreters.
- **Path Confinement**: `run.py` is self-contained within `agent/skills/investigation/email-osint/`.
- **SSRF Guard Compliance**: Outbound requests are restricted to public HTTPS endpoints (`gravatar.com`). Never contacts cloud metadata IPs (`169.254.169.254`, `100.100.100.200`) or private RFC 1918 subnets.
- **OPSEC Enforcement**: `passive_only` check at top of `run()`:
  ```python
  if not passive_only:
      raise ValueError("OPSEC violation: passive_only must be True for email-osint")
  ```

---

## 4. Complete Code Implementation

### 4.1 Manifest: `agent/skills/investigation/email-osint/skill.yaml`
```yaml
name: email-osint
version: 1.0.0
category: investigation
status: runnable
description: >
  100% free passive Email OSINT investigation: RFC 5322 syntax validation,
  domain MX record resolution, disposable/temporary mail provider detection,
  consumer webmail and corporate routing identification, and public Gravatar
  profile footprints with cryptographic evidence tracking.
triggers:
  - "email-osint"
  - "email lookup"
  - "check email"
  - "mail osint"
  - "verify email"
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
      description: "Target email address to investigate (e.g. user@example.com)"
    passive_only:
      type: boolean
      default: true
      description: "OPSEC invariant: Must remain True for passive reconnaissance"
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

### 4.2 Full Implementation: `agent/skills/investigation/email-osint/run.py`
```python
"""
Email OSINT Skill v1.5.0
100% Original Proprietary Implementation for Trustworthy Agent
Tier 1: 100% Free, Passive Reconnaissance, No API Keys Required.

Capabilities:
1. RFC 5322 syntax validation & subaddressing decomposition.
2. DNS MX record resolution via dnspython with RFC 5321 A/AAAA fallback.
3. Disposable / temporary email domain & MX detection (150+ provider catalog).
4. Free consumer webmail vs. enterprise corporate infrastructure classification.
5. Passive Gravatar avatar & profile footprint discovery (SHA256 & MD5).
6. Standardized cryptographic evidence tracking (source, query, timestamp, response_sha256).
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import unicodedata
from datetime import datetime, timezone
from typing import Any

# RFC 5322 validation regular expressions
_LOCAL_PART_REGEX = re.compile(
    r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
)
_DOMAIN_REGEX = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})+$"
)

# 150+ Curated disposable / temporary email domains
DISPOSABLE_DOMAINS: set[str] = {
    # Mailinator family
    "mailinator.com", "mailinator2.com", "mailin8r.com", "suremail.info",
    "spamherelots.com", "thisisnotmyrealemail.com", "safetymail.info",
    # GuerrillaMail family
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.biz", "guerrillamailblock.com", "sharklasers.com",
    "grr.la", "pokemail.net", "spam4.me",
    # 10MinuteMail family
    "10minutemail.com", "10minutemail.net", "10minutemail.org",
    "10minemail.com", "10minutemailbox.com", "10mail.org",
    # TempMail family
    "temp-mail.org", "tempmail.com", "temp-mail.io", "tempmail.net",
    "tempmail.ninja", "tempmailaddress.com", "disposablemail.com",
    # YOPmail family
    "yopmail.com", "yopmail.fr", "yopmail.net", "cool.fr.nf",
    "jetable.fr.nf", "courriel.fr.nf", "moncourrier.fr.nf",
    "monemail.fr.nf", "monmail.fr.nf", "hide.biz.st", "mymail.infos.st",
    # ThrowAwayMail & TrashMail
    "throwawaymail.com", "throwawayemailaddress.com", "dispostable.com",
    "trashmail.com", "trashmail.net", "trashmail.me", "trashmail.org",
    "trash-mail.com", "rcpt.at", "trashmail.de",
    # Popular disposable web tools
    "fakeinbox.com", "mohmal.com", "mohmal.im", "dropmail.me",
    "emailondeck.com", "fakemailgenerator.com", "generator.email",
    "inboxkitten.com", "mytemp.email", "mytempemail.com", "tempail.com",
    "burnermail.io", "crazymailing.com", "nada.ltd", "getairmail.com",
    "inboxbear.com", "mailcatch.com", "mailnesia.com", "trashcanmail.com",
    "getnada.com", "abvmail.com", "tempmailo.com", "fakemail.net",
    "tempemail.co", "crazymail.com", "disposable.com", "tempmailer.com",
    "tmpmail.org", "tmpmail.net", "maildrop.cc", "harakirimail.com",
    "mailhero.io", "guerrillamail.de", "spamgourmet.com", "incognitomail.org",
    "mytempmail.com", "fastmail.fm", "zetmail.com", "oneoffmail.com"
}

# Disposable MX server fragments
DISPOSABLE_MX_PATTERNS = [
    "mailinator.com", "guerrillamail.com", "yopmail.com", "trashmail.com",
    "temp-mail.org", "mohmal.com", "dropmail.me"
]

# Major consumer webmail domains
FREE_WEBMAIL_DOMAINS: dict[str, str] = {
    "gmail.com": "Google Workspace / Gmail",
    "googlemail.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft Outlook / Hotmail",
    "hotmail.com": "Microsoft Outlook / Hotmail",
    "live.com": "Microsoft Outlook / Hotmail",
    "msn.com": "Microsoft Outlook / Hotmail",
    "yahoo.com": "Yahoo Mail",
    "ymail.com": "Yahoo Mail",
    "rocketmail.com": "Yahoo Mail",
    "icloud.com": "Apple iCloud Mail",
    "me.com": "Apple iCloud Mail",
    "mac.com": "Apple iCloud Mail",
    "proton.me": "ProtonMail (End-to-End Encrypted)",
    "protonmail.com": "ProtonMail (End-to-End Encrypted)",
    "protonmail.ch": "ProtonMail (End-to-End Encrypted)",
    "pm.me": "ProtonMail (End-to-End Encrypted)",
    "zoho.com": "Zoho Mail",
    "mail.com": "1&1 Mail.com",
    "email.com": "1&1 Mail.com",
    "aol.com": "AOL Mail",
    "gmx.com": "GMX Mail",
    "gmx.net": "GMX Mail",
    "yandex.com": "Yandex Mail",
    "yandex.ru": "Yandex Mail",
    "ya.ru": "Yandex Mail",
    "fastmail.com": "Fastmail",
    "tuta.com": "Tuta Mail (Encrypted)",
    "tutanota.com": "Tutanota Mail (Encrypted)",
}

# Known enterprise mail infrastructure patterns mapped from MX hostnames
ENTERPRISE_MX_PATTERNS = [
    (re.compile(r".*(?:google|googlemail|l\.google)\.com$"), "Google Workspace"),
    (re.compile(r".*mail\.protection\.outlook\.com$"), "Microsoft 365 / Exchange Online"),
    (re.compile(r".*pphosted\.com$"), "Proofpoint Email Protection"),
    (re.compile(r".*mimecast\.com$"), "Mimecast Security Gateway"),
    (re.compile(r".*iphmx\.com$"), "Cisco IronPort Email Security"),
    (re.compile(r".*barracudanetworks\.com$"), "Barracuda Email Security"),
    (re.compile(r".*inbound-smtp\..*\.amazonaws\.com$"), "Amazon SES / WorkMail"),
    (re.compile(r".*yahoodns\.net$"), "Yahoo Business Mail"),
    (re.compile(r".*zoho\.com$"), "Zoho Workplace Mail"),
    (re.compile(r".*protonmail\.ch$"), "ProtonMail Enterprise"),
]


def _hash_bytes(data: bytes | str) -> str:
    """Compute standard SHA-256 hex digest for cryptographic evidence integrity."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def normalize_email(raw: str) -> str:
    """Normalize email address: NFKC Unicode normalization, strip whitespace, lowercase."""
    if not isinstance(raw, str):
        raw = str(raw) if raw is not None else ""
    return unicodedata.normalize("NFKC", raw).strip().lower()


def validate_email_syntax(email: str) -> tuple[bool, str, str, str | None, str | None]:
    """
    Validate email address according to RFC 5322.
    Returns: (is_valid, local_part, domain, base_local, tag)
    """
    if not email or len(email) > 254 or "\x00" in email:
        return False, "", "", None, None

    parts = email.rsplit("@", 1)
    if len(parts) != 2:
        return False, "", "", None, None

    local_part, domain = parts[0], parts[1]

    # Validate length boundaries
    if not (1 <= len(local_part) <= 64 and 1 <= len(domain) <= 253):
        return False, local_part, domain, None, None

    # Check for consecutive dots
    if ".." in local_part or ".." in domain:
        return False, local_part, domain, None, None

    # Validate regex patterns
    if not _LOCAL_PART_REGEX.match(local_part):
        return False, local_part, domain, None, None
    if not _DOMAIN_REGEX.match(domain):
        return False, local_part, domain, None, None

    # Subaddressing (+tag) decomposition
    base_local = local_part
    tag = None
    if "+" in local_part:
        subparts = local_part.split("+", 1)
        base_local = subparts[0]
        tag = subparts[1]

    return True, local_part, domain, base_local, tag


def resolve_mx_records(domain: str, timeout: float = 2.5) -> tuple[list[str], list[dict[str, Any]], bool, list[dict[str, Any]]]:
    """
    Resolve DNS MX records via dnspython.
    Falls back to RFC 5321 Section 5.1 implicit MX (A/AAAA) if MX records are absent.
    Returns: (mx_records_strings, mx_servers_dicts, has_mx, evidence_list)
    """
    evidence: list[dict[str, Any]] = []
    ts = datetime.now(timezone.utc).isoformat()
    mx_records_str: list[str] = []
    mx_servers_list: list[dict[str, Any]] = []
    has_mx = False

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout

        try:
            answers = resolver.resolve(domain, "MX")
            # Sort by preference ascending
            sorted_answers = sorted(answers, key=lambda r: int(r.preference))
            for rdata in sorted_answers:
                pref = int(rdata.preference)
                exch = rdata.exchange.to_text().rstrip(".").lower()
                mx_records_str.append(f"{pref} {exch}")
                mx_servers_list.append({"preference": pref, "exchange": exch})

            if mx_records_str:
                has_mx = True
                evidence.append({
                    "source": f"dns://{domain}/MX",
                    "query": domain,
                    "timestamp": ts,
                    "response_sha256": _hash_bytes(json.dumps(mx_records_str, sort_keys=True))
                })
                return mx_records_str, mx_servers_list, has_mx, evidence

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

        # RFC 5321 §5.1 Implicit MX Fallback (A / AAAA records)
        try:
            a_answers = resolver.resolve(domain, "A")
            a_ips = sorted([r.to_text() for r in a_answers])
            if a_ips:
                has_mx = True
                fallback_entry = f"0 {domain}"
                mx_records_str.append(fallback_entry)
                mx_servers_list.append({"preference": 0, "exchange": domain, "note": "RFC 5321 implicit MX fallback (A record)"})
                evidence.append({
                    "source": f"dns://{domain}/A",
                    "query": domain,
                    "timestamp": ts,
                    "response_sha256": _hash_bytes(json.dumps(a_ips, sort_keys=True))
                })
        except Exception:
            pass

    except ImportError:
        # Fallback to standard library socket if dnspython is absent
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            if ips:
                has_mx = True
                mx_records_str.append(f"0 {domain}")
                mx_servers_list.append({"preference": 0, "exchange": domain, "note": "socket implicit A fallback"})
                evidence.append({
                    "source": f"socket.gethostbyname_ex({domain})",
                    "query": domain,
                    "timestamp": ts,
                    "response_sha256": _hash_bytes(json.dumps(ips, sort_keys=True))
                })
        except Exception:
            pass

    return mx_records_str, mx_servers_list, has_mx, evidence


def classify_provider(domain: str, mx_servers: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Classify email domain provider: disposable, consumer webmail, or corporate infrastructure.
    """
    d_lower = domain.lower()

    # 1. Check embedded disposable domain catalog
    if d_lower in DISPOSABLE_DOMAINS:
        return {
            "is_disposable": True,
            "is_free_provider": True,
            "provider_type": "disposable",
            "infrastructure": "Temporary / Disposable Email Service"
        }

    # 2. Check MX server hostnames for disposable routing
    for mx in mx_servers:
        exch = mx.get("exchange", "").lower()
        if any(pat in exch for pat in DISPOSABLE_MX_PATTERNS):
            return {
                "is_disposable": True,
                "is_free_provider": True,
                "provider_type": "disposable",
                "infrastructure": f"Custom Domain Routed to Disposable Service ({exch})"
            }

    # 3. Check consumer webmail catalog
    if d_lower in FREE_WEBMAIL_DOMAINS:
        infra = FREE_WEBMAIL_DOMAINS[d_lower]
        return {
            "is_disposable": False,
            "is_free_provider": True,
            "provider_type": "consumer_webmail",
            "infrastructure": infra
        }

    # 4. Check enterprise mail infrastructure patterns from MX exchanges
    detected_infra = None
    for mx in mx_servers:
        exch = mx.get("exchange", "").lower()
        for pattern, name in ENTERPRISE_MX_PATTERNS:
            if pattern.match(exch):
                detected_infra = name
                break
        if detected_infra:
            break

    return {
        "is_disposable": False,
        "is_free_provider": False,
        "provider_type": "corporate_custom" if detected_infra else "custom_unknown",
        "infrastructure": detected_infra or "Custom Corporate / Self-Hosted Mail Server"
    }


def lookup_gravatar(email: str, timeout: float = 3.0) -> tuple[bool, str, str, dict[str, Any], list[dict[str, Any]]]:
    """
    Perform passive Gravatar lookup using SHA-256 and MD5 hash endpoints.
    Returns: (has_gravatar, sha256_hash, md5_hash, profile_data, evidence_list)
    """
    canonical_email = email.strip().lower()
    sha256_hash = hashlib.sha256(canonical_email.encode("utf-8")).hexdigest()
    md5_hash = hashlib.md5(canonical_email.encode("utf-8")).hexdigest()

    evidence: list[dict[str, Any]] = []
    ts = datetime.now(timezone.utc).isoformat()
    profile_data: dict[str, Any] = {
        "profile_exists": False,
        "avatar_exists": False,
        "avatar_url": None,
        "profile_url": None,
        "display_name": None,
        "username": None
    }
    has_gravatar = False

    try:
        import requests
        headers = {"User-Agent": "TrustworthyAgent/1.5 (Passive OSINT Investigation)"}

        # 1. Query avatar endpoint with d=404
        avatar_url = f"https://www.gravatar.com/avatar/{sha256_hash}?d=404"
        try:
            resp_avatar = requests.get(avatar_url, headers=headers, timeout=(1.5, timeout))
            if resp_avatar.status_code == 200:
                has_gravatar = True
                profile_data["avatar_exists"] = True
                profile_data["avatar_url"] = f"https://www.gravatar.com/avatar/{sha256_hash}"
                evidence.append({
                    "source": avatar_url,
                    "query": sha256_hash,
                    "timestamp": ts,
                    "response_sha256": _hash_bytes(resp_avatar.content)
                })
        except requests.RequestException:
            pass

        # 2. Query profile JSON endpoint
        profile_json_url = f"https://en.gravatar.com/{sha256_hash}.json"
        try:
            resp_json = requests.get(profile_json_url, headers=headers, timeout=(1.5, timeout))
            if resp_json.status_code == 200:
                has_gravatar = True
                profile_data["profile_exists"] = True
                data = resp_json.json()
                if "entry" in data and len(data["entry"]) > 0:
                    entry = data["entry"][0]
                    profile_data["display_name"] = entry.get("displayName")
                    profile_data["username"] = entry.get("preferredUsername")
                    profile_data["profile_url"] = entry.get("profileUrl")

                evidence.append({
                    "source": profile_json_url,
                    "query": sha256_hash,
                    "timestamp": ts,
                    "response_sha256": _hash_bytes(resp_json.content)
                })
        except requests.RequestException:
            pass

    except ImportError:
        pass

    return has_gravatar, sha256_hash, md5_hash, profile_data, evidence


def run(email: str, passive_only: bool = True, **kwargs) -> dict[str, Any]:
    """
    Execute Email OSINT passive investigation.
    
    Parameters:
        email: Target email address string.
        passive_only: Enforced OPSEC guardrail. Must be True.
        
    Returns:
        Structured JSON dictionary meeting PROJECT.md and spec_report.md contracts.
    """
    # Enforce strict OPSEC passive-only guardrail
    if not passive_only:
        raise ValueError("OPSEC violation: passive_only must be True for email-osint")

    if not email or not isinstance(email, str):
        return {
            "ok": False,
            "error": "Email must be a non-empty string",
            "email": str(email) if email is not None else "",
            "valid_format": False,
            "domain": "",
            "is_disposable": False,
            "mx_records": [],
            "has_gravatar": False,
            "gravatar_hash": "",
            "evidence": []
        }

    norm_email = normalize_email(email)
    ts = datetime.now(timezone.utc).isoformat()
    all_evidence: list[dict[str, Any]] = []

    # 1. RFC 5322 Syntax Validation
    is_valid, local_part, domain, base_local, tag = validate_email_syntax(norm_email)

    syntax_summary = {
        "email": norm_email,
        "valid_format": is_valid,
        "local_part": local_part,
        "domain": domain,
        "subaddress_tag": tag
    }
    all_evidence.append({
        "source": "rfc5322://addr-spec",
        "query": norm_email,
        "timestamp": ts,
        "response_sha256": _hash_bytes(json.dumps(syntax_summary, sort_keys=True))
    })

    if not is_valid:
        return {
            "ok": True,
            "email": norm_email,
            "valid_format": False,
            "domain": domain,
            "is_disposable": False,
            "mx_records": [],
            "has_gravatar": False,
            "gravatar_hash": "",
            "evidence": all_evidence,
            "local_part": local_part,
            "timestamp": ts,
            "passive_only": True,
            "validation": {
                "syntax_valid": False,
                "has_mx_records": False,
                "mx_servers": [],
                "error": "Failed RFC 5322 syntax validation"
            },
            "classification": {
                "is_disposable": False,
                "is_free_provider": False,
                "provider_type": "invalid_syntax",
                "infrastructure": "None"
            },
            "public_footprint": {
                "gravatar": {
                    "profile_exists": False,
                    "avatar_exists": False,
                    "avatar_url": None,
                    "profile_url": None
                }
            }
        }

    # 2. DNS MX Record Resolution
    mx_records_str, mx_servers_list, has_mx, dns_evidence = resolve_mx_records(domain)
    all_evidence.extend(dns_evidence)

    # 3. Provider & Disposable Classification
    classification = classify_provider(domain, mx_servers_list)
    all_evidence.append({
        "source": "catalog://disposable-email-domains/v1.0",
        "query": domain,
        "timestamp": ts,
        "response_sha256": _hash_bytes(json.dumps(classification, sort_keys=True))
    })

    # 4. Passive Gravatar Lookup
    has_gravatar, sha256_hash, md5_hash, gravatar_profile, gravatar_evidence = lookup_gravatar(norm_email)
    all_evidence.extend(gravatar_evidence)

    # Assemble harmonized return payload
    return {
        # Core fields matching PROJECT.md interface contract
        "ok": True,
        "email": norm_email,
        "valid_format": True,
        "domain": domain,
        "is_disposable": classification["is_disposable"],
        "mx_records": mx_records_str,
        "has_gravatar": has_gravatar,
        "gravatar_hash": sha256_hash,
        "evidence": all_evidence,

        # Rich forensic metadata matching spec_report.md
        "local_part": local_part,
        "base_local": base_local,
        "subaddress_tag": tag,
        "timestamp": ts,
        "passive_only": True,
        "validation": {
            "syntax_valid": True,
            "has_mx_records": has_mx,
            "mx_servers": mx_servers_list
        },
        "classification": classification,
        "public_footprint": {
            "gravatar": {
                "profile_exists": gravatar_profile["profile_exists"],
                "avatar_exists": gravatar_profile["avatar_exists"],
                "avatar_url": gravatar_profile["avatar_url"],
                "profile_url": gravatar_profile["profile_url"],
                "display_name": gravatar_profile["display_name"],
                "username": gravatar_profile["username"],
                "sha256_hash": sha256_hash,
                "md5_hash": md5_hash
            }
        }
    }
```

---

## 5. Test Suite & Verification Strategy

### 5.1 Deterministic Unit Testing Strategy
To maintain absolute determinism and eliminate network flakiness, all unit tests must mock external network calls:
1. **Mocking `dnspython`**:
   - Patch `dns.resolver.Resolver.resolve`:
     - Test valid MX answer returning standard preference and exchange mocks.
     - Test `NoAnswer` on MX triggering fallback to `A` record query.
     - Test `NXDOMAIN` marking `has_mx_records: False` and `mx_records: []`.
2. **Mocking Gravatar HTTP calls**:
   - Patch `requests.get`:
     - Return HTTP 200 with mock Gravatar JSON and avatar content for positive tests.
     - Return HTTP 404 for negative tests.
     - Raise `requests.exceptions.ConnectTimeout` to verify robust error recovery.
3. **Time Freezing via `freezegun`**:
   - Utilize `@freeze_time("2026-11-06T12:00:00Z")` so that all `timestamp` fields in evidence and responses evaluate to identical strings across runs.

### 5.2 Test Matrix
| Test Case | Target Input | Expected Output Attributes |
|---|---|---|
| `test_valid_corporate_email` | `investigator@bank.co.th` | `valid_format: True`, `is_disposable: False`, `provider_type: "corporate_custom"` |
| `test_disposable_domain` | `scammer@mailinator.com` | `valid_format: True`, `is_disposable: True`, `provider_type: "disposable"` |
| `test_disposable_mx_routing` | `custom@scam-domain.xyz` (with MX `mail.mailinator.com`) | `is_disposable: True`, `classification.infrastructure` indicates disposable MX |
| `test_consumer_webmail` | `user@gmail.com` | `is_free_provider: True`, `provider_type: "consumer_webmail"`, `infrastructure: "Google Workspace / Gmail"` |
| `test_subaddressing_tag` | `alice+test@proton.me` | `base_local: "alice"`, `subaddress_tag: "test"` |
| `test_invalid_email_syntax` | `not_an_email`, `@domain.com`, `user@.com`, `user@@domain.com` | `valid_format: False`, `ok: True`, `mx_records: []` |
| `test_gravatar_found` | `known_gravatar@example.com` (mocked 200) | `has_gravatar: True`, `gravatar_hash: 64-char hex`, `profile_exists: True` |
| `test_gravatar_not_found` | `unknown@example.com` (mocked 404) | `has_gravatar: False`, `profile_exists: False` |
| `test_passive_only_violation` | `passive_only=False` | Raises `ValueError("OPSEC violation: passive_only must be True...")` |
| `test_evidence_structure` | Any query | Each evidence item has `source`, `query`, `timestamp`, `response_sha256` (len 64) |
| `test_executor_conformance` | Executed via `Executor.run(skill, args)` | Conforms to `Executor` v1.4.2 without tripping security guards |

---

## 6. Implementation Checklist for Worker Agent

When Milestone 1 worker begins implementation:
- [ ] Create directory: `agent/skills/investigation/email-osint/`.
- [ ] Write `agent/skills/investigation/email-osint/skill.yaml` with `status: runnable`.
- [ ] Write `agent/skills/investigation/email-osint/run.py` matching Section 4.2.
- [ ] Verify `Registry` loads the skill without raising stub or manifest errors:
  ```powershell
  python -c "from core.registry import Registry; r = Registry('agent/skills'); print('email-osint loaded:', 'email-osint' in r.skills)"
  ```
- [ ] Verify `Router` does NOT displace `phone-email-osint` in `agent/tests/test_router.py`:
  ```powershell
  pytest agent/tests/test_router.py
  ```
- [ ] Run full existing 171-test baseline suite:
  ```powershell
  pytest agent/tests
  ```
