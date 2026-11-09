# Project: Trustworthy Agent v1.5.0 Production-Grade OSINT Skills

## Architecture
- Two-Tier OSINT Architecture:
  * Tier 1 (100% Free, no API keys required): Domain/WHOIS OSINT, IP Geolocation OSINT, Email OSINT.
  * Tier 2 (Configurable API keys with graceful fallback): Phone OSINT, Breach Check.
- Execution Environment:
  * Pure Python execution adhering to v1.4.2 Executor allowlist (`agent/core/executor.py`).
  * Confinement within skill directories; no external shell/curl/wget binaries.
  * Pre-installed standard libraries utilized: `dnspython`, `requests`, `urllib3`, `freezegun`.
  * RDAP over HTTPS / socket queries for domain registration (due to absence of third-party `whois` library).
- Cross-Skill Invocation:
  * `domain-whois-osint` dynamically discovers and executes `ip-geolocation-osint` via `Registry` and `Executor` with graceful fallback.
- Explainable Heuristics:
  * 7-signal weighted scam heuristic algorithm producing 0-100 score, confidence rating (`HIGH`, `MEDIUM`, `LOW`), and bilingual reasons (`top_reason_th` and `top_reason_en`).
- Evidence & Forensic Tracking:
  * Standardized `evidence` array on all findings: `{"source": ..., "query": ..., "timestamp": ..., "response_sha256": ...}`.
  * Integration into `Guardrails.audit` SHA-256 hash chain and `build_artifact_manifest` Merkle ledger.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | IP Geolocation OSINT | Free public IP lookups (country, city, ASN, ISP, bogon/Tor) with evidence tracking | M1 | Survey |
| F2 | Email OSINT | Free syntax, MX lookup via dnspython, disposable domain check, Gravatar SHA256 check | M1 | Survey |
| F3 | Domain/WHOIS OSINT Engine | Pure-Python RDAP, DNS, crt.sh certificate transparency lookups | M2 | Survey |
| F4 | Explainable Scam Heuristic | 0-100 risk score, confidence level, bilingual reasons (`top_reason_th`, `top_reason_en`) | M2 | Survey |
| F5 | Cross-Skill Intelligence | Domain skill queries IP skill via Registry/Executor with graceful fallback | M2 | Survey |
| F6 | Phone OSINT Skill | Configurable API key (`NUMVERIFY_API_KEY`) via env with offline fallback (Thai/Taiwan prefixes, E.164) | M3 | Survey |
| F7 | Breach Check Skill | Configurable API key (`HIBP_API_KEY`) via env with k-anonymity / graceful fallback | M3 | Survey |
| F8 | Backward Compatibility | Ensure `phone-email-osint`, `test_router.py`, and `test_guardrails.py` continue passing | M3 | Survey |
| F9 | Standardized Evidence Tracking | All findings include source URL/query, timestamp, response sha256 | M1, M2, M3 | Survey |
| F10 | Deterministic Unit Tests | Mocked unit tests using frozen time (`freezegun`) for domain age and temporal calculations | M4 | Survey |
| F11 | Cross-Skill Integration Tests | E2E execution in v1.4.2 Executor allowlist with Domain -> IP invocation | M4 | Survey |
| F12 | Cryptographic Audit & Ledger | Audit log hash chain (`audit.jsonl`) and Merkle ledger (`artifact_manifest.json`) integration | M5 | Survey |
| F13 | Baseline Regression Zero-Tolerance | 100% pass of existing 171 tests and 5-pillar verification script | M5 | Survey |
| F14 | Final Adversarial Coverage & Audit | Adversarial edge-case hardening (Challenger) and Forensic Integrity Audit (Auditor) | M6 | Survey |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Tier 1 IP & Email Skills | Implement `ip-geolocation-osint` and `email-osint` with evidence tracking | none | PLANNED |
| M2 | Tier 1 Domain & Scam Heuristics | Implement `domain-whois-osint` (RDAP, DNS, crt.sh, scam heuristic, cross-skill IP) | M1 | PLANNED |
| M3 | Tier 2 Phone & Breach Skills | Implement `phone-osint` and `breach-check` with env API keys and graceful fallback; preserve `phone-email-osint` | none | PLANNED |
| M4 | Test Suite & Frozen Time Coverage | Deterministic unit tests with `freezegun`, cross-skill integration tests, schema tests | M1, M2, M3 | PLANNED |
| M5 | Audit Hash Chain & Zero Regression | 171 baseline tests pass, 5-pillar `verify_all.py` passes, audit hash chain & Merkle roots verified | M4 | PLANNED |
| M6 | Final Adversarial & Integrity Audit | Challenger stress tests + Forensic Auditor clean verification | M5 | PLANNED |

## Interface Contracts
### `ip-geolocation-osint`
- Input: `{"ip": "<IPv4/IPv6>", "passive_only": true}`
- Output:
  ```json
  {
    "ok": true,
    "ip": "...",
    "country": "...",
    "country_code": "...",
    "city": "...",
    "isp": "...",
    "asn": "...",
    "is_bogon": false,
    "is_tor": false,
    "evidence": [
      {
        "source": "https://ip-api.com/...",
        "query": "...",
        "timestamp": "2026-11-06T...",
        "response_sha256": "..."
      }
    ]
  }
  ```

### `email-osint`
- Input: `{"email": "<user@domain.com>", "passive_only": true}`
- Output:
  ```json
  {
    "ok": true,
    "email": "...",
    "valid_format": true,
    "domain": "...",
    "is_disposable": false,
    "mx_records": ["..."],
    "has_gravatar": false,
    "gravatar_hash": "...",
    "evidence": [...]
  }
  ```

### `domain-whois-osint`
- Input: `{"domain": "<example.com>", "passive_only": true, "include_ip_osint": true}`
- Output:
  ```json
  {
    "ok": true,
    "domain": "...",
    "registrar": "...",
    "creation_date": "...",
    "expiration_date": "...",
    "domain_age_days": 120,
    "dns_records": {"A": [...], "MX": [...]},
    "certificates": [{"issuer": "...", "valid_to": "..."}],
    "ip_osint": {...},
    "scam_heuristic": {
      "risk_score": 15,
      "risk_level": "LOW",
      "confidence": "HIGH",
      "signals": [...],
      "top_reason_th": "โดเมนจดทะเบียนมานานกว่า 1 ปี และมีใบรับรอง SSL ที่ถูกต้อง",
      "top_reason_en": "Domain registered over 1 year ago with valid SSL certificate"
    },
    "evidence": [...]
  }
  ```

### `phone-osint`
- Input: `{"phone": "<+66812345678>", "passive_only": true}`
- Output:
  ```json
  {
    "ok": true,
    "phone": "...",
    "country_code": "TH",
    "carrier": "...",
    "line_type": "mobile",
    "is_valid": true,
    "source_used": "api" | "offline_fallback",
    "evidence": [...]
  }
  ```

### `breach-check`
- Input: `{"target": "<email_or_username>", "passive_only": true}`
- Output:
  ```json
  {
    "ok": true,
    "target": "...",
    "breached": false,
    "breach_count": 0,
    "breaches": [],
    "source_used": "api" | "fallback",
    "evidence": [...]
  }
  ```

## Code Layout
- `agent/skills/investigation/ip-geolocation-osint/`
  * `skill.yaml`
  * `run.py`
- `agent/skills/investigation/email-osint/`
  * `skill.yaml`
  * `run.py`
- `agent/skills/investigation/domain-whois-osint/`
  * `skill.yaml`
  * `run.py`
- `agent/skills/investigation/phone-osint/`
  * `skill.yaml`
  * `run.py`
- `agent/skills/investigation/breach-check/`
  * `skill.yaml`
  * `run.py`
- `agent/skills/investigation/phone-email-osint/`
  * `run.py` (updated to delegate to `phone-osint` / `email-osint` while maintaining backward compatibility)
- `agent/tests/`
  * `test_osint_skills.py` (comprehensive unit & integration tests for all 5 skills with `freezegun`)
  * `test_cross_skill_osint.py` (Domain -> IP cross-skill invocation tests)
