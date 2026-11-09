# Dispatch Records

## 2026-11-06T09:52:47Z

Develop 5 production-grade OSINT skills for Trustworthy Agent v1.5.0 to replace stubs and mocks with verifiable investigation capabilities suitable for real demonstrations to enterprise and government audiences.

Integrity mode: demo
The team must NOT: copy code from existing open-source projects for core logic, run external scripts or delegate execution to other tools outside the controlled environment

## Requirements

### R1. Two-Tier OSINT Skill Suite
Implement 5 production-grade OSINT skills in `skills/investigation/` following a two-tier architecture:
- Tier 1 (100% Free, no API keys required): Domain/WHOIS OSINT (using WHOIS, DNS, crt.sh), IP Geolocation OSINT (using free public lookups), and Email OSINT.
- Tier 2 (Configurable API keys with graceful fallback): Phone OSINT and Breach Check, querying real services when keys are present via environment variables and providing graceful error handling or free-tier fallback when keys are absent.
Do not configure the Data Agent Kit plugin; focus exclusively on the 5 OSINT skills, beginning with `domain-whois-osint`.

### R2. Cross-Skill Intelligence and Explainable Heuristics
- Enable cross-skill intelligence where the Domain skill can query the IP skill via the Registry/Executor with graceful fallback when the IP skill is unavailable.
- Implement an explainable scam heuristic that calculates a numeric risk score (0-100) based on weighted signals, provides an explicit confidence level, and supplies bilingual explanations (`top_reason_th` and `top_reason_en`).

### R3. Evidence Tracking and Cryptographic Audit Integration
- Every finding and claim must include evidence tracking attributes: source URL/query, timestamp, and response sha256 hash.
- Ensure all skill executions emit structured forensic outputs and integrate into Trustworthy Agent's cryptographic audit hash chain, Merkle ledger, and tamper-evident reporting pipeline.

### R4. Core Logic and Environment Conformance
Write 100% original proprietary code for core logic without copying from existing open-source projects. All execution must strictly adhere to the v1.4.2 Executor allowlist. Standard pre-built libraries (such as dnspython, requests, urllib, freezegun) are permitted.

### R5. Test Coverage, Frozen Time, and Regression Prevention
Provide automated test coverage for all new skills while maintaining full compatibility with the existing test suite:
- Deterministic unit tests for every skill using mocked external API responses to eliminate network flakiness.
- Frozen time testing (e.g. via `freezegun`) for time-dependent calculations such as domain age and certificate expiration.
- Controlled integration tests verifying end-to-end execution, cross-skill queries, and output schemas.
- Zero regressions against the existing 171 repository tests.

## Verification Resources
- Existing repository test suite in `agent/tests/` (171 tests baseline).
- Existing investigation skill schemas and agent runner artifacts in `agent/skills/investigation/` and `agent/artifacts/`.

## Acceptance Criteria

### Test & Regression Guardrails
- [ ] All 171 existing repository tests pass with zero regressions (`pytest` exits 0).
- [ ] Deterministic unit tests cover all 5 skills without network dependencies, utilizing frozen time (`freezegun` or equivalent) for domain age and temporal calculations.
- [ ] Integration tests verify skill execution within the v1.4.2 Executor allowlist, including cross-skill invocation between Domain and IP skills.

### Live Functionality & Heuristics
- [ ] Tier 1 skills (Domain/WHOIS, IP Geolocation, Email OSINT) function completely using free endpoints without requiring API credentials.
- [ ] Tier 2 skills (Phone OSINT, Breach Check) read API keys from environment variables and fail gracefully or provide safe fallback when keys are missing.
- [ ] Each skill defines a valid `skill.yaml` specification and input/output schema.
- [ ] Scam heuristic produces an explainable numeric score (0-100), weighted signals, confidence level, and bilingual reasons (`top_reason_th` and `top_reason_en`).

### Evidence Tracking & Tamper-Evidence
- [ ] Every extracted claim and finding contains source URL/query, timestamp, and response sha256.
- [ ] Executed investigation outputs produce structured JSON records linked to the Merkle ledger and cryptographic audit hash chain.

## 2026-11-06T10:49:25Z

Notice for Milestone 2 from user/parent:
`domain-whois-osint` has already been fully implemented and verified in `agent/skills/investigation/domain-whois-osint/` with 19 deterministic unit/integration tests in `agent/tests/test_domain_whois.py` and strict JSON Schema validation (`schema.json`) based on the user's Enterprise Dark-Mode UI Mockup as the Single Source of Truth.
It includes:
- Explainable 0-100 Scam Risk Scorer (with weighted signals: domain age, privacy guard, young SSL, suspicious TLD, no MX, brand keywords, bulletproof hosting)
- Cross-skill IP enrichment invoking `ip-geolocation-osint` via Registry/Executor
- Strict < 10.0s latency SLO (average live latency 2.8s - 8.0s)
- Bilingual rationales (`top_reason_th`, `top_reason_en`)
- Cryptographic evidence envelope with raw response SHA-256 digests.

When advancing to Milestone 2, you may incorporate or audit this existing production implementation directly.
