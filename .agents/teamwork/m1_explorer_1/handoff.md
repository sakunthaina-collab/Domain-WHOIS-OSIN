# Handoff Report: `ip-geolocation-osint` Technical Implementation Strategy

**Author**: `m1_explorer_1` (Teamwork Explorer Subagent)  
**Recipient**: `55cddded-d3e8-4597-ace7-b88461de123a` (Parent Orchestrator)  
**Milestone**: Milestone 1 (ip-geolocation-osint strategy)  
**Date**: 2026-11-06  
**Artifact Delivered**: `C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\m1_explorer_1\ip_strategy.md`  

---

## 1. Observation

1. **Original Requirements & Acceptance Criteria**:
   - `ORIGINAL_REQUEST.md` (lines 14, 27, 54): Requires Tier 1 (100% Free, no API keys) IP Geolocation OSINT skill in `skills/investigation/` using free public lookups, pure Python adhering to v1.4.2 Executor allowlist, and standardized evidence tracking (`source`, `query`, `timestamp`, `response_sha256`).
   - `PROJECT.md` (lines 49-72, 149-151): Specifies exact input (`{"ip": "...", "passive_only": true}`) and output contracts, including `country`, `city`, `isp`, `asn`, `is_bogon`, `is_tor`, and `evidence` array.

2. **Codebase Cross-Skill Dependency**:
   - In `agent/skills/investigation/domain-whois-osint/run.py` (lines 247-299), function `_enrich_ip_intel` discovers and invokes `ip-geolocation-osint`:
     ```python
     reg = Registry()
     ip_skill = reg.skills.get("ip-geolocation-osint")
     if ip_skill and getattr(ip_skill, "status", None) == "runnable":
         res = Executor().run(ip_skill, {"ip": ip, "passive_only": True})
         if res and isinstance(res, dict):
             intel_item.update(res)
             executed = True
     ```
   - In line 405 of `domain-whois-osint/run.py`, the scam heuristic checks `item.get("is_tor") or item.get("is_vpn")` to flag bulletproof hosting (+20 risk penalty).
   - In lines 284-290, when `ip-geolocation-osint` is missing, `_enrich_ip_intel` falls back to `socket.gethostbyaddr(ip)` which lacks a timeout argument.

3. **Executor Sandboxing & Security Constraints**:
   - In `agent/core/executor.py` (lines 25-39), `_ALLOWED_CLI_BINS = {"python", "python3", "py", "node", "uv"}` and `_DENIED_BINS` bans `curl`, `wget`, `nc`, `sh`, `powershell`, etc.
   - In `agent/core/executor.py` (lines 42-56), `_METADATA_IPS` blocks `169.254.169.254`, `169.254.170.2`, `100.100.100.200`, and `fd00:ec2::254`.
   - In `agent/core/executor.py` (lines 59-76), a sliding-window rate limiter enforces a default cap of 60 calls/minute.

4. **Test Suite Baseline & Execution Observations**:
   - `python -m pytest agent/tests/test_domain_whois.py -k "not test_controlled_live_domain_integration and not test_full_run_workflow_mocked"` executed 15 tests in 0.15s (100% pass).
   - Direct execution of `test_full_run_workflow_mocked` stalled because `socket.gethostbyaddr("93.184.216.34")` was invoked without a timeout on Windows Winsock stack when `ip-geolocation-osint` was absent.
   - Core baseline suites (`test_guardrails.py`, `test_audit_chain.py`, `test_router.py`, `test_trust.py`, `test_manifest.py`, `test_adversarial.py`) pass 100% (33 passed in 8.75s).

---

## 2. Logic Chain

1. **Free Tier & Zero-Key Invariant**:
   - Observation 1 dictates that `ip-geolocation-osint` cannot require paid API keys.
   - Standard public endpoints (`http://ip-api.com/json/{ip}`, `https://ipwho.is/{ip}`, and authoritative RIR RDAP over HTTPS `https://rdap.arin.net/registry/ip/{ip}`) provide comprehensive country, city, ISP, ASN, and hosting attributes for free.
   - Therefore, a multi-tier failover structure (`ip-api.com` -> `ipwho.is` -> RIR RDAP -> local fallback) ensures maximum reliability without paid credentials.

2. **Bogon & Private Filtering Invariant**:
   - Observation 1 and 3 require private IP and bogon detection conforming to RFC 1918, RFC 3927, and cloud metadata blocking.
   - Using Python's stdlib `ipaddress` allows instant in-memory checking against CIDR tables (`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `fe80::/10`, etc.).
   - Immediate short-circuiting on bogons prevents leaking internal network architecture to external APIs, avoids socket timeouts, and completes in < 2ms.

3. **rDNS Timeout Safety**:
   - Observation 4 demonstrated that raw `socket.gethostbyaddr` blocks the process when outbound DNS is slow or unmocked.
   - `dnspython`'s `dns.reversename` and `dns.resolver.Resolver` provides explicit `timeout` and `lifetime` configuration (e.g. 1.5s).
   - Therefore, `dnspython` must be the primary rDNS resolver, with socket access strictly guarded by timeout controls.

4. **Cross-Skill Contract Alignment**:
   - Observation 2 shows `domain-whois-osint` directly merges the IP skill's output via `intel_item.update(res)` and evaluates `is_tor` / `is_vpn`.
   - Supplying `is_tor` (via TorDNSEL `dnsel.torproject.org`), `is_vpn`, `is_datacenter`, `is_bogon`, `country`, `city`, `isp`, `asn`, and `hostname` directly fulfills this requirement.

5. **Evidence Schema Unification**:
   - Observation 1 requires `source`, `query`, `timestamp`, `response_sha256`.
   - Observation 2 and existing code expect `claim`, `retrieved_at`, `raw_response_sha256`.
   - Providing both sets of keys in every evidence object guarantees zero schema mismatches across all consumers.

---

## 3. Caveats

1. **ip-api.com Free Tier Protocol**:
   - `ip-api.com` free endpoint uses plain HTTP (`http://ip-api.com`). HTTPS is only supported on paid plans. `executor.py` supports both HTTP and HTTPS, but in environments requiring strict end-to-end TLS, Tier 2 (`https://ipwho.is`) or Tier 3 (HTTPS RDAP) can be set as primary if desired.
2. **Tor Exit Node DNSBL**:
   - Querying `dnsel.torproject.org` requires active DNS UDP port 53 egress. In strictly air-gapped/offline test environments, this lookup will time out or be skipped gracefully, returning `is_tor = False`.
3. **No Code Modification Undertaken**:
   - In accordance with the explorer archetype rules, zero files in `agent/` were modified. The strategy is purely architectural and ready for the Milestone 1 implementer.

---

## 4. Conclusion

The technical implementation strategy for `ip-geolocation-osint` is fully formulated and documented in `ip_strategy.md`. It provides:
1. Complete `skill.yaml` and `run.py` code blueprints.
2. Multi-tier free lookup failover (`ip-api.com` -> `ipwho.is` -> RIR RDAP).
3. In-memory RFC bogon classification engine.
4. Bounded `dnspython` PTR resolution.
5. Standardized 6-attribute cryptographic evidence tracking.
6. Seamless cross-skill integration with `domain-whois-osint`.

---

## 5. Verification Method

To verify this technical strategy and prepare for implementation:

1. **Inspect Artifact**:
   - Read `ip_strategy.md`:
     `C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\m1_explorer_1\ip_strategy.md`
2. **Verify Baseline Test Compatibility**:
   - Run existing core tests:
     `python -m pytest agent/tests/test_guardrails.py agent/tests/test_audit_chain.py agent/tests/test_router.py agent/tests/test_domain_whois.py -k "not test_controlled_live_domain_integration and not test_full_run_workflow_mocked"`
   - Assert all tests exit 0.
3. **Invalidation Conditions**:
   - The strategy is invalidated if any proposed dependency requires paid credentials, introduces non-allowlisted CLI binaries, or fails to emit valid SHA-256 evidence records.
