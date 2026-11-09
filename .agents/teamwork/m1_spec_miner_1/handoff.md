# Handoff Report: Milestone 1 Specification & Schema Contract

**Author:** `m1_spec_miner_1` (Specification Miner)  
**Recipient:** Milestone 1 Worker (`m1_worker_1`) & Parent Orchestrator (`55cddded-d3e8-4597-ace7-b88461de123a`)  
**Date:** 2026-11-06  
**Type:** Hard Handoff (Milestone 1 Specification Mining Complete)

---

## 1. Observation

### 1.1 Existing Codebase & Execution Engine
1. **Dynamic Python Skill Invocation (`agent/core/executor.py:200-215`):**
   ```python
   def _run_python(self, skill: Any, args: dict[str, Any]) -> dict[str, Any]:
       rt = skill.runtime
       skill_dir = (getattr(skill, "dir", None) or pathlib.Path(".")).resolve()
       entry = _resolve_within(skill_dir, rt["entry"])
       spec = importlib.util.spec_from_file_location(...)
       mod = importlib.util.module_from_spec(spec)
       spec.loader.exec_module(mod)
       res = mod.run(**args)
       return res if isinstance(res, dict) else {"ok": True, "result": res}
   ```
   *Execution requirement:* Entry file must be `run.py` within the skill directory, exposing `run(**args) -> dict`.

2. **SSRF Guard & Cloud Metadata IP Set (`agent/core/executor.py:42-47`):**
   ```python
   _METADATA_IPS = {
       ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure metadata
       ipaddress.ip_address("169.254.170.2"),    # AWS ECS task
       ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
       ipaddress.ip_address("fd00:ec2::254"),    # AWS IPv6
   }
   ```
   *Observation:* IP queries to metadata addresses must be intercepted locally without network egress.

3. **OPSEC Invariant Enforcement (`agent/core/guardrails.py:84-86`):**
   ```python
   if args.get("passive_only") is False and g.get("passive_only_required", True):
       return False
   ```
   *Observation:* Any input with `passive_only=False` is rejected by `Guardrails.allow()` and raises `ValueError`.

4. **Skill Loading & Dataclass Contract (`agent/core/registry.py:9-22, 54-73`):**
   `Registry` discovers skills via `rglob("skill.yaml")`. A valid skill requires: `name`, `description`, `category`, `input_schema`, `runtime`, `version`, `status` ("runnable"), `triggers`, `permissions`, `risk` ("low"), `outputs`.

5. **Cross-Skill Invocation Call Site (`agent/skills/investigation/domain-whois-osint/run.py:270-280, 405-412`):**
   ```python
   from core.registry import Registry
   from core.executor import Executor
   
   reg = Registry()
   ip_skill = reg.skills.get("ip-geolocation-osint")
   if ip_skill and getattr(ip_skill, "status", None) == "runnable":
       res = Executor().run(ip_skill, {"ip": ip, "passive_only": True})
       if res and isinstance(res, dict):
           intel_item.update(res)
           executed = True
   ```
   And in `calculate_scam_score`:
   ```python
   if any(item.get("is_tor") or item.get("is_vpn") for item in ip_intel):
       weight = 20
       score += weight
   ```
   *Observation:* The result of `ip-geolocation-osint` is merged directly via `intel_item.update(res)`. Therefore, top-level keys (`is_tor`, `is_vpn`, `is_private`, `country`, `city`, `isp`, `asn`) must be present in the root dictionary for cross-skill compatibility.

### 1.2 Tool Probing Commands and Empirical Results
1. **Installed Python Packages Verification:**
   Command: `python -c "import requests, dns, dns.resolver, ipaddress, hashlib, freezegun; print('OK')"`
   Result: `OK`. All required dependencies are pre-installed.
2. **Missing External Libraries Verification:**
   Command: `python -c "for m in ['ipwhois', 'whois', 'email_validator']: ..."`
   Result: `ipwhois: NOT installed`, `whois: NOT installed`, `email_validator: NOT installed`.
   *Observation:* All IP parsing and email validation must be implemented using pure Python (`ipaddress`, `re`, `socket`, `dnspython`).
3. **Public Free IP Geolocation Probes:**
   - Command: `python -c "import requests; r = requests.get('http://ip-api.com/json/8.8.8.8'); print(r.status_code, r.json()['country'])"`
     Result: `200 United States`.
   - Command: `python -c "import requests; r = requests.get('https://ipwho.is/8.8.8.8'); print(r.status_code, r.json()['country'])"`
     Result: `200 United States`.
   - IPv6 Probe on `2606:4700:4700::1111`:
     `http://ip-api.com` timed out on port 80.
     `https://ipwho.is/2606:4700:4700::1111` succeeded with `200 OK`, returning US, San Francisco, AS13335 Cloudflare.
   - Tor Exit Probe on `185.220.101.5`:
     `https://ipwho.is/185.220.101.5` returned Germany, ASN 60729 (`CIA TRIAD SECURITY LLC`), domain `relayon.org`.
4. **DNS MX Resolution via `dnspython` Probe:**
   Command: `python -c "import dns.resolver; print([r.exchange.to_text() for r in dns.resolver.resolve('gmail.com', 'MX')])"`
   Result: Resolved 5 MX exchangers in < 0.1s. Non-existent domain correctly raises `dns.resolver.NXDOMAIN`.
5. **Gravatar Profile Probe:**
   Command: `python -c "import requests; print(requests.get('https://en.gravatar.com/d41d8cd98f00b204e9800998ecf8427e.json').status_code)"`
   Result: `200 OK` on active profile; `404 Not Found` on non-existent hash (treated as clean state).
6. **Repository Test Baseline:**
   Command: `pytest agent/tests/`
   Result: 188 collected items. 187 passed, 1 failed (`test_controlled_live_domain_integration` failed at `agent/tests/test_domain_whois.py:325` due to live network resolution attempt). Excluding `test_domain_whois.py`, all 171 baseline repository tests pass with 100% success.

---

## 2. Logic Chain

1. **Premise 1:** The user request (`ORIGINAL_REQUEST.md` R1) mandates a two-tier OSINT architecture where Tier 1 skills (`ip-geolocation-osint` and `email-osint`) function 100% free with zero API keys.
2. **Premise 2:** Live empirical testing confirms that `http://ip-api.com/json/{ip}` and `https://ipwho.is/{ip}` are free, unauthenticated, and reliable for public IP lookups, with `ipwho.is` providing seamless IPv6 support.
3. **Premise 3:** `agent/core/executor.py` strictly restricts binaries and provides a strict SSRF guard against cloud metadata IPs. Using Python's standard `ipaddress` library to filter RFC 1918, loopback, link-local, and cloud metadata IPs before network egress satisfies both OPSEC and SSRF invariants without any network latency.
4. **Premise 4:** In `agent/skills/investigation/domain-whois-osint/run.py:270-280`, the domain skill dynamically looks up `ip-geolocation-osint` in `Registry` and executes it via `Executor().run()`, updating its internal dictionary with the returned keys (`intel_item.update(res)`). Later, line 405 evaluates `item.get("is_tor")` and `item.get("is_vpn")`. Therefore, `ip-geolocation-osint` must return a flat set of top-level keys (`country`, `city`, `isp`, `asn`, `is_tor`, `is_vpn`, `is_private`) in addition to any structured sub-dictionaries (`location`, `network`).
5. **Premise 5:** For `email-osint`, `dnspython` is pre-installed and resolves MX records in milliseconds. RFC 5321 §5.1 requires falling back to domain A records if MX records are absent. Temporary email detection is deterministically achieved via an embedded offline catalog of 100+ known disposable domains (0ms latency, zero flakiness). Gravatar public profiles are verified via MD5 hash requests, where HTTP 404 is explicitly handled as an unlinked clean state rather than an error.
6. **Premise 6:** `ORIGINAL_REQUEST.md` R3 and R5 require evidence tracking attributes (`source`, `query`, `timestamp`, `response_sha256`) and deterministic tests with mocked external responses and frozen time (`freezegun`). Providing both alias fields (`timestamp` and `retrieved_at`, `response_sha256` and `raw_response_sha256`) satisfies all existing repo consumers.
7. **Conclusion:** Delivering the specification contract in `spec_contract.md` with explicit schemas, edge-case tables, and test requirements provides the Worker agent with an exact, complete, and verifiable implementation blueprint.

---

## 3. Caveats

1. **Live Network Constraints in CI:** Live queries to external domains in tests (like `test_controlled_live_domain_integration`) can fail due to local DNS or firewall policies. Therefore, all unit tests for `ip-geolocation-osint` and `email-osint` MUST mock external HTTP (`requests.get`) and DNS calls (`dns.resolver.Resolver.resolve`) to guarantee 100% determinism.
2. **IPv6 with ip-api.com:** Empirical testing revealed that `http://ip-api.com` can time out on IPv6 addresses. The implementation must prioritize `https://ipwho.is/{ip}` or fallback to it whenever an IPv6 target is queried.
3. **Gravatar MD5 Standard:** Gravatar's public protocol uses MD5 for its lookup hash. The evidence envelope, however, strictly computes the SHA-256 digest of the raw HTTP response payload to maintain forensic chain-of-custody compliance.

---

## 4. Conclusion

Specification mining for Milestone 1 is complete. The detailed specification contract has been authored and saved to:
`C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\m1_spec_miner_1\spec_contract.md`

The contract defines:
- The exact `skill.yaml` declarations with multilingual triggers (English, Thai, Chinese).
- Exhaustive step-by-step execution pipelines for both `ip-geolocation-osint` and `email-osint`.
- Complete JSON output schemas matching both flat cross-skill requirements and nested forensic structures.
- 15 discovered features across all relevant categories.
- 18 analyzed edge cases with exact observed/required behaviors.
- Deterministic test plans for `agent/tests/test_ip_geolocation.py` and `agent/tests/test_email_osint.py` using `unittest.mock` and `freezegun`.

---

## 5. Verification Method

To independently verify this specification contract:
1. **Inspect Artifacts:**
   - View specification contract:
     `view_file` on `C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\m1_spec_miner_1\spec_contract.md`
   - Verify `Features Discovered` and `Edge Cases` tables are fully populated.
2. **Verify Library Pre-Requisites:**
   Execute in PowerShell:
   `python -c "import requests, dns.resolver, ipaddress, hashlib, freezegun; print('OK')"`
3. **Verify Baseline Tests:**
   Execute in PowerShell:
   `pytest agent/tests/test_guardrails.py agent/tests/test_router.py agent/tests/test_manifest.py agent/tests/test_audit_chain.py`
   All baseline tests must exit with code 0.
