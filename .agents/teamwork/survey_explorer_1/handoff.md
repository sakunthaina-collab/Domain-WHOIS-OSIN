# Handoff Report: Test Suite & v1.4.2 Executor Allowlist Survey

**Agent**: `survey_explorer_1` (teamwork_explorer subagent)  
**Date**: 2026-11-06  
**Working Directory**: `C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\survey_explorer_1`  
**Handoff Type**: Hard (Task Complete)

---

## 1. Observation

1. **Test Suite Baseline**:
   - Command: `cd agent; pytest`
   - Output: `============================ 171 passed in 34.48s =============================`
   - Test breakdown: 171 tests across 20 files (14 modules in `agent/tests/` totaling 137 tests, and 6 property-based test modules in `agent/tests/properties/` totaling 34 tests).
   - Pytest collection command: `pytest agent/tests --collect-only` collected exactly 171 items.
2. **Pytest & Hypothesis Configuration**:
   - `agent/tests/conftest.py` lines 8-16: inserts `agent/` into `sys.path[0]`, defines Hypothesis profiles (`ci` max_examples=1000, `dev` max_examples=200, `debug` max_examples=50 with `deadline=None`), loads profile from `HYPOTHESIS_PROFILE` (defaulting to `dev`).
   - `agent/tests/conftest_gpg.py` lines 29-111: defines session-scoped fixture `_base_gpg_keyring` (generates ephemeral RSA 2048-bit key, skips if `gpg` missing), function-scoped `gpg_keyring` (ephemeral `GNUPGHOME` per test), and `gpg_signer` (`GPGSigner(strict=True)`).
   - No `pytest.ini` or `pyproject.toml` exists in the repository.
3. **Mocking & Isolation Mechanisms in Existing Tests**:
   - S3 / WORM: `agent/tests/test_s3_worm_adapter.py` lines 7-69 uses `moto.mock_aws` / `mock_s3` with an in-memory monkeypatch on Moto's `S3Response` (`_patch_moto_for_retention`) to emulate S3 Object Lock retention XML and raise `AccessDeniedByLock`.
   - LLMs: `agent/tests/test_resilience.py` lines 13-22 defines `MockFailingLLM` to simulate transient network errors and retries.
   - Guardrails / Skills: `agent/tests/test_adversarial.py` lines 28-30 and `agent/tests/test_case_id_injection.py` lines 9-20 define in-memory mock skills (`FakeSkill`, `_Skill`).
   - Network / Egress: Zero external network or socket calls are made in the 171 baseline tests. All tests run completely offline.
4. **Time-Dependent Logic & Freezegun**:
   - `agent/requirements-dev.txt` line 6 specifies `freezegun>=1.2`.
   - Python environment inspection (`python -m pip list`) confirms `freezegun 1.5.5` is installed.
   - Grep search for `freezegun` / `freeze_time` in `agent/tests/` returned 0 occurrences in existing baseline tests; baseline tests rely on static mock timestamps or arithmetic mutations.
5. **v1.4.2 Executor Allowlist & Security Restrictions**:
   - Located in `agent/core/executor.py` lines 23-57, 82-150, 156-295.
   - CLI allowlist (`_ALLOWED_CLI_BINS` line 25): `{"python", "python3", "py", "node", "uv"}`.
   - CLI denylist (`_DENIED_BINS` lines 29-39): 32 dangerous binaries denied outright (`cmd`, `powershell`, `pwsh`, `bash`, `sh`, `rm`, `del`, `curl`, `wget`, `nc`, `npx`, `uvx`, `perl`, `ruby`, `php`, etc.).
   - Path confinement (`_resolve_within` lines 100-118): rejects null bytes, absolute paths, Windows drive letters, and directory traversals (`..`).
   - SSRF guard (`_validate_http_url` lines 121-149): allows only `http`/`https`; always blocks cloud metadata IPs (`_METADATA_IPS`: `169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`); blocks private subnets (`_BLOCKED_NETS_LOCAL`) unless `allow_local=True`.
   - Rate limiting (`RateLimiter` lines 59-76): sliding-window limiter enforcing 60 calls per 60.0s window per skill/domain.
6. **Environment Packages & Dependencies**:
   - Verified installed: `dnspython 2.9.1`, `requests 2.34.2`, `urllib3 2.7.0`, `freezegun 1.5.5`, `boto3 1.43.96`, `moto 5.1.22`, `pytest 9.2.0`, `pytest-mock 3.17.0`, `responses 0.26.3`, `hypothesis 6.170.14`, `cryptography 50.0.1`, `pydantic 2.12.5`, `python-dateutil 2.9.0.post0`.
   - `python -c "import whois"` exits with code 1 (`ModuleNotFoundError: No module named 'whois'`).
7. **Regression Guardrails in Existing Tests**:
   - `agent/tests/test_stubs_isolation.py` lines 39-47: loads real `Registry` and asserts all loaded skills have `status == "runnable"`.
   - `agent/tests/test_guardrails.py` lines 31-40: asserts `passive_only=False` raises `ValueError` in skill logic and is rejected by `Guardrails.allow()`.
   - `agent/tests/test_router.py` lines 19-45: verifies top routing hits for specific Thai and Chinese search queries.

---

## 2. Logic Chain

1. From Observation 1, the baseline test suite has 171 tests that pass in ~34.5s. Therefore, zero regression acceptance criteria requires running `pytest agent/tests` after any additions and confirming all 171 tests continue to pass.
2. From Observation 2, imports in `agent/tests/` rely on `conftest.py` putting `agent/` at `sys.path[0]`. Any new test file placed in `agent/tests/` will automatically inherit this environment and the Hypothesis settings (`deadline=None`).
3. From Observation 3 and Observation 6, the test environment runs 100% hermetically without network egress. If the 5 new OSINT skills make real network requests during unit tests, tests will be flaky or fail offline. Therefore, all external network requests (DNS queries via `dnspython`, HTTP/RDAP requests via `requests`/`urllib`) MUST be mocked in tests using `pytest-mock` (`mocker.patch`), `unittest.mock`, or `responses`.
4. From Observation 4 and the R5 requirement in `ORIGINAL_REQUEST.md`, `freezegun` (v1.5.5) must be used via `@freeze_time("2026-11-06T12:00:00Z")` or `with freeze_time(...):` to freeze time when testing domain age calculations (`(now - creation_date).days`) and certificate expiration.
5. From Observation 5, `agent/core/executor.py` strictly restricts CLI binaries to `python`, `python3`, `py`, `node`, `uv run` and bans `curl`, `wget`, `sh`, `bash`, etc. Thus, skills cannot use external CLI scripts or OS tools. They must run under `runtime: {type: python, entry: run.py}` with pure Python logic.
6. From Observation 6, `whois` is NOT installed in the Python environment. Attempting `import whois` will cause `ModuleNotFoundError`. Therefore, domain registration intelligence must use RFC 7480-7484 RDAP over HTTPS (`https://rdap.org/domain/...`) and direct socket lookups, both of which are fully supported by `requests`, `urllib`, and `socket`.
7. From Observation 7, any new skill registered in `agent/skills/investigation/<skill>/skill.yaml` must have `status: runnable`. If set to `stub`, `test_stubs_isolation.py` will fail. Furthermore, all skills must require `passive_only: true` by default and raise a `ValueError` if `passive_only=False` to pass `test_guardrails.py` invariants.

---

## 3. Caveats

1. **Subagent Read-Only Constraint**: As a survey subagent, no source code or test files were created or modified. All findings are purely observational and analytical.
2. **DNS Rebinding in Executor**: As noted in `agent/core/executor.py` lines 124-127, URL validation checks IP addresses at validation time via `socket.getaddrinfo()`, which does not protect against DNS rebinding without network egress ACLs. For mock unit tests, this has no operational impact.
3. **Execution Mode**: In production live runs, external network access is needed for real OSINT lookups (RDAP, DNS, crt.sh, APIs); however, all automated tests must be 100% hermetic and mocked.

---

## 4. Conclusion

1. The test harness is healthy, robust, and completely functional (171/171 baseline tests pass in 34.48s).
2. The v1.4.2 Executor allowlist in `agent/core/executor.py` strictly enforces pure Python or confined CLI execution, blocks 32 dangerous binaries, confines file paths within each skill directory, blocks cloud metadata SSRF, and enforces a 60 call/min rate limit.
3. Standard pre-built libraries required for OSINT development (`dnspython`, `requests`, `urllib3`, `freezegun`, `boto3`, `pytest-mock`, `responses`) are already installed and functional.
4. The absence of the third-party `whois` package requires domain registration intelligence to be implemented using RFC 7482 RDAP and raw sockets, which perfectly aligns with the requirement for 100% original proprietary code.
5. All detailed findings, inventories, configurations, and regression guardrails are documented in `test_executor_report.md`.

---

## 5. Verification Method

To independently verify the observations and conclusions in this report:

1. **Run full baseline test suite**:
   ```powershell
   cd C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\agent
   pytest
   ```
   *Expected result*: Exit code 0, exactly 171 passed tests in ~35 seconds.

2. **Verify test collection from root**:
   ```powershell
   cd C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill
   pytest agent/tests --collect-only
   ```
   *Expected result*: Exactly 171 items collected across 20 files.

3. **Verify Executor allowlist definitions**:
   Inspect `agent/core/executor.py`:
   - Line 25: `_ALLOWED_CLI_BINS`
   - Lines 29-39: `_DENIED_BINS`
   - Lines 42-56: `_METADATA_IPS` and `_BLOCKED_NETS_LOCAL`
   - Lines 100-118: `_resolve_within`
   - Lines 121-149: `_validate_http_url`

4. **Verify installed environment packages**:
   ```powershell
   python -c "import dns, requests, urllib3, freezegun, hypothesis, moto; print('All required OSINT & testing libraries present')"
   ```
   *Expected result*: Prints confirmation without import errors.

5. **Verify `whois` absence and necessity of RDAP**:
   ```powershell
   python -c "import whois"
   ```
   *Expected result*: Exits with code 1 (`ModuleNotFoundError`).

6. **Invalidation Conditions**:
   - If any of the 171 baseline tests fail or are skipped.
   - If `agent/core/executor.py` is modified to allow shell execution or unauthorized binaries.
   - If `test_stubs_isolation.py` fails due to non-runnable skills in `agent/skills/`.
