# Comprehensive Survey Report: Test Suite & v1.4.2 Executor Allowlist

**Author**: `survey_explorer_1` (teamwork_explorer subagent)  
**Date**: 2026-11-06  
**Scope**: Trustworthy Agent v1.5.0 / v1.4.2 Executor Hardening & Test Baseline  
**Target Repository**: `C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill`

---

## 1. Executive Summary

This report delivers a full architectural survey of the Trustworthy Agent test suite (171 baseline tests in `agent/tests/`) and the v1.4.2 Executor security allowlist (`agent/core/executor.py`). 

Key findings:
1. **Existing Test Suite Baseline**: All **171 baseline tests pass in 34.48s** with zero failures or skips under Python 3.12.10 (pytest 9.2.0, hypothesis 6.170.14, moto 5.1.22).
2. **Test Structure**: Tests are split into standard deterministic unit/integration/adversarial tests (137 tests across 14 modules) and property-based fuzzing tests using Hypothesis (34 property tests across 6 modules in `agent/tests/properties/`).
3. **Configuration**: Pytest has no root `.ini` or `pyproject.toml`; configuration is managed through `agent/tests/conftest.py` (which injects `agent/` into `sys.path` and defines Hypothesis profiles with `deadline=None`) and `conftest_gpg.py` (which sets up an isolated session-scoped GPG keyring).
4. **Mocking & Isolation**: No real network calls are made during the existing test run. AWS S3 Object Lock is mocked via `moto[server]` with custom in-memory patches; LLMs are mocked via stateful classes (`MockFailingLLM`); GPG is isolated via ephemeral `GNUPGHOME` directories.
5. **Temporal Logic**: `freezegun>=1.2` is installed (v1.5.5) and specified in `requirements-dev.txt`, but was not yet utilized in baseline tests. It is explicitly required for deterministic testing of domain age and certificate expiration in the new OSINT skills.
6. **Executor Allowlist**: Strictly enforced in `agent/core/executor.py` (v1.4.2). Only 5 CLI binaries are permitted (`python`, `python3`, `py`, `node`, `uv`), 32 dangerous binaries are denied outright, path traversal is blocked via `_resolve_within()`, cloud metadata IPs (AWS/GCP/Azure `169.254.169.254`, Alibaba `100.100.100.200`, etc.) and private subnets are blocked via `_validate_http_url()`, and execution is rate-limited (60 calls/min).

---

## 2. Existing Test Suite Survey (`agent/tests/`)

### 2.1 Inventory of Test Files and Test Breakdown (171 Baseline Tests)

The test suite consists of 20 test files in `agent/tests/` (14 root modules + 6 in `properties/`):

| File Path | Test Count | Primary Focus / Subsystem Under Test |
|---|---|---|
| `tests/properties/test_adversarial_json_properties.py` | 6 | Corrupted bytes resilience, UTF-8 BOM tolerance, blank lines, tail deletion detection via anchor, thread safety (no deadlock/data loss). |
| `tests/properties/test_audit_chain_properties.py` | 4 | Invariant properties of the cryptographic hash chain: valid chains pass, single-field mutation fails, internal deletion fails, record swapping fails. |
| `tests/properties/test_executor_properties.py` | 8 | FIND-05 (arbitrary binary rejection), FIND-06 (path traversal blocked), FIND-07 (SSRF metadata blocked), CLI shell injection safety, sliding-window rate limiter invariant. |
| `tests/properties/test_merkle_properties.py` | 3 | Merkle tree determinism, single-byte mutation detection (avalanche effect), empty directory invariant. |
| `tests/properties/test_normalize_properties.py` | 5 | Phone normalization idempotency, separator invariance, output shape invariant (`^\+?[0-9]*$`), plus sign positioning, email normalization. |
| `tests/properties/test_s3_worm_properties.py` | 4 | S3 WORM retention days validation, non-positive day rejection, SHA-256 checksum roundtrip, invalid retention mode rejection. |
| `tests/test_adversarial.py` | 17 | SQL/shell injection in audit args, path traversal in `case_id`, malicious CLI runtime blocked, audit log truncation/deletion detection, empty artifact manifest rejection, Unicode phone & Thai text handling, 5-process concurrent audit writes. |
| `tests/test_anchor_integration.py` | 2 | End-to-end integration: Guardrails audit logger → Anchor ledger → `scripts/verify_audit.py` verification; detects appended entries mismatching old anchor. |
| `tests/test_audit_chain.py` | 3 | Hash chain genesis (`0`*64), sequential linking, payload tampering detection, middle-entry deletion detection. |
| `tests/test_case_id_injection.py` | 17 | Regex validation of canonical case IDs (`YYYY-MM-DD-CASE-...`), injection into skill arguments, overriding LLM hallucinated case IDs, orchestrator directory traversal prevention. |
| `tests/test_fuzz_regressions.py` | 23 | Deterministic regression tests for FIND-01 (Unicode digits to ASCII), FIND-02 (embedded `+` removal), FIND-03 (NEL/Line Separator escaping in JSONL), FIND-04 (tail deletion prefix documentation), regression coverage meta-test. |
| `tests/test_fuzz_round2_regressions.py` | 43 | Deterministic regression tests for FIND-05 (denied/allowed CLI bins, interpreter script requirement, uv run flags), FIND-06 (traversal & null byte blocking), FIND-07 (non-HTTP schemes, cloud metadata IPs, loopback blocking), FIND-08 (corrupted JSON lines, BOM, non-dict lines). |
| `tests/test_gpg_anchor.py` | 9 | GPG ledger signing and detached `.asc` verification, tampered ledger detection, `verify_audit.py` exit code 2/4 checks, strict vs non-strict fallback, signed git tags, public key export/import. |
| `tests/test_guardrails.py` | 4 | Enforcement of `passive_only=True`, high-risk skills blocked without `_confirmed=True`, `deny_actions` profile blocking, audit log chain of custody & result SHA-256 hash. |
| `tests/test_manifest.py` | 2 | Artifact Merkle manifest generation, file tampering detection, reproducible run manifest generation and environment difference detection. |
| `tests/test_resilience.py` | 3 | `ResilientLLM` exponential backoff and retry recovery, maximum retries exceeded exception, memory checkpoint save and load. |
| `tests/test_router.py` | 3 | Keyword routing for Thai/Chinese queries (routing to `google-maps-scraper` vs `phone-email-osint`), filtering of unconfirmed actions in investigator profile. |
| `tests/test_s3_worm_adapter.py` | 9 | `S3WormAdapter` COMPLIANCE mode, retention period verification, Object Lock deletion blocking, payload SHA-256 checksum verification, GPG signature inclusion, case anchor listing. |
| `tests/test_stubs_isolation.py` | 2 | `Registry` stub isolation: stubs in `_stubs/` or with `status: stub` are never loaded into the production registry; all loaded skills are `runnable`. |
| `tests/test_trust.py` | 4 | Core trust pipeline integration: audit hash chain, artifact Merkle tree, run manifest environment reproducibility, memory snapshot and restore. |
| **Total** | **171** | **All 171 tests pass synchronously / in CI** |

---

### 2.2 Test Structure & Architecture

1. **Two-Tier Test Design**:
   - **Property-based tests** (`agent/tests/properties/`): Use `hypothesis` to generate hundreds of semi-random, adversarial, and boundary inputs (e.g. malformed JSON, arbitrary Unicode, random binary blobs, concurrency, and rate limiting).
   - **Deterministic unit & regression tests** (`agent/tests/`): Test specific modules, verify bug fixes (e.g. FIND-01 through FIND-08), and validate integration flows with exact assertions.
2. **Hermetic File Isolation**:
   - Tests heavily rely on pytest's `tmp_path` and `tmp_path_factory` fixtures to create isolated directories for audit logs (`audit.jsonl`), anchor ledgers (`ledger.json`), checkpoints, and artifact directories.
3. **Subprocess Invocations**:
   - Standalone verification scripts like `agent/scripts/verify_audit.py` are executed via `subprocess.run([sys.executable, str(VERIFY_SCRIPT), ...])` to verify that external verification tools exit with proper status codes (e.g., exit 0 on success, exit 2 on truncation/tampering, exit 4/5 on GPG failure).

---

### 2.3 Pytest Configuration (`conftest.py`, `conftest_gpg.py`)

1. **`agent/tests/conftest.py`**:
   - **Path Injection**: Resolves `agent/` as `agent_dir` and inserts it at index 0 of `sys.path`. This enables direct imports such as `from core.guardrails import Guardrails`.
   - **Hypothesis Profiles**:
     - `ci`: `max_examples=1000, deadline=None`
     - `dev`: `max_examples=200, deadline=None` (Default loaded if `HYPOTHESIS_PROFILE` is unset)
     - `debug`: `max_examples=50, verbosity=Verbosity.verbose, deadline=None`
     - Setting `deadline=None` is critical across all profiles to prevent test failures on slower CI runners or during heavy background CPU load.
2. **`agent/tests/conftest_gpg.py`**:
   - **Session-scoped Keyring (`_base_gpg_keyring`)**: Finds `gpg` via `_find_gpg()`; if missing, calls `pytest.skip("gpg binary not available")`. Generates an ephemeral 2048-bit RSA key (`test@example.org`) in a temporary directory.
   - **Function-scoped Fixture (`gpg_keyring`)**: Copies the base keyring into a fresh temporary directory per test and sets `GNUPGHOME` in the environment.
   - **Signer Fixture (`gpg_signer`)**: Yields a `GPGSigner(strict=True)` instance tied to the ephemeral keyring.

---

### 2.4 Mocking Strategies for External Services & Networks

1. **AWS S3 / WORM Object Lock**:
   - Uses `moto[server]` (`moto.mock_aws` / `moto.mock_s3`).
   - In `test_s3_worm_adapter.py` and `test_s3_worm_properties.py`, a helper `_patch_moto_for_retention()` monkeypatches Moto's internal `S3Response` to emulate S3 Object Lock retention XML responses and raise `AccessDeniedByLock` upon deletion attempts.
2. **LLM Calls**:
   - Simulated using in-memory mock classes (e.g. `MockFailingLLM` in `test_resilience.py`), verifying retry handling and backoff without making network requests.
3. **HTTP & DNS Calls**:
   - Currently, no external HTTP or DNS requests are made during test runs. URL validation (`_validate_http_url`) in `test_executor_properties.py` only resolves hosts or validates schemas.
   - For new OSINT skills, network mocking can utilize `unittest.mock` / `pytest-mock` (`mocker.patch("requests.get")`, `mocker.patch("dns.resolver.Resolver.resolve")`) or `responses` (which is already installed in the virtual environment).

---

### 2.5 Time-Dependent Logic & Freezegun Usage

1. **Existing Time Handling**:
   - In baseline tests, timestamps are captured using `time.time()` or ISO strings and asserted for presence or type.
   - Tampering tests mutate timestamps arithmetically (`target["ts"] += 999.0`).
   - Anchoring tests use static timestamps (`1700000000.0`, `"2026-11-05T00:00:00Z"`).
2. **Freezegun Requirement for OSINT Skills**:
   - `freezegun` (v1.5.5) is installed in the Python environment.
   - For domain age calculation (`(now - creation_date).days`) and TLS certificate expiration checks in `domain-whois-osint`, time MUST be frozen using `@freeze_time("2026-11-06T12:00:00Z")` or `with freeze_time(...):` so tests remain completely deterministic over time.

---

## 3. v1.4.2 Executor Allowlist & Security Restrictions

### 3.1 Definition Location

The Executor allowlist, path confinement, and SSRF guard are implemented in:
**`agent/core/executor.py`** (v1.4.2).

### 3.2 CLI Allowlist & Denylist

1. **Permitted Binaries (`_ALLOWED_CLI_BINS`)**:
   ```python
   _ALLOWED_CLI_BINS = {"python", "python3", "py", "node", "uv"}
   ```
2. **Denied Binaries (`_DENIED_BINS`)**:
   ```python
   _DENIED_BINS = {
       "cmd", "powershell", "pwsh",
       "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh",
       "rm", "del", "rmdir", "erase", "format", "dd", "mkfs", "shutdown", "reboot",
       "curl", "wget", "nc", "ncat",
       "ssh", "scp", "sftp", "rsync",
       "npx", "uvx",              # supply-chain risk
       "perl", "ruby", "php",
       "regedit", "reg", "reg.exe",
       "sc", "net", "netsh",
   }
   ```
3. **Extension Stripping (`_basename_ci`)**:
   - Strips `.exe`, `.cmd`, `.bat`, `.com`, `.ps1` in a case-insensitive manner before allowlist checking.
4. **Interpreter Confinement**:
   - For interpreter binaries (`python`, `python3`, `py`, `node`), the first non-flag argument must be a script file that resolves within the skill directory.
   - For `uv`, execution is strictly restricted to `uv run <script>`. Flags `--from` and `--with` raise a `PermissionError`.

### 3.3 Path Confinement (`_resolve_within`)

- **Function**: `_resolve_within(skill_dir: pathlib.Path, rel: str) -> pathlib.Path`
- **Restrictions**:
  - Rejects null bytes (`\x00`).
  - Rejects absolute paths (`p_rel.is_absolute()`) and Windows drive letters (`rel[1] == ':'`).
  - Enforces that `candidate.resolve().relative_to(skill_dir.resolve())` succeeds; otherwise raises `ValueError("Path traversal blocked")`.
- **Application**: Applied to `runtime.entry` for Python skills, CLI script arguments, and binary paths.

### 3.4 SSRF Guard (`_validate_http_url`)

- **Permitted Schemes**: Only `"http"` and `"https"`. All other schemes (`file://`, `ftp://`, `gopher://`, etc.) raise `ValueError`.
- **Blocked Cloud Metadata IPs (`_METADATA_IPS`)**:
  - `169.254.169.254` (AWS/GCP/Azure link-local metadata)
  - `169.254.170.2` (AWS ECS task metadata)
  - `100.100.100.200` (Alibaba Cloud metadata)
  - `fd00:ec2::254` (AWS IPv6 metadata)
  - **Invariant**: Metadata IPs are **ALWAYS blocked**, even if `allow_local=True`.
- **Blocked Private/Local Networks (`_BLOCKED_NETS_LOCAL`)**:
  - Blocks RFC 1918, loopback (`127.0.0.0/8`, `::1`), link-local, carrier-grade NAT, multicast, etc.
  - Enforced unless `allow_local=True` is explicitly specified in `runtime`.

### 3.5 Sliding-Window Rate Limiter

- **Class**: `RateLimiter(max_calls=60, period_sec=60.0)`
- Enforces a 60 calls/minute sliding window keyed by skill name (or target domain for HTTP runtime).
- If exceeded, returns `{"ok": False, "error": "Rate limit exceeded for '...'"}`, avoiding process crashes.

### 3.6 Strict Execution Restrictions for the 5 New OSINT Skills

1. **Pure Python Runtime**:
   - Skills must declare `runtime: {type: python, entry: run.py}`.
   - The file `run.py` must be contained within the skill folder (`agent/skills/investigation/<skill-name>/run.py`).
   - The module must export a `run(**kwargs) -> dict` function.
2. **Zero Forbidden Binaries / Shell Calls**:
   - Must NOT shell out to `curl`, `wget`, `whois`, `dig`, `nslookup`, `sh`, or PowerShell.
   - All network calls must be executed using Python standard libraries (`urllib.request`, `socket`) or permitted installed third-party libraries (`dnspython`, `requests`).
3. **SSRF Guard Adherence**:
   - Free public lookups (e.g. crt.sh, RDAP, IP lookups) must only contact public HTTPS endpoints and never cloud metadata or loopback addresses.
4. **Passive-Only Guardrail Enforcement**:
   - All OSINT skills must default to `passive_only: true` in schema and enforce `if not passive_only: raise ValueError(...)`.

---

## 4. Python Environment & Dependency Analysis

### 4.1 Dependency Specifications in the Codebase

- **`agent/requirements-dev.txt`**:
  ```text
  boto3>=1.34
  moto[server]>=5.0
  pytest-mock>=3.12
  hypothesis>=6.100
  freezegun>=1.2
  ```
- **`pyproject.toml`**: Not present in repository.

### 4.2 Installed Packages in Python 3.12 Environment

| Package | Installed Version | Status & Capability for OSINT Suite |
|---|---|---|
| `dnspython` | `2.9.1` | **Installed & Ready**. Supports A, AAAA, MX, NS, TXT record resolution. |
| `requests` | `2.34.2` | **Installed & Ready**. Permitted for HTTPS REST API calls (RDAP, crt.sh, HIBP). |
| `urllib3` | `2.7.0` | **Installed & Ready**. Underlying transport for requests. |
| `freezegun` | `1.5.5` | **Installed & Ready**. Ready for frozen time unit testing. |
| `pytest` | `9.2.0` | **Installed & Ready**. Main test runner. |
| `pytest-mock` | `3.17.0` | **Installed & Ready**. Fixture `mocker` for patching network endpoints. |
| `responses` | `0.26.3` | **Installed & Ready**. Mocking HTTP requests. |
| `hypothesis` | `6.170.14` | **Installed & Ready**. Property-based testing framework. |
| `boto3` / `botocore` | `1.43.96` | **Installed & Ready**. AWS SDK. |
| `moto` | `5.1.22` | **Installed & Ready**. S3 mocking backend. |
| `cryptography` | `50.0.1` | **Installed & Ready**. Cryptographic primitives. |
| `pydantic` | `2.12.5` | **Installed & Ready**. Schema parsing. |
| `python-dateutil`| `2.9.0.post0` | **Installed & Ready**. Robust date parsing for RDAP/WHOIS strings. |
| `whois` | **Not Installed** | `import whois` raises `ModuleNotFoundError`. **Design Decision**: Domain OSINT must use RFC 7482 RDAP via HTTPS and direct socket queries rather than depending on external `python-whois`. |

---

## 5. Regression Risks & Test Execution Guardrails

### 5.1 Invariant: 171 Baseline Tests Must Pass (`pytest` exits 0)
- Running `cd agent; pytest` or `pytest agent/tests` must continue to pass with 171 passed tests.
- When new test files are added (e.g. `agent/tests/test_osint_skills.py`), pytest will collect `171 + N` tests. All existing 171 tests must pass untouched.

### 5.2 Skill Registry & Isolation Guardrails (`test_stubs_isolation.py`)
- In `agent/tests/test_stubs_isolation.py`, `test_registry_filters_by_status()` loads the real registry:
  ```python
  skills_dir = pathlib.Path("skills") if pathlib.Path("skills").exists() else AGENT_DIR / "skills"
  real_reg = Registry(skills_dir)
  assert all(getattr(s, "status", "runnable") == "runnable" for s in real_reg.skills.values())
  ```
- **Critical Risk**: Any new skill added to `agent/skills/investigation/` MUST specify `status: runnable` in its `skill.yaml`. If `status: stub` is placed in a non-stub directory, `test_stubs_isolation.py` will fail!

### 5.3 Router Disruption Risks (`test_router.py`)
- `test_router.py` verifies skill selection order:
  - `"หาเบอร์โทรของร้านอาหารในเชียงใหม่"` must route to `google-maps-scraper` as `hits[0]`.
  - `"追踪电话号码和关联账户"` must route to `phone-email-osint` as `hits[0]`.
  - `"ตรวจสอบเบอร์ +66942638165 และเครือข่ายที่เชื่อมโยง จัดทำสำนวนส่งตำรวจ"` must include `phone-email-osint` and `case-dossier-exporter`, and exclude `google-maps-scraper`.
- **Critical Risk**: New skills must define trigger keywords and categories carefully so they do not inadvertently hijack the top ranking for existing test phrases.

### 5.4 OPSEC & Passive-Only Enforcement (`test_guardrails.py`)
- `Guardrails.allow()` checks `if args.get("passive_only") is False and g.get("passive_only_required", True): return False`.
- In `test_passive_only_enforced()`, skills called with `passive_only=False` must raise `ValueError("...passive_only...")`.
- All new OSINT skills must implement this check at the entry point of `run()`.

### 5.5 Case ID Injection & Schema Compatibility (`test_case_id_injection.py`)
- Skills that accept a `case_id` argument must define it in `input_schema` so `inject_case_id()` can bind the canonical case ID and prevent LLM case redirection attacks.

### 5.6 Test Hermeticity (Zero Network Calls in Unit Tests)
- Real network calls to crt.sh, RDAP, DNS, or APIs during unit tests will introduce network flakiness, latency, and failure if running offline.
- All new skill unit tests must mock external inputs using `unittest.mock.patch`, `pytest-mock`, or `responses`.
- Time-dependent tests must use `freezegun.freeze_time`.

---

## 6. Recommendations for Implementation & Testing

1. **Skill Placement**: Implement the 5 OSINT skills in `agent/skills/investigation/<skill-name>/` with `run.py` and `skill.yaml` (with `status: runnable`).
2. **New Test Suite**: Add comprehensive tests in `agent/tests/test_osint_skills.py` or modular test files in `agent/tests/`:
   - Unit tests covering each skill with mocked DNS (`dnspython`), mocked RDAP/HTTP (`requests`/`urllib`), and mocked API keys.
   - Frozen time tests using `@freeze_time("2026-11-06T12:00:00Z")` for domain age, expiration calculations, and evidence timestamps.
   - Cross-skill invocation test: `domain-whois-osint` invoking `ip-geolocation-osint` via Registry/Executor, with verified fallback when IP skill is unavailable.
   - Scam heuristic tests verifying 0-100 score boundaries, signal weighting, confidence levels, and Thai/English explanations.
   - Evidence structure test verifying `source`, `timestamp`, and `raw_response_sha256` on all claims.
3. **Execution Command**: Verify with:
   ```powershell
   cd agent
   pytest -v
   ```
   Ensuring all 171 existing baseline tests + all new OSINT skill tests pass with 100% success.
