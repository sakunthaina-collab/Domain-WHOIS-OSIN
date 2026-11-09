# Handoff Report — Codebase Architecture, Skill Execution & Cryptographic Audit Pipeline Survey

**Agent**: `survey_explorer_2` (Teamwork Explorer)  
**Date**: 2026-11-06  
**Milestone**: Architecture Survey for Trustworthy Agent v1.5.0 OSINT Skill Suite  
**Working Directory**: `C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\survey_explorer_2`

---

## 1. Observation

1. **Repository Layout and Skill Locations**:
   - `agent/config.yaml` lines 10-15 define paths:
     ```yaml
     paths:
       skills: ./skills
       profiles: ./profiles
       artifacts: ./artifacts
       logs: ./logs
       sandbox: ./sandbox
     ```
   - In `agent/main.py` lines 40-41:
     ```python
     base_dir = pathlib.Path(__file__).resolve().parent
     os.chdir(base_dir)
     ```
     This confirms that when `main.py` runs, working directory is set to `agent/`, making `./skills` resolve to `agent/skills/`.
   - In contrast, the root directory `skills/` contains `.curated/` (39 items) and `.system/` (5 items) with only `SKILL.md` markdown files and **zero `skill.yaml` manifests** (verified via `find_by_name Pattern="skill.yaml"` returning 0 results).
   - In `agent/tests/conftest.py` lines 8-11:
     ```python
     agent_dir = str(pathlib.Path(__file__).resolve().parent.parent)
     if agent_dir not in sys.path:
         sys.path.insert(0, agent_dir)
     ```
     This puts `agent/` at the head of `sys.path`, so Python imports like `from skills.investigation.phone_email_osint_entry import phone_email_osint` resolve to `agent/skills/investigation/phone_email_osint_entry.py`.

2. **Skill Inventory and Registry**:
   - Running `python agent/scripts/audit_skill_inventory.py` produced:
     ```text
     Total inventory items: 458
       ✅ runnable:  124  (Fully operational with code/CLI/scripts)
       ⚠️  stubs:     334  (Guides only, isolated in _stubs/)
       ❌ broken:      0  (No broken manifests)
     Duplicates found: 0 
     Runnable by category:
       - docs            :   9
       - engineering     :  46
       - external        :  15
       - investigation   :   8
       - lifesci         :  41
       - scraping        :   5
     Stubs by category (awaiting implementation):
       - docs            :  31
       - engineering     : 252
       - external        :  16
       - investigation   :   2
       - lifesci         :  23
       - scraping        :  10
     ```
   - In `agent/core/registry.py` lines 55-73:
     ```python
     class Registry:
         def __init__(self, root: str | pathlib.Path = "skills", include_stubs: bool = False):
             self.root = pathlib.Path(root)
             self.include_stubs = include_stubs
             self.skills: dict[str, Skill] = {}
             self.all_loaded: list[Skill] = []
             if self.root.exists():
                 for p in sorted(self.root.rglob("skill.yaml")):
                     d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                     valid_keys = {k: v for k, v in d.items() if k in Skill.__dataclass_fields__}
                     s = Skill(**valid_keys)
                     s.dir = p.parent
                     self.all_loaded.append(s)
                     is_stub = s.status == "stub" or "_stubs" in p.parts
                     if not include_stubs and is_stub:
                         continue
                     existing = self.skills.get(s.name)
                     if existing is None or (existing.status == "stub" and s.status == "runnable"):
                         self.skills[s.name] = s
     ```
     Stubs are strictly excluded unless `include_stubs=True`.

3. **Executor Execution Mechanics & Security Controls**:
   - In `agent/core/executor.py` lines 180-215:
     ```python
     rt = getattr(skill, "runtime", None) or {}
     t = rt.get("type", "python")
     # ...
     if t == "python":
         return self._run_python(skill, args)
     ```
     For python skills, `_run_python` dynamically loads `entry = _resolve_within(skill_dir, rt["entry"])` and calls `res = mod.run(**args)`.
   - Security constraints in `core/executor.py`:
     - CLI allowlist (lines 25-39): `_ALLOWED_CLI_BINS = {"python", "python3", "py", "node", "uv"}`. Denies shells (`cmd`, `powershell`, `bash`, `sh`), network downloaders (`curl`, `wget`), and dangerous utils (`rm`, `del`).
     - Path confinement (lines 100-118): `_resolve_within` rejects absolute paths, null bytes, and traversal outside `skill_dir`.
     - SSRF Guard (lines 42-56, 121-149): Blocks cloud metadata IPs (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`) and private/loopback IP blocks unless `allow_local=True`.

4. **Cryptographic Audit Hash Chain & Merkle Ledger**:
   - **Hash Chain** (`agent/core/guardrails.py` lines 88-135):
     `Guardrails.audit(...)` computes `args_sha256 = _sha(args)` and `result_sha256 = _sha(result)`.
     Under OS file lock (`core/file_lock.py`), it reads `prev_hash` from the file's tail (or genesis `0` * 64) and computes:
     ```python
     rec["entry_hash"] = hashlib.sha256(
         (json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str) + prev).encode("utf-8")
     ).hexdigest()
     ```
     Appends to both `logs/audit.jsonl` (global) and `artifacts/<case_id>/audit.jsonl` (case log) followed by `os.fsync()`.
   - **Merkle Ledger** (`agent/core/artifact_manifest.py` lines 9-53):
     `_compute_merkle_root(leaf_hashes)` sorts leaves, pairs them recursively combining hashes via `hashlib.sha256((left + right).encode("utf-8")).hexdigest()`, and produces the 64-char `merkle_root`.
     `build_artifact_manifest(case_dir)` scans all files in `artifacts/<case_id>/` (excluding `artifact_manifest.json`), computes their SHA-256 hashes, generates `merkle_root`, and writes `artifact_manifest.json`.
   - **External Anchoring** (`agent/core/anchor.py` lines 113-140):
     `Anchor.anchor(...)` reads `head_hash` and `entry_count`, appends to `logs/anchor_ledger.json`, signs via GPG (`anchor_ledger.json.asc`), and anchors via Git tag (`anchor/<case_id>/<head_hash[:12]>`) or S3 WORM (`S3WormAdapter`).

5. **Existing Investigation Skills and Stubs/Mocks**:
   - In `agent/skills/investigation/phone-email-osint/run.py` lines 12-25:
     ```python
     inspector_script = pathlib.Path.home() / ".gemini/config/plugins/phone-email-osint/scripts/osint_inspector.py"
     if inspector_script.exists():
         proc = subprocess.run([sys.executable, str(inspector_script), target], ...)
         # ...
     return {"ok": True, "target": target, "target_type": target_type, "passive_only": True, "timestamp": ...}
     ```
     Currently delegates via subprocess to an external script outside the repository, falling back to a static stub dictionary.
   - `domain-whois-osint`: Already created under `agent/skills/investigation/domain-whois-osint/` with `run.py` implementing DNS, RDAP, crt.sh, scam heuristic, and cross-skill lookup.
   - `ip-geolocation-osint`, `email-osint`, and `breach-check`: Missing from `agent/skills/investigation/`.
   - `cyber-intelligence-osint-investigator` and `telegram-playbooks`: Located under `agent/skills/_stubs/investigation/` with `status: stub` and `entry: SKILL.md`.

6. **Baseline Test Suite**:
   - Executing `pytest agent/tests` and `python agent/scripts/verify_all.py --base-dir agent`:
     Result: **171 passed in 36.18s**, exit code 0. Zero regressions against baseline.

---

## 2. Logic Chain

1. From Observation 1, the authoritative location for skills is `agent/skills/` (and `agent/skills/investigation/`). The root `skills/` directory contains external markdown files and no `skill.yaml` manifests.
2. From Observation 2, `Registry` automatically discovers all `skill.yaml` files under `agent/skills/`. Any new skill placed in `agent/skills/investigation/<skill-name>/skill.yaml` with `status: runnable` and `category: investigation` is immediately indexed and available to the `investigator` profile (`Profile.categories = ["investigation", "docs"]`).
3. From Observation 3, when `Executor.run()` executes a Python skill, it imports `run.py` and calls `run(**args)`. Therefore, all skill entry points must define a top-level `run(...)` function accepting JSON-serializable keyword arguments and returning a JSON-serializable dictionary.
4. From Observation 1 and 3, in cross-skill invocation (e.g. `domain-whois-osint` invoking `ip-geolocation-osint`), calling `Registry()` from within a skill without an explicit root directory resolves to `pathlib.Path("skills")`. When tests are run from the repository root rather than `agent/`, `pathlib.Path("skills")` points to the root directory which has 0 skills. Therefore, cross-skill lookups must resolve the path dynamically relative to `__file__` (e.g. `pathlib.Path(__file__).resolve().parent.parent.parent`) or accept injected `registry` / `executor` via `**kwargs`.
5. From Observation 4, the Trustworthy Agent pipeline automatically binds skill outputs into the cryptographic chain:
   - Orchestrator automatically invokes `Guardrails.audit(...)` with the skill's return dictionary, creating `result_sha256` and linking `entry_hash` into `audit.jsonl`.
   - Orchestrator automatically writes `raw/<seq>_<name>.json` to `artifacts/<case_id>/raw/`.
   - At case completion, `build_artifact_manifest()` hashes all files in `artifacts/<case_id>/` into the Merkle tree, generating `merkle_root`.
   - Therefore, to satisfy R3 and court admissibility, each skill's internal payload must also include an explicit `evidence` list tracking `{"claim": ..., "source": ..., "retrieved_at": ..., "raw_response_sha256": ...}`.
6. From Observation 5, existing tests (`agent/tests/test_guardrails.py`, `agent/tests/test_router.py`, `agent/tests/test_trust.py`) import and assert `phone-email-osint`. While implementing the 5 skills (Tier 1: `domain-whois-osint`, `ip-geolocation-osint`, `email-osint`; Tier 2: `phone-osint`, `breach-check`), `phone-email-osint` must either be maintained as an alias/entry point or retain exact trigger/argument signatures so that no existing test breaks.
7. From Observation 6, all 171 tests currently pass, establishing a strict regression baseline.

---

## 3. Caveats

1. **Root Directory `skills/`**: Do not confuse `agent/skills/investigation/` with root `skills/investigation/`. Root `skills/` contains upstream external skills (`.curated/`, `.system/`). Placing skills there will not be discovered by `Registry` or the test suite.
2. **Pre-built Dependencies**: `dnspython`, `requests`, and `freezegun` are verified installed and working. However, third-party libraries such as `whois` or `python-whois` are **not installed**. WHOIS queries must be performed via raw sockets (`socket` module to whois servers on port 43) or via RDAP REST endpoints (`urllib.request`).
3. **Network Constraints during Testing**: Live external endpoints (e.g. `crt.sh`, RDAP, public IP APIs) must never be hit during automated tests. All tests must use `unittest.mock.patch` or static fixture dictionaries with frozen time (`freezegun`).

---

## 4. Conclusion

1. **Location**: All 5 skills belong in `agent/skills/investigation/<skill-name>/` with valid `skill.yaml` and `run.py`.
2. **Suite Structure**:
   - `domain-whois-osint` (Tier 1): Already structured with DNS, RDAP, crt.sh, scam heuristic (0-100), and evidence tracking.
   - `ip-geolocation-osint` (Tier 1): Must be implemented with free public lookups (e.g., ip-api, ipinfo) and socket fallback, returning country, city, ASN, ISP, bogon/Tor status, and evidence tracking.
   - `email-osint` (Tier 1): Must be implemented with syntax validation, MX query via dnspython/socket, disposable domain check, Gravatar SHA256 check, and evidence tracking.
   - `phone-osint` / `phone-email-osint` (Tier 2): Must replace the subprocess mock in `phone-email-osint/run.py` with 100% original proprietary code. Accepts `NUMVERIFY_API_KEY` via env var with graceful offline heuristic fallback, maintaining backward compatibility with `test_guardrails.py`.
   - `breach-check` (Tier 2): Must be implemented checking HaveIBeenPwned API (`HIBP_API_KEY`) or k-anonymity SHA-1 prefix endpoint with graceful error handling when key is missing.
3. **Forensic Contract**: Every skill must return `{"ok": True, ..., "evidence": [{"claim": ..., "source": ..., "retrieved_at": ..., "raw_response_sha256": ...}]}`.
4. **Comprehensive Architecture Report**: Saved in full at `C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\survey_explorer_2\architecture_report.md`.

---

## 5. Verification Method

1. **Inspect Artifacts**:
   - Check `architecture_report.md`:
     `view_file C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\.agents\teamwork\survey_explorer_2\architecture_report.md`
2. **Verify Skill Inventory & Isolation**:
   - Command: `python agent/scripts/audit_skill_inventory.py`
   - Expected Output: 458 total items, 124 runnable, 334 stubs, 0 broken, 0 duplicates.
3. **Verify Baseline Test Suite**:
   - Command: `python agent/scripts/verify_all.py --base-dir agent`
   - Expected Output: `171 passed`, exit code 0, and `🎉 ALL VERIFICATION CHECKS PASSED: SYSTEM FULLY TRUSTWORTHY`.
4. **Invalidation Conditions**:
   - Any test failure in `pytest agent/tests` (less than 171 tests passing).
   - Any leakage of stubs into runnable inventory.
   - Discrepancy between `args_sha256` / `result_sha256` and the actual JSON output in `Guardrails.audit`.
