# Trustworthy Agent Architecture & Forensic Pipeline Survey Report

**Author**: survey_explorer_2 (Teamwork Explorer Subagent)  
**Date**: 2026-11-06  
**Target System**: Trustworthy Agent v1.5.0  
**Scope**: Codebase architecture, skill execution, cross-skill invocation, cryptographic audit hash chain, Merkle ledger pipeline, and investigation skill inventory.

---

## Executive Summary

Trustworthy Agent is an enterprise- and court-grade forensic AI agent architecture adhering to international evidentiary standards (ISO/IEC 27037:2012, ISO/IEC 27041:2015, Thai Anti-Trafficking Act B.E. 2551, and Taiwan Code of Criminal Procedure). The system grounds its trustworthiness in **5 Cryptographic Pillars**:
1. **Pillar 1 — Tamper-Evident Dual Audit Hash Chain** (`logs/audit.jsonl` and `artifacts/<case_id>/audit.jsonl`).
2. **Pillar 2 — External Multi-Adapter Anchoring** (`logs/anchor_ledger.json`, GPG-signed ledger, signed Git tags, and S3 WORM Object Lock).
3. **Pillar 3 — Merkle Root Artifact Manifest** (`artifacts/<case_id>/artifact_manifest.json` computing a binary Merkle tree across all output files).
4. **Pillar 4 — Deterministic Run Manifest & Reproducibility** (`00_run_manifest.json` tracking registry hash, seed, models, and parameters).
5. **Pillar 5 — Strict Stub Isolation** (strict separation of runnable production skills from 334 documentation stubs in `_stubs/`).

This survey details the exact codebase structure, execution models, cross-skill invocation contracts, cryptographic linking mechanics, and existing stubs/mocks to guide the development and integration of the 5 production-grade OSINT skills.

---

## 1. Project Repository Layout & Skill Organization

### 1.1 Directory Structure & Skill Locations
The workspace contains two distinct `skills` directories that serve entirely different purposes:

1. **`agent/skills/` (Authoritative Agent Skill Repository)**:
   - Configured in `agent/config.yaml` as `paths.skills: ./skills`.
   - When the agent executes (`agent/main.py`), it sets `os.chdir("agent")`, making `agent/skills/` the root of all discoverable skills.
   - Organized into categories: `investigation/`, `engineering/`, `docs/`, `lifesci/`, `external/`, `scraping/`.
   - Contains both active runnable skills (e.g., `agent/skills/investigation/case-dossier-exporter/`) and isolated documentation stubs located strictly under `agent/skills/_stubs/<category>/`.
   - In Python import terms, `agent/tests/conftest.py` adds `agent/` to `sys.path`. Consequently, imports such as `from skills.investigation.phone_email_osint_entry import phone_email_osint` resolve to `agent/skills/investigation/phone_email_osint_entry.py`.

2. **`skills/` (External / Catalog Skills Directory)**:
   - Root directory containing `.curated/` and `.system/` folders (such as `aspnet-core`, `linear`, `figma`, `plugin-creator`).
   - Contains only markdown documentation files (`SKILL.md`) and lacks `skill.yaml` manifests.
   - The production Registry scans for `skill.yaml` and therefore ignores this root folder completely.

### 1.2 Skill Inventory Breakdown
Audited via `python agent/scripts/audit_skill_inventory.py`:
- **Total Manifests**: 458
- **Runnable Skills**: 124 (fully implemented with Python entry points or CLI allowlist runners)
- **Stubs**: 334 (documentation-only, quarantined in `_stubs/`)
- **Broken Manifests**: 0
- **Duplicates**: 0
- **Investigation Category**:
  - Runnable (8): `case-dossier-exporter`, `counter-fraud-disruption`, `digital-forensics-investigator`, `domain-whois-osint`, `phone-email-osint`, `secops-detection-engineering`, `syndicate-roster-tracker`, `system-architecture-planner`.
  - Stubs (2): `cyber-intelligence-osint-investigator`, `telegram-playbooks`.

---

## 2. Skill Registry & Skill Loader Architecture

### 2.1 Discovery & Loading (`core/registry.py`)
- **Class `Registry(root="skills", include_stubs=False)`**:
  - Scans recursively using `self.root.rglob("skill.yaml")`.
  - For each `skill.yaml`, parses YAML data using `yaml.safe_load`.
  - Maps data into the `@dataclass Skill` object, capturing `s.dir = p.parent`.
  - **Stub Quarantine**: If `s.status == "stub"` or `"_stubs"` is in `p.parts`, the skill is flagged as a stub. Unless `include_stubs=True` is explicitly passed (CLI `--include-stubs`), stubs are excluded from `self.skills`.
  - **Precedence**: If duplicate names exist, a `runnable` skill replaces any existing `stub`.
  - Exposes `reg.get(name)` to retrieve a `Skill` by name.
  - Exposes `reg.subset(categories)` to filter by profile categories.
  - Exposes `reg.to_openai_tools(names)` to format tool definitions into standard OpenAI/DeepSeek function calling JSON schemas.

### 2.2 Skill Specification Contract (`skill.yaml`)
Each skill must define:
```yaml
name: <skill-name>                      # e.g., domain-whois-osint
version: 1.0.0                          # semantic version
category: investigation                 # must match profile category
status: runnable                        # runnable | stub | deprecated
description: >                          # rich description used by BM25 Router
  ...
triggers:                               # keyword triggers for Router scoring
  - "..."
input_schema:                           # JSON Schema for function calling
  type: object
  properties:
    ...
  required: [...]
runtime:
  type: python                          # python | cli | http
  entry: run.py                         # relative script entry within skill directory
  timeout: 30                           # seconds
permissions: [network]                  # filesystem:read, network, etc.
risk: low                               # low | medium | high
outputs: [json, markdown]
```

---

## 3. Executor Execution Model & Security Sandboxing

### 3.1 Executor Core (`core/executor.py`)
- **Class `Executor(sandbox="sandbox", max_timeout=900, rate_limit_per_min=60)`**:
  - Checks sliding-window rate limiting (`RateLimiter.acquire(key)`).
  - Dispatches execution based on `skill.runtime["type"]`.

### 3.2 Python Execution Path (`_run_python`)
```python
def _run_python(self, skill: Any, args: dict[str, Any]) -> dict[str, Any]:
    rt = skill.runtime
    skill_dir = (getattr(skill, "dir", None) or pathlib.Path(".")).resolve()
    entry = _resolve_within(skill_dir, rt["entry"])
    if not entry.is_file():
        raise ValueError(f"entry not found: {rt['entry']}")

    spec = importlib.util.spec_from_file_location(
        getattr(skill, "name", "skill").replace("-", "_"), entry
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    res = mod.run(**args)
    return res if isinstance(res, dict) else {"ok": True, "result": res}
```
**Key Constraints**:
- The entry script must be loaded dynamically within `skill_dir`.
- It executes `mod.run(**args)`. Keyword arguments are unpacked directly from the arguments dictionary.
- The return value must be a dictionary (or wrapped in `{"ok": True, "result": res}`).

### 3.3 Security Guardrails (v1.4.2 Allowlist & Path Confinement)
- **Path Traversal Prevention (`_resolve_within`)**: Blocks `..`, absolute paths (including Windows drive letters `C:`), null bytes `\x00`, and symlink escapes.
- **Strict CLI Binary Allowlist (`_is_allowed_bin`)**:
  - Permitted binaries: `_ALLOWED_CLI_BINS = {"python", "python3", "py", "node", "uv"}`.
  - Explicitly banned binaries (`_DENIED_BINS`): `cmd`, `powershell`, `pwsh`, `bash`, `sh`, `rm`, `del`, `curl`, `wget`, `nc`, `npx`, `uvx`, etc.
  - Interpreter safety: the script argument must resolve within `skill_dir`.
- **SSRF Guard (`_validate_http_url`)**:
  - Prohibits cloud metadata IPs (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`).
  - Prohibits private and loopback networks (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `::1/128`, etc.) unless `allow_local=True` is declared.

---

## 4. Cross-Skill Invocation Architecture

### 4.1 Invocation Pattern
In the current architecture, skills run inside independent modules loaded via `importlib`. To enable cross-skill invocation (e.g., Domain skill querying IP Geolocation skill):
1. **Registry Lookup**: A caller skill queries the central `Registry` for the target skill:
   ```python
   from core.registry import Registry
   from core.executor import Executor

   reg = Registry()
   ip_skill = reg.skills.get("ip-geolocation-osint")
   ```
2. **Execution via Executor**:
   ```python
   if ip_skill and getattr(ip_skill, "status", None) == "runnable":
       res = Executor().run(ip_skill, {"ip": target_ip, "passive_only": True})
   ```
3. **Graceful Fallback**: If `ip-geolocation-osint` is not installed, disabled, or fails during runtime, the calling skill must catch exceptions and fall back to local heuristics (e.g. reverse DNS lookup via `socket.gethostbyaddr(ip)` or basic bogon checks) without throwing an uncaught exception.

### 4.2 Path Resolution Invariant
When `Registry()` is instantiated without arguments, its default root is `pathlib.Path("skills")`.
- When running from `agent/`, `pathlib.Path("skills")` resolves correctly to `agent/skills`.
- When executed from the repository root (or inside unit tests running from the root), `pathlib.Path("skills")` points to the root `skills/` directory which contains zero `skill.yaml` files.
- **Architecture Best Practice for Cross-Skill Invocation**:
  Skills should discover the skills directory robustly:
  ```python
  skills_root = pathlib.Path(__file__).resolve().parent.parent.parent
  reg = Registry(root=skills_root if (skills_root / "investigation").exists() else "skills")
  ```
  Alternatively, skills can accept an optional `registry=None` and `executor=None` in `**kwargs` for dependency injection during integration and unit tests.

---

## 5. Cryptographic Audit, Merkle Ledger & Tamper-Evident Reporting

### 5.1 The 5 Pillars of Forensic Trust

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Trustworthy Agent Pipeline                      │
│                                                                        │
│   [Tool Call] ──► Guardrails.allow()                                   │
│                         │                                              │
│                   Executor.run()                                       │
│                         │                                              │
│   ┌─────────────────────┴──────────────────────┐                       │
│   ▼                                            ▼                       │
│ Pillar 1: Hash Chain Audit               Pillar 3: Merkle Manifest     │
│ Guardrails.audit()                       Memory.save_artifact()        │
│   - args_sha256                              - raw/<seq>_<name>.json   │
│   - result_sha256                            - dossier.md              │
│   - prev_hash ──► entry_hash                 - 00_run_manifest.json    │
│   - logs/audit.jsonl                         build_artifact_manifest() │
│   - artifacts/<case>/audit.jsonl             - SHA256 of all files     │
│         │                                    - Merkle Root hash        │
│         ▼                                                              │
│ Pillar 2: External Anchor                                              │
│ Anchor.anchor()                                                        │
│   - anchor_ledger.json (+ .asc GPG)                                    │
│   - Git Tag / S3 WORM Object Lock                                      │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Hash Chain Audit Logging (`core/guardrails.py`)
- Every execution step triggers `Guardrails.audit(...)`.
- **Atomic Concurrency**: Uses OS-level file locking (`msvcrt.locking` on Windows, `fcntl.flock` on POSIX via `core/file_lock.py`).
- **Chain Linking**:
  - Genesis block: `prev_hash = "0" * 64`.
  - For each new record, reads `prev_hash` from the last valid line.
  - Constructs `entry_hash = hashlib.sha256((json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str) + prev).encode("utf-8")).hexdigest()`.
  - Calls `os.fsync` after write to ensure durability against power loss or crashes.
- **UTF-8 Resilience**: Escapes Unicode line separators (`U+0085`, `U+2028`, `U+2029`) via `_safe_json_line` to prevent line-injection attacks. Verifier uses `encoding="utf-8-sig"` to strip BOM.

### 5.3 Artifact Manifest & Merkle Ledger (`core/artifact_manifest.py`)
- **Leaf Hashing**: Scans `artifacts/<case_id>/` (excluding `artifact_manifest.json`). Every file (including `raw/*.json`, `audit.jsonl`, `checkpoint.json`, and markdown reports) is read, and its SHA-256 digest is calculated.
- **Binary Merkle Tree Computation (`_compute_merkle_root`)**:
  - Sorts leaf hashes deterministically: `current_level = sorted(leaf_hashes)`.
  - Combines adjacent pairs: `hashlib.sha256((left + right).encode("utf-8")).hexdigest()`.
  - If a level has an odd number of nodes, the last node is paired with itself: `right = current_level[i + 1] if i + 1 < len(current_level) else left`.
  - Iterates upward until a single 64-character hexadecimal `merkle_root` is produced.
  - Generates `artifact_manifest.json`:
    ```json
    {
      "case_dir": "...",
      "created_at": 1793946767.086,
      "file_count": 8,
      "merkle_root": "4836a6a771d7d9c68f9e209d6ed531b4efdddb74f6cc8e628fb75a3ac3ab0cdc",
      "files": [
        {"path": "raw/001_domain-whois-osint.json", "size_bytes": 601, "sha256": "..."}
      ]
    }
    ```
- **Integrity Verification (`verify_artifacts`)**: Checks for `MISSING`, `TAMPERED`, `UNMANIFESTED_FILE`, and `MERKLE_ROOT_MISMATCH`.

### 5.4 External Anchoring (`core/anchor.py`)
- Reads the audit chain's `head_hash` and `entry_count`.
- Appends to `logs/anchor_ledger.json`.
- Layer 1: GPG-signs the ledger (`anchor_ledger.json.asc`).
- Layer 2: Anchors to external systems:
  - Git Tag: `anchor/<case_id>/<head_hash[:12]>` with GPG signature.
  - S3 Object Lock (WORM): Stores in AWS S3 with `COMPLIANCE` or `GOVERNANCE` retention.

### 5.5 Forensic Output Attributes & Evidence Tracking Contract
To seamlessly integrate with Trustworthy Agent's legal chain-of-custody, every skill output must adhere to the forensic output schema:
1. **Top-Level Status**: `"ok": True` or `"ok": False`.
2. **Target & Metadata**:
   - `"target"` / `"domain"`: normalized target identifier.
   - `"target_type"`: `"domain"`, `"ip"`, `"email"`, `"phone"`, or `"breach"`.
   - `"passive_only"`: strictly `True`.
   - `"timestamp_utc"`: ISO-8601 UTC timestamp (e.g. `2026-11-06T12:00:00Z`).
   - `"latency_sec"`: float execution duration.
3. **Evidence Tracking Triple (`evidence` array)**:
   Every individual claim/data point must include an evidence record:
   - `claim`: descriptive label of the finding (e.g. `dns_a_records`, `whois_registration`, `hibp_breach_match`).
   - `source`: URL, endpoint, or query executed (e.g. `https://rdap.org/domain/...`, `DNS query MX example.com`).
   - `retrieved_at`: ISO-8601 UTC timestamp.
   - `raw_response_sha256`: SHA-256 hexadecimal hash of the verbatim raw response payload before extraction.
4. **Explainable Scam Heuristic Structure** (for scam assessment):
   - `scam_risk_score`: integer `0` to `100`.
   - `confidence`: `"low"`, `"medium"`, or `"high"`.
   - `signals`: list of evaluated risk factors with `factor`, `weight`, `value`, and `detail`.
   - `top_reason_th`: Thai plain-language explanation.
   - `top_reason_en`: English plain-language explanation.

---

## 6. Existing Skill Stubs, Mocks, and Replacement Analysis

| Skill Directory | Current Status | Current Implementation / Mock Logic | Action Required for v1.5.0 Suite |
|---|---|---|---|
| `phone-email-osint` | Runnable (Mock/Subprocess) | Attempts subprocess call to `~/.gemini/config/plugins/.../osint_inspector.py`. If missing, returns hardcoded fallback dictionary. | **Must replace mock logic** with 100% original proprietary code. Split into Tier 1 `email-osint` and Tier 2 `phone-osint`, maintaining `phone-email-osint` alias for backward test compatibility. |
| `domain-whois-osint` | Runnable (New Implementation) | Full production implementation of DNS, RDAP, crt.sh, IP enrichment, scam scoring, and evidence tracking. | First skill of the suite. Ready for full deterministic test coverage. |
| `ip-geolocation-osint` | Missing (Target for Suite) | None. (Referenced in `domain-whois-osint` cross-skill query). | **Implement Tier 1 skill**: free public lookups (IP-API / ipinfo / RDAP), ASN, ISP, country, city, bogon/Tor checks, evidence tracking. |
| `email-osint` | Missing (Target for Suite) | None. | **Implement Tier 1 skill**: syntax validation, MX lookup, disposable domain detection, Gravatar hash check, SMTP simulation, evidence tracking. |
| `breach-check` | Missing (Target for Suite) | None. | **Implement Tier 2 skill**: HaveIBeenPwned API check via env var `HIBP_API_KEY`, k-anonymity SHA-1 prefix check / safe fallback, evidence tracking. |
| `cyber-intelligence-osint-investigator` | Stub (`_stubs/investigation/`) | `status: stub`, `entry: SKILL.md`. No Python code. | Remains in `_stubs/` (isolated). |
| `telegram-playbooks` | Stub (`_stubs/investigation/`) | `status: stub`, `entry: SKILL.md`. No Python code. | Remains in `_stubs/` (isolated). |
| `secops-detection-engineering` | Runnable (Static Stub) | Returns static dict with `source_skill_md`. | Existing skill; preserve to avoid test regression. |
| `system-architecture-planner` | Runnable (Static Stub) | Returns static dict with `source_skill_md`. | Existing skill; preserve to avoid test regression. |
| `case-dossier-exporter` | Runnable (Hardcoded) | Generates bilingual markdown with hardcoded suspect aliases. | Existing skill; preserve to avoid test regression. |
| `digital-forensics-investigator` | Runnable (Static Mock) | Returns hardcoded roaming analysis and MACB events. | Existing skill; preserve to avoid test regression. |
| `counter-fraud-disruption` | Runnable (Static Stub) | Returns static passive abuse package confirmation. | Existing skill; preserve (tests check high-risk guardrail). |

---

## 7. Exact Module Paths, Class Names, Function Signatures, and Data Contracts

### 7.1 Registry & Discovery (`core.registry`)
- **Module Path**: `agent/core/registry.py`
- **Class `Skill`**:
  ```python
  @dataclass
  class Skill:
      name: str
      description: str
      category: str
      input_schema: dict[str, Any]
      runtime: dict[str, Any]
      version: str = "1.0.0"
      status: str = "runnable"  # runnable | stub | deprecated
      triggers: list[str] = field(default_factory=list)
      permissions: list[str] = field(default_factory=list)
      risk: str = "low"
      outputs: list[str] = field(default_factory=list)
      dir: pathlib.Path | None = None
      def get(self, key: str, default: Any = None) -> Any: ...
  ```
- **Class `Profile`**:
  ```python
  @dataclass
  class Profile:
      name: str
      model: str
      categories: list[str]
      top_k: int = 12
      temperature: float = 0.2
      escalate_model: str | None = None
      seed: int = 42
      system_prompt: str = "You are a helpful AI agent."
      guardrails: dict[str, Any] = field(default_factory=dict)
      @classmethod
      def from_yaml(cls, path: str | pathlib.Path) -> Profile: ...
  ```
- **Class `Registry`**:
  ```python
  class Registry:
      def __init__(self, root: str | pathlib.Path = "skills", include_stubs: bool = False): ...
      def get(self, name: str) -> Skill | None: ...
      def subset(self, categories: list[str] | None = None) -> list[Skill]: ...
      def to_openai_tools(self, names: list[str]) -> list[dict[str, Any]]: ...
  ```

### 7.2 Execution Sandboxing (`core.executor`)
- **Module Path**: `agent/core/executor.py`
- **Class `Executor`**:
  ```python
  class Executor:
      def __init__(self, sandbox: str | pathlib.Path = "sandbox", max_timeout: int = 900, rate_limit_per_min: int = 60): ...
      def run(self, skill: Any, args: dict[str, Any]) -> dict[str, Any]: ...
  ```
- **Security Helpers**:
  - `_resolve_within(skill_dir: pathlib.Path, rel: str) -> pathlib.Path`
  - `_is_allowed_bin(bin_path: str) -> bool`
  - `_validate_http_url(url: str, allow_local: bool = False) -> str`

### 7.3 Audit Hash Chain & Guardrails (`core.guardrails`)
- **Module Path**: `agent/core/guardrails.py`
- **Class `Guardrails`**:
  ```python
  class Guardrails:
      def __init__(self, log_path: str = "logs/audit.jsonl", case_id: Optional[str] = None, artifacts_root: str = "artifacts"): ...
      def allow(self, skill, args: dict, profile: Any) -> bool: ...
      def audit(
          self,
          skill,
          args: dict,
          step: int,
          case_id: Optional[str] = None,
          result: Optional[Any] = None,
          status: str = "ok",
          latency_ms: float = 0,
          parent_step: Optional[int] = None,
          dry_run: bool = False,
      ) -> dict: ...
  ```
- **Verification Helper**:
  - `verify_audit_chain(log_path: str) -> tuple[bool, str]`

### 7.4 Merkle Ledger & Manifest (`core.artifact_manifest`)
- **Module Path**: `agent/core/artifact_manifest.py`
- **Functions**:
  ```python
  def _compute_merkle_root(leaf_hashes: list[str]) -> str: ...
  def build_artifact_manifest(case_dir: str | pathlib.Path) -> dict[str, Any]: ...
  def verify_artifacts(case_dir: str | pathlib.Path) -> list[str]: ...
  ```

### 7.5 External Anchoring (`core.anchor`)
- **Module Path**: `agent/core/anchor.py`
- **Class `Anchor`**:
  ```python
  class Anchor:
      def __init__(self, adapter: str = "git", ledger_path: str = "logs/anchor_ledger.json", gpg_signer: Optional[GPGSigner] = None, **adapter_cfg): ...
      def anchor(self, case_id: str, audit_path: str) -> dict: ...
      def last_anchor(self, case_id: str) -> Optional[dict]: ...
      def verify_ledger_signature(self) -> tuple[bool, str]: ...
  ```
- **Class `S3WormAdapter`**:
  ```python
  class S3WormAdapter:
      def __init__(self, bucket: str, mode: str = "COMPLIANCE", retention_days: int = 2555, prefix: str = "anchors/", s3_client: Optional[S3Client] = None, region: str = "us-east-1"): ...
      def anchor(self, rec: dict, sig_path: Optional[str] = None) -> dict: ...
  ```

### 7.6 Case ID Validation & Memory (`core.case_id`, `core.memory`)
- **Module Paths**: `agent/core/case_id.py`, `agent/core/memory.py`
- **Functions & Classes**:
  ```python
  # core/case_id.py
  def validate_case_id(case_id: str) -> str: ...
  def is_valid_case_id(case_id: str) -> bool: ...

  # core/memory.py
  class Memory:
      def __init__(self, case_id: str = "DEFAULT-CASE", artifacts_root: str | pathlib.Path = "artifacts"): ...
      def save_artifact(self, filename: str, data: Any, raw: bool = True) -> pathlib.Path: ...
  ```

---

## 8. Architectural Recommendations for Skill Implementation

1. **Deterministic Testing & Frozen Time**:
   - Time calculations (such as domain age, certificate expiration, breach dates) must accept an optional `ref_date: datetime | None = None` parameter or be mocked using `freezegun.freeze_time("2026-11-06T12:00:00Z")`.
   - All network calls (RDAP, DNS, HTTP endpoints) must be cleanly mockable via `unittest.mock.patch` (`requests.get`, `urllib.request.urlopen`, `dns.resolver.Resolver.resolve`) to guarantee deterministic unit test execution with zero live network calls.

2. **Backward Compatibility & Regression Guardrails**:
   - `test_guardrails.py` specifically tests `skills.investigation.phone_email_osint_entry.phone_email_osint`. When implementing `phone-osint` and `email-osint`, preserve or update `phone_email_osint_entry.py` and `agent/skills/investigation/phone-email-osint/run.py` so that `test_guardrails.py`, `test_router.py`, and `test_trust.py` pass with zero regressions.
   - All 171 existing repository tests must pass on every change.

3. **Cross-Skill Dependency Injection**:
   - In `domain-whois-osint`, allow `registry: Optional[Registry] = None` and `executor: Optional[Executor] = None` to be passed via kwargs to enable controlled, mockable cross-skill integration tests.
   - When instantiated internally, resolve `skills` path dynamically to ensure it works whether pytest is invoked from `agent/` or the repository root.

4. **Cryptographic Linking Verification**:
   - Ensure every output dictionary contains the evidence tracking triple (`source`, `retrieved_at`, `raw_response_sha256`) and valid JSON serialization to guarantee clean `args_sha256` and `result_sha256` in `Guardrails.audit` and consistent Merkle leaf generation in `artifact_manifest.json`.
