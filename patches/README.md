# Trustworthy Agent v1.1 — Patch Bundle

This directory contains the complete, modular patch bundle upgrading the Multi-Profile Digital Forensics Agent into a court-ready, cryptographically verifiable, and resilient system (v1.1) in accordance with the evidentiary standards of the **Thai Anti-Trafficking in Persons Act B.E. 2551** and the **Taiwan Code of Criminal Procedure / Human Trafficking Prevention Act**.

---

## 📁 Patch Directory Layout

```
patches/
├── 01_audit_chain/             # Tamper-evident SHA-256 hash chain
│   ├── core/guardrails.py      # Guardrails engine with prev_hash + entry_hash
│   └── scripts/verify_audit.py # Standalone cryptographic chain auditor
├── 02_run_manifest/            # Reproducibility & run manifest
│   ├── core/run_manifest.py    # Captures environment, model pins, seed, registry hash
│   ├── main.py.additions.py    # main.py integration snippet
│   └── core/orchestrator.additions.py
├── 03_artifact_manifest/       # Case artifacts Merkle tree
│   └── core/artifact_manifest.py # Computes Merkle root & validates SHA256 integrity
├── 04_resilience/              # Fault tolerance & state resumption
│   ├── core/resilience.py      # ResilientLLM (exponential backoff) & Checkpoint
│   └── main.py.additions.py    # --resume flag integration
├── 05_stub_management/         # Registry quality & stub isolation
│   ├── scripts/detect_status.py # Distinguishes runnable skills vs markdown guides
│   └── scripts/reorganize_stubs.py # Isolates documentation stubs to skills/_stubs/
├── 06_verification/            # Automated multi-pillar validation
│   └── scripts/verify_all.py   # Runs all 5 forensic trust checks
├── 07_tests/                   # Unit test suite
│   └── tests/
│       ├── test_audit_chain.py
│       ├── test_manifest.py
│       └── test_resilience.py
├── 08_docs/                    # Standards & verification guidelines
│   └── docs/TRUST.md           # 5-point verification checklist & ISO/IEC 27037 guide
├── apply_all.ps1               # Master PowerShell installer (Windows)
├── apply_all.sh                # Master Bash installer (Linux/macOS)
└── README.md                   # This documentation
```

---

## 🚀 How to Apply the Patches

### Windows (PowerShell)
To apply directly to the default `agent/` folder:
```powershell
.\patches\apply_all.ps1 -TargetDir .\agent -RunTests
```

### Linux / macOS (Bash)
```bash
./patches/apply_all.sh ./agent
```

---

## 🛡️ 5-Point Cryptographic Verification

After applying the patches, run the master verification script:

```bash
python agent/scripts/verify_all.py --base-dir agent
```

Or execute the individual pillars:

1. **Verify Audit Chain:**
   ```bash
   python agent/scripts/verify_audit.py agent/logs/audit.jsonl
   ```
2. **Verify Case Artifacts & Merkle Root:**
   ```bash
   python agent/main.py --verify-artifacts 2026-11-05-CASE-001
   ```
3. **Replay Deterministic Run:**
   ```bash
   python agent/main.py --replay 2026-11-05-CASE-001 --compare-hash
   ```
4. **Audit Skill Inventory:**
   ```bash
   python agent/scripts/audit_skill_inventory.py
   ```
5. **Run Pytest Suite:**
   ```bash
   pytest agent/tests/ -v
   ```

---

## ⚖️ Key Improvements in v1.1

| Capability | v1.0 (Initial) | v1.1 (Trustworthy) |
|---|---|---|
| **Audit Logs** | Plain JSON lines (modifiable) | Continuous SHA-256 Hash Chain with Genesis `0*64` |
| **Reproducibility** | Non-deterministic | `00_run_manifest.json` recording seed, environment, model pins & registry hash |
| **Artifact Integrity** | Unsigned output files | Merkle Root + per-file SHA-256 validation |
| **Transient Errors** | Crashes on timeout/rate limit | `ResilientLLM` with exponential backoff (1s, 2s, 4s) |
| **Crash Recovery** | Re-run from scratch | `checkpoint.json` saving state every step; resume with `--resume` |
| **Skill Inventory** | Stubs mixed with runnable code | Isolated into `skills/_stubs/` (123 runnable, 334 stubs quarantined) |
