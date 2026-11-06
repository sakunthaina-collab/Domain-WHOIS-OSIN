# Forensic Trust & Evidentiary Verification Standards (TRUST.md)

This document specifies the verification and accountability protocols for the Multi-Profile Digital Forensics Agent, designed to satisfy the evidentiary standards of the **Thai Anti-Trafficking in Persons Act B.E. 2551** and the **Taiwan Code of Criminal Procedure / Human Trafficking Prevention Act**.

---

## 5-Point Cryptographic Verification Checklist

Before transferring case dossiers or evidence packages to law enforcement agencies (e.g. DSI, Thai Royal Police, Taiwan National Immigration Agency), execute the following 5 verification commands:

### 1. Tamper-Evident Audit Log Verification (Hash Chain)
Verifies that no entry in the continuous SHA-256 hash chain has been altered, injected, or removed:
```bash
python scripts/verify_audit.py logs/audit.jsonl
```
*Expected Output:* `[PASS] OK — N audit entries cryptographically verified (Chain unbroken)`

---

### 2. Artifact Integrity Verification (Merkle Root Validation)
Validates that every evidence file (JSON, Markdown, CSV) matches its recorded SHA-256 digest and that the overall folder Merkle root is untampered:
```bash
python main.py --verify-artifacts 2026-11-05-CASE-001
```
*Expected Output:* `[PASS] Artifact integrity verified for case '2026-11-05-CASE-001' (Merkle root matched, 0 tampering).`

---

### 3. Reproducible Replay Verification (Seed & Registry Determinism)
Replays the case with the exact model parameters, seed, and registry state recorded in `00_run_manifest.json`:
```bash
python main.py --replay 2026-11-05-CASE-001 --compare-hash
```
*Expected Output:* `[*] Replay verification: Environment and Registry hash match original manifest 100%.`

---

### 4. Full Pytest Assurance Suite (Negative Guardrails & Routing)
Executes all unit tests verifying OPSEC boundaries, high-risk confirmation gates, rate limiting, and bilingual routing:
```bash
pytest tests/ -v
```
*Expected Output:* All passed

---

### 5. Honest Skill Inventory & Stub Quality Audit
Audits runnable skills versus documentation-only stubs (isolated in `skills/_stubs/`):
```bash
python scripts/audit_skill_inventory.py
```
*Expected Output:* Clear separation between runnable skills and stubs, with 0 broken manifests and 0 duplicate skill names.

---

## Forensic Integrity Principles

1. **Passive Reconnaissance Invariant:**  
   `passive_only` is enforced at both the schema and runtime levels. Any attempt to set `passive_only=False` triggers an immediate `ValueError` and is blocked by the Guardrails engine.
2. **Chain-of-Custody & Parent Steps:**  
   Every audit record contains `parent_step`, `args_sha256`, and `result_sha256` preserving the sequence of actions and causal dependency.
3. **Resilience & Checkpoint State:**  
   Transient network failures trigger exponential backoff via `ResilientLLM`. In case of manual interruption (`SIGINT`), state is frozen in `checkpoint.json` and can be resumed with `--resume`.
