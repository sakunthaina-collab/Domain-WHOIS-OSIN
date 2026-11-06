# Trustworthy Agent v1.2 — Race Fix, External Anchor & Adversarial Hardening

This patch bundle upgrades the system from v1.1 to v1.2, addressing critical court admissibility and forensic auditor requirements:
1. **Race Condition Elimination:** Inter-process OS file lock (`msvcrt` on Windows, `fcntl` on POSIX) and tail hash re-read under lock.
2. **Dual Audit Chains:** Independent hash chains for global system log (`logs/audit.jsonl`) and case-specific log (`artifacts/<case_id>/audit.jsonl`).
3. **External Anchoring & Zero-Entry Trap:** Extensible anchor engine (Git default, S3 Object Lock, HTTP webhook, local share) and detection of log truncation/deletion.
4. **Input Unicode Normalization:** Normalization of international phone numbers (Arabic-Indic digits), emails, and text before routing.
5. **Adversarial Test Suite:** 8 explicit attack vector validations including SQL/shell injections, path traversal, malicious runtime, log truncation, and high-concurrency writes.
6. **Stub Transparency:** Explicit documentation and test proving that 334 stubs in `skills/_stubs/` are strictly excluded from production runtime.

---

## 🚀 How to Apply

### Windows (PowerShell)
```powershell
.\patches_v1.2\apply_all.ps1 -Target .\agent
```

### Linux / macOS (Bash)
```bash
./patches_v1.2/apply_all.sh ./agent
```

---

## 📋 Manual Snippet Instructions

### 1. `config.yaml`
Add anchor configuration to the top level:
```yaml
anchor:
  adapter: git
  ledger_path: logs/anchor_ledger.json
```

### 2. `main.py`
After `agent.run()` and `build_manifest()`:
```python
from core.anchor import Anchor

anchor_cfg = cfg.get("anchor", {"adapter": "git"})
anchor = Anchor(
    adapter=anchor_cfg.get("adapter", "git"),
    ledger_path=anchor_cfg.get("ledger_path", "logs/anchor_ledger.json"),
    **{k: v for k, v in anchor_cfg.items() if k not in ("adapter", "ledger_path")}
)
try:
    rec = anchor.anchor(case_id=target_case_id, audit_path=str(guard.log_path))
    print(f"⚓ Anchored: head={rec['head_hash'][:16]}... n={rec['entry_count']} via {rec['adapter']}")
except ValueError as e:
    print(f"⚠️  anchor skipped: {e}")
```

---

## 🛡️ Verification Commands

```bash
# 1. Run all unit & adversarial tests
pytest agent/tests/ -v

# 2. Run dry-run case
python agent/main.py --dry-run --case-id SMOKE-V12

# 3. Verify audit log against external anchor
python agent/scripts/verify_audit.py agent/artifacts/SMOKE-V12/audit.jsonl SMOKE-V12 agent/logs/anchor_ledger.json
```
