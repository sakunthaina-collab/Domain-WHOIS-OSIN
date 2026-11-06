# Patch v1.4: Property-Based Fuzzing Suite

This patch integrates Hypothesis property-based fuzzing to mathematically test and falsify invariants across:
1. `core/normalize.py` (Phone, email, and text normalization)
2. `core/guardrails.py` (Audit log cryptographic hash chain)
3. `core/artifact_manifest.py` (Artifact Merkle tree integrity)

## How to Apply

Windows (PowerShell):
```powershell
.\patches_v1.4\apply_all.ps1
```

Linux / macOS:
```bash
bash patches_v1.4/apply_all.sh
```

## How to Run Property Tests

```powershell
pytest agent/tests/properties -v
```
