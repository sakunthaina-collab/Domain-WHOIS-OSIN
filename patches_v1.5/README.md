# Patch v1.5 — S3 WORM Adapter (Object Lock)

Implements S3 Write-Once-Read-Many (WORM) Object Lock adapter for tamper-proof forensic evidence anchoring.

## Features
- `core/s3_client.py`: Thin S3 wrapper around `boto3` with `put_worm`, `verify_checksum`, `verify_retention`, and `list_locked_objects`.
- `core/anchor.py`: Added `S3WormAdapter` supporting both `COMPLIANCE` (court-admissible default) and `GOVERNANCE` modes.
- `tests/test_s3_worm_adapter.py`: 8 unit tests running against in-memory mock (`moto`).
- `tests/properties/test_s3_worm_properties.py`: 4 property-based tests via Hypothesis.
- `scripts/run_localstack.ps1` & `scripts/run_localstack.sh`: Integration script for LocalStack container testing.
- `docs/ANCHOR_WORM.md`: Auditor and operational manual detailing retention policies, IAM permissions, and verification commands.

## How to Apply

```powershell
.\patches_v1.5\apply_all.ps1 -Target .\agent
```

Or on Linux / macOS:

```bash
./patches_v1.5/apply_all.sh ./agent
```
