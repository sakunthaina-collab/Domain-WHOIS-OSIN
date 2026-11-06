# Release v1.5.0 – S3 WORM Adapter

## Overview
This release introduces the **S3 WORM (Object Lock) adapter** for the Trustworthy Agent, providing immutable storage of ledger snapshots.

## Key Features
- Write‑once‑read‑many (WORM) storage using AWS S3 Object Lock.
- Automatic verification of retention mode and legal hold.
- Integration with the existing anchor ledger and GPG signing workflow.

## Documentation
- Adapter implementation: `core/s3_client.py` and `core/anchor.py` extensions.
- Configuration snippet: `patches_v1.5/01_s3_worm/config.yaml.additions.yaml`.
- Test suite coverage: unit tests and property‑based tests in `patches_v1.5/02_tests`.

## Release Process
1. Run pre‑release checks (`scripts/pre_release_check.py`).
2. Generate and sign the release manifest (`scripts/sign_release.py --sign`).
3. Create a signed Git tag `v1.5.0`.
4. Build the auditor packet (`scripts/build_auditor_packet.py`).

*All steps are reproducible without external network access.*