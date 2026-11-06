# Release Notes — Trustworthy Agent v1.5.0

**Release date:** 2026-11-06

**Tag:** `v1.5.0` (signed)

**Previous:** `v1.4.2`

## Highlights

### New: S3 WORM Anchor Adapter

The strongest available evidence anchor, suitable for court-admissible

preservation of audit-chain head hashes.

- `core/s3_client.py` — thin boto3 wrapper with checksum + retention verification

- `core/anchor.py` — `S3WormAdapter` supports COMPLIANCE (immutable) and

  GOVERNANCE (bypassable) retention modes

- Default: **COMPLIANCE, 7 years (2555 days)** — matches Thai criminal statute

  of limitations

- Immediate read-back verification after `put_worm` (defense in depth)

### Fixes carried in this release

| ID | Severity | Component |

|---|---|---|

| FIND-01 | Medium | `normalize_phone` Unicode digits |

| FIND-02 | Low | `normalize_phone` embedded `+` |

| FIND-03 | **High** | Unicode line separators in JSONL |

| FIND-05 | **High** | Executor CLI allowlist bypass |

| FIND-06 | **High** | Path traversal in `_run_python` |

| FIND-07 | Medium | SSRF to cloud metadata IP |

| FIND-08 | Medium | UTF-8 / BOM crash in verifier |

### Docs added

- `docs/ANCHOR_WORM.md` — WORM setup, IAM, retention policy

- `docs/GPG_KEY_MANAGEMENT.md` — key lifecycle

- `docs/AUDITOR_GUIDE.md` §4.3 — residual risk from FIND-04

- `docs/FINDINGS.md` — all findings, Round 1 + Round 2

## Test Summary

| Category | Tests | Status |

|---|---|---|

| Unit + regression | 105 | ✅ pass |

| S3 WORM unit | 9 | ✅ pass |

| S3 WORM property | 4 | ✅ pass |

| Property fuzzing | 36 | ✅ pass |

| **Total** | **154** | ✅ **154/154** |

## 5-Pillar Verification

All pillars pass — see `verify_all.py` output.

## Breaking changes

None. `anchor.adapter: git` remains the default; existing ledgers unaffected.

## Upgrade path

```bash

# from v1.4.2

git pull --ff-only

pip install -r requirements-dev.txt

pytest tests/ -v

python scripts/verify_all.py --base-dir .

# optional: set anchor.adapter=s3 in config.yaml

Known limitations

See docs/AUDITOR_GUIDE.md §4.3 (Residual Risk) — notably:

DNS rebinding for http skills requires network egress ACL

Root compromise before anchoring requires HSM/TPM (out of scope)

S3 COMPLIANCE cannot be reversed even by AWS Support

Signed artifacts

docs/SIGNED_HASHES.txt — SHA-256 of all source files

docs/SIGNED_HASHES.txt.asc — detached GPG signature

Git tag v1.5.0 — signed with org key

Fingerprint: 3892E3F2CEDAE88EDEF85D64892DBC9697F6927A

text
