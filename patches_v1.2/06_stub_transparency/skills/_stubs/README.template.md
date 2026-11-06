# Stub Inventory

## Summary
- **Runnable (production)**: {RUNNABLE}
- **Stubs (documentation-only)**: {STUBS}
- **Broken**: {BROKEN}
- **Last audited**: {DATE}

## Why stubs exist
These {STUBS} skills are imported from `openai/skills`, `google/skills`,
and `.gemini/config`. They provide SKILL.md documentation but no
runnable implementation.

## Isolation guarantee
Stubs are stored in `skills/_stubs/<category>/`. The production Registry
**never** loads anything under `_stubs/`. This is enforced by:
- `Registry.__init__`: filters `status != "runnable"` and `_stubs` path prefix
- `tests/test_stubs_isolation.py::test_stubs_never_loaded`

## Roadmap
| Quarter | Goal | Count |
|---------|------|-------|
| Q4 2026 | Implement top-20 lifesci stubs | 20 |
| Q1 2027 | Port engineering stubs with community impls | 50 |
| Q2 2027 | Archive unused (no reference in 6 mo) | rest |

## How to promote a stub to runnable
1. Implement `run(**kwargs)` in `_stubs/<cat>/<name>/run.py`
2. Move directory to `skills/<cat>/<name>/`
3. Update `skill.yaml`: `status: runnable`, `last_verified: <date>`
4. Add to integration test: `tests/test_<category>_smoke.py`
5. Run `pytest tests/ -v` and `scripts/verify_all.py --base-dir .`
