# Patch v1.4.2: Fuzzing Round 2 & Executor/Verifier Hardening

Resolves findings `FIND-05` .. `FIND-08` and adds property-based proof for `FIND-04` (anchored tail-deletion detection):
- **FIND-05:** Strict CLI binary allowlist (`python`, `python3`, `py`, `node`, `uv`) with script confinement inside `skill.dir`; blocks `.exe`/`.cmd` deny-list bypass and `npx`/`uvx` supply-chain execution.
- **FIND-06:** `_resolve_within(skill_dir, rel)` blocks `..`, absolute paths, symlink escapes, and null bytes.
- **FIND-07:** HTTP SSRF protection (`_validate_http_url`) blocks non-HTTP(S) schemes, always blocks cloud metadata IPs (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`), blocks loopback/private networks unless `allow_local: true`, and sets `allow_redirects=False`.
- **FIND-08:** `verify_audit_chain` opens with `encoding="utf-8-sig"` (tolerates UTF-8 BOM) and catches `UnicodeDecodeError` cleanly without crashing.
