```markdown

# Release Process (SOP)

**Applies to:** every versioned release

**Required roles:** Release Engineer + Reviewer (SoD)

## Sequence

```bash

# 1. Pre-release gate

python scripts/pre_release_check.py       # must exit 0

# 2. Build + sign manifest

python scripts/sign_release.py --sign

# 3. Verify (paranoid check)

python scripts/sign_release.py --verify

# 4. Commit

git add -A

git commit -m "release: v1.5.0 — <one-line summary>"

# 5. Sign tag

git tag -s v1.5.0 -m "Trustworthy Agent v1.5.0"

# 6. Verify tag signature

git tag -v v1.5.0

# 7. Push

git push origin main --tags

Rules

Never re-sign an existing version tag. If broken → bump to vX.Y.Z+1.

Never amend SIGNED_HASHES.txt after signing. Re-run sign_release.py --sign.

Reviewer must independently run sign_release.py --verify before approving tag push.

Two-person rule: tag push requires approval from a second person with GPG key access.

Post-release

bash

# Build auditor packet from the tagged release

python scripts/build_auditor_packet.py --tag v1.5.0 --out dist/

text

## Git commands (ทำด้วยมือหลัง apply)

```powershell

cd agent

python scripts/pre_release_check.py

python scripts/sign_release.py --sign

python scripts/sign_release.py --verify

git add -A

git commit -m "release: v1.5.0 - S3 WORM adapter + fuzz hardening"

git tag -s v1.5.0 -m "Trustworthy Agent v1.5.0"

git tag -v v1.5.0

git push origin main --tags

PART 2 — Auditor Evidence Packet
