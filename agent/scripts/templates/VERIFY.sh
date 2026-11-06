```bash

#!/usr/bin/env bash

# One-command verifier for the Auditor Evidence Packet.

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'

NC='\033[0m'

fail() { echo -e "${RED}❌ $1${NC}" >&2; exit 1; }

ok()   { echo -e "${GREEN}✅ $1${NC}"; }

warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }

echo "════════════════════════════════════════════════════════════"

echo "  Auditor Evidence Packet — Verifier"

echo "════════════════════════════════════════════════════════════"

echo

# ── Step 1: gpg available? ─────────────────────────────────

if ! command -v gpg >/dev/null; then

    warn "gpg not installed — signature checks will be SKIPPED"

    GPG_OK=false

else

    GPG_OK=true

fi

# ── Step 2: import public key ──────────────────────────────

if [ "$GPG_OK" = true ]; then

    echo "── [1/5] Importing org public key ──"

    [ -f TRUST/public-key.asc ] || fail "TRUST/public-key.asc missing"

    gpg --import TRUST/public-key.asc 2>&1 | grep -E "imported|not changed" || true

    FP=$(gpg --list-keys --with-colons | awk -F: '/^fpr:/ {print $10; exit}')

    echo "   fingerprint: $FP"

    case "$FP" in

        3892E3F2CEDAE88EDEF85D64892DBC9697F6927A*) ok "fingerprint matches packet" ;;

        *) fail "fingerprint MISMATCH — expected 3892E3F2...6927A" ;;

    esac

fi

# ── Step 3: verify SIGNED_HASHES.txt.asc ───────────────────

echo

echo "── [2/5] Verifying SIGNED_HASHES.txt signature ──"

[ -f TRUST/SIGNED_HASHES.txt ]     || fail "TRUST/SIGNED_HASHES.txt missing"

[ -f TRUST/SIGNED_HASHES.txt.asc ] || fail "TRUST/SIGNED_HASHES.txt.asc missing"

if [ "$GPG_OK" = true ]; then

    if gpg --verify TRUST/SIGNED_HASHES.txt.asc TRUST/SIGNED_HASHES.txt 2>&1 \

       | grep -q "Good signature"; then

        ok "signature on SIGNED_HASHES.txt valid"

    else

        fail "SIGNED_HASHES.txt signature INVALID"

    fi

fi

# ── Step 4: verify MANIFEST.json.asc ───────────────────────

echo

echo "── [3/5] Verifying MANIFEST.json signature ──"

[ -f MANIFEST.json ]     || fail "MANIFEST.json missing"

[ -f MANIFEST.json.asc ] || fail "MANIFEST.json.asc missing"

if [ "$GPG_OK" = true ]; then

    if gpg --verify MANIFEST.json.asc MANIFEST.json 2>&1 \

       | grep -q "Good signature"; then

        ok "signature on MANIFEST.json valid"

    else

        fail "MANIFEST.json signature INVALID"

    fi

fi

# ── Step 5: verify file hashes ─────────────────────────────

echo

echo "── [4/5] Checking file hashes against SIGNED_HASHES.txt ──"

# extract source, then sha256sum -c

TMP=$(mktemp -d)

trap 'rm -rf "$TMP"' EXIT

tar -xzf SOURCE/source.tar.gz -C "$TMP"

cd "$TMP"

if command -v sha256sum >/dev/null; then

    if sha256sum -c --quiet "$OLDPWD/TRUST/SIGNED_HASHES.txt" 2>&1 \

       | grep -v ": OK$" | head -5; then

        fail "some source files FAILED hash check"

    fi

    ok "all source files match SIGNED_HASHES.txt"

elif command -v shasum >/dev/null; then

    if shasum -a 256 -c --quiet "$OLDPWD/TRUST/SIGNED_HASHES.txt" 2>&1 \

       | grep -v ": OK$" | head -5; then

        fail "some source files FAILED hash check"

    fi

    ok "all source files match SIGNED_HASHES.txt (shasum)"

else

    warn "neither sha256sum nor shasum found — skipping file hash check"

fi

cd - >/dev/null

# ── Step 6: verify MANIFEST hashes (packet integrity) ──────

echo

echo "── [5/5] Checking MANIFEST.json against packet files ──"

python3 - <<'EOF' || exit 1

import hashlib, json, pathlib, sys

mf = json.load(open("MANIFEST.json", encoding="utf-8"))

bad = []

for f in mf["files"]:

    p = pathlib.Path(f["path"])

    if not p.exists():

        bad.append(f"MISSING: {p}"); continue

    got = hashlib.sha256(p.read_bytes()).hexdigest()

    if got != f["sha256"]:

        bad.append(f"TAMPERED: {p}")

if bad:

    print("❌", *bad[:10], sep="\n   "); sys.exit(1)

print(f"   {mf['file_count']} files verified")

print(f"   merkle_root: {mf['merkle_root'][:32]}...")

EOF

ok "all packet files match MANIFEST.json"

# ── Final ──────────────────────────────────────────────────

echo

echo "════════════════════════════════════════════════════════════"

echo "  ✅ PACKET VERIFIED — all checks passed"

echo "════════════════════════════════════════════════════════════"
