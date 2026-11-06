#!/usr/bin/env bash
# scripts/gpg_setup_org_key.sh
set -euo pipefail

NAME_REAL="${NAME_REAL:-Forensic Ops}"
EMAIL="${EMAIL:-forensic-ops@example.org}"
PASSPHRASE="${ANCHOR_GPG_PASSPHRASE:-}"
KEY_TYPE="${KEY_TYPE:-RSA}"
KEY_LENGTH="${KEY_LENGTH:-4096}"

if ! command -v gpg >/dev/null; then
    echo "[FAIL] gpg not found. Install: apt install gnupg / brew install gnupg" >&2
    exit 1
fi

echo "[OK] gpg: $(command -v gpg)"
echo
echo "--- Existing secret keys ---"
gpg --list-secret-keys --with-colons 2>/dev/null | grep "^sec:" || echo "   (none)"

if [ -z "$PASSPHRASE" ]; then
    echo
    echo "[FAIL] ANCHOR_GPG_PASSPHRASE env var not set" >&2
    echo "   export ANCHOR_GPG_PASSPHRASE='your-strong-passphrase'" >&2
    exit 1
fi

BATCH=$(cat <<EOF
%no-protection
Key-Type: $KEY_TYPE
Key-Length: $KEY_LENGTH
Key-Usage: sign
Name-Real: $NAME_REAL
Name-Email: $EMAIL
Expire-Date: 2y
%commit
EOF
)

echo
echo "--- Generating key (30-120s for RSA 4096) ---"
echo "$BATCH" | gpg --batch --generate-key

FPR=$(gpg --list-keys --with-colons "$EMAIL" \
      | grep "^fpr:" | head -1 | cut -d: -f10)
echo
echo "[OK] Key generated"
echo "   Fingerprint: $FPR"
echo
echo "--- Set environment ---"
echo "   export ANCHOR_GPG_KEY=\"$FPR\""
echo "   export ANCHOR_GPG_PASSPHRASE=\"<passphrase>\""

mkdir -p docs
PUBKEY="docs/public-key-${FPR:0:16}.asc"
gpg --armor --export "$FPR" > "$PUBKEY"
echo
echo "[OK] Public key exported: $PUBKEY"
echo
echo "[WARN] BACKUP SECRET KEY (HSM / encrypted USB / offline safe):"
echo "   gpg --armor --export-secret-keys $FPR > secret-key.asc"
