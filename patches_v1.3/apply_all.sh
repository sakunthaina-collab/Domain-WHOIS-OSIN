#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-$(pwd)}"

echo "=== Trustworthy Agent v1.3 - GPG Anchor ==="
echo "Target: $TARGET"

command -v gpg >/dev/null || {
    echo "[WARN] gpg not found. Tests will skip GPG cases."
    echo "       Install: apt install gnupg / brew install gnupg"
}

apply() {
    local src="$HERE/$1" dst="$TARGET/$2"
    mkdir -p "$(dirname "$dst")"
    [ -f "$dst" ] && cp "$dst" "$dst.bak.$(date +%s)" && echo "  ~ $2" || echo "  + $2"
    cp "$src" "$dst"
}

apply "01_gpg_anchor/core/gpg_signer.py"                  "core/gpg_signer.py"
apply "01_gpg_anchor/core/anchor.py"                      "core/anchor.py"
apply "02_setup_scripts/scripts/gpg_setup_org_key.ps1"    "scripts/gpg_setup_org_key.ps1"
apply "02_setup_scripts/scripts/gpg_setup_org_key.sh"     "scripts/gpg_setup_org_key.sh"
apply "02_setup_scripts/scripts/generate_mock_keyring.py" "scripts/generate_mock_keyring.py"
apply "03_verify_upgrade/scripts/verify_audit.py"         "scripts/verify_audit.py"
apply "04_tests/tests/conftest_gpg.py"                    "tests/conftest_gpg.py"
apply "04_tests/tests/test_gpg_anchor.py"                 "tests/test_gpg_anchor.py"
apply "05_docs/docs/GPG_KEY_MANAGEMENT.md"                "docs/GPG_KEY_MANAGEMENT.md"

cp "$HERE/01_gpg_anchor/config.yaml.additions.yaml" "$TARGET/config.yaml.gpg.additions.yaml"
chmod +x "$TARGET/scripts/gpg_setup_org_key.sh" 2>/dev/null || true

echo -e "\n[OK] Files applied. See next steps in README.md."
