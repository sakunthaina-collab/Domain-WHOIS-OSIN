#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-$(pwd)}"

echo "═══ Trustworthy Agent v1.2 — Apply ═══"
echo "Target: $TARGET"

apply() {
    local src="$HERE/$1" dst="$TARGET/$2"
    mkdir -p "$(dirname "$dst")"
    [ -f "$dst" ] && cp "$dst" "$dst.bak.$(date +%s)" && echo "  ~ $2" || echo "  + $2"
    cp "$src" "$dst"
}

apply "01_race_fix/core/file_lock.py"                     "core/file_lock.py"
apply "01_race_fix/core/guardrails.py"                    "core/guardrails.py"
apply "02_anchor/core/anchor.py"                          "core/anchor.py"
apply "03_verify_upgrade/scripts/verify_audit.py"         "scripts/verify_audit.py"
apply "04_normalizer/core/normalize.py"                   "core/normalize.py"
apply "05_adversarial_tests/tests/test_adversarial.py"    "tests/test_adversarial.py"
apply "06_stub_transparency/tests/test_stubs_isolation.py" "tests/test_stubs_isolation.py"
apply "07_integration_tests/tests/test_anchor_integration.py" "tests/test_anchor_integration.py"
apply "08_court_docs/docs/AUDITOR_GUIDE.md"          "docs/AUDITOR_GUIDE.md"
apply "08_court_docs/docs/INCIDENT_RESPONSE.md"      "docs/INCIDENT_RESPONSE.md"
apply "08_court_docs/docs/CHAIN_OF_CUSTODY_SOP.md"   "docs/CHAIN_OF_CUSTODY_SOP.md"
apply "08_court_docs/docs/THREAT_MODEL.md"           "docs/THREAT_MODEL.md"
apply "08_court_docs/docs/SIGNED_HASHES.txt"         "docs/SIGNED_HASHES.txt"

cp "$HERE/02_anchor/config.yaml.additions.yaml" "$TARGET/"
cp "$HERE/02_anchor/main.py.additions.py"       "$TARGET/main.py.anchor.additions.py"

readmeSrc="$HERE/06_stub_transparency/skills/_stubs/README.template.md"
readmeDst="$TARGET/skills/_stubs/README.md"
if [ -f "$readmeSrc" ] && [ ! -f "$readmeDst" ]; then
    mkdir -p "$(dirname "$readmeDst")"
    cp "$readmeSrc" "$readmeDst"
    echo "  + skills/_stubs/README.md (template)"
fi

echo -e "\n✅ Files applied. Paste 2 snippets manually. See README.md."
