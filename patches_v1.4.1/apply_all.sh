#!/usr/bin/env bash
# patches_v1.4.1/apply_all.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-agent}"

echo "═══ Trustworthy Agent v1.4.1 — Fuzz Hotfix ═══"
echo "Target: $TARGET"

apply() {
    local src="$HERE/$1" dst="$TARGET/$2"
    mkdir -p "$(dirname "$dst")"
    [ -f "$dst" ] && cp "$dst" "$dst.bak.$(date +%s)" && echo "  ~ $2" || echo "  + $2"
    cp "$src" "$dst"
}

apply "01_normalize_fix/core/normalize.py"                   "core/normalize.py"
apply "02_guardrails_fix/core/guardrails.py"                 "core/guardrails.py"
apply "03_regression_tests/tests/test_fuzz_regressions.py"   "tests/test_fuzz_regressions.py"
apply "04_findings_update/docs/FINDINGS.md"                  "docs/FINDINGS.md"

echo -e "\n✅ Files applied. Run: pytest agent/tests/ -v"
