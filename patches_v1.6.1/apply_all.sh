#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-$(pwd)}"

echo "═══ Trustworthy Agent v1.6.1 — Case-ID Injection ═══"

apply() {
    local src="$HERE/$1" dst="$TARGET/$2"
    mkdir -p "$(dirname "$dst")"
    [ -f "$dst" ] && cp "$dst" "$dst.bak.$(date +%s)" && echo "  ~ $2" || echo "  + $2"
    cp "$src" "$dst"
}

apply "01_core/core/case_id.py"                        "core/case_id.py"
apply "01_core/core/case_id_injector.py"               "core/case_id_injector.py"
apply "04_tests/tests/test_case_id_injection.py"       "tests/test_case_id_injection.py"

cp "$HERE/02_orchestrator/core/orchestrator.additions.py" "$TARGET/core/orchestrator.additions.py"
cp "$HERE/03_skill_patch/skills/case-dossier-exporter.additions.py" \
   "$TARGET/skills/investigation/case-dossier-exporter/run.py.additions.py"

echo -e "\n✅ Files applied. Paste snippets manually before testing."
