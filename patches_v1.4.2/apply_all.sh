#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-agent}"
apply() {
    local src="$HERE/$1" dst="$TARGET/$2"
    mkdir -p "$(dirname "$dst")"
    [ -f "$dst" ] && cp "$dst" "$dst.bak.$(date +%s)" && echo "  ~ $2" || echo "  + $2"
    cp "$src" "$dst"
}
apply "01_executor_hardening/core/executor.py"                    "core/executor.py"
apply "02_verifier_utf8/core/guardrails.py"                       "core/guardrails.py"
apply "03_properties/tests/properties/test_executor_properties.py" "tests/properties/test_executor_properties.py"
apply "03_properties/tests/properties/test_adversarial_json_properties.py" "tests/properties/test_adversarial_json_properties.py"
apply "04_regressions/tests/test_fuzz_round2_regressions.py"      "tests/test_fuzz_round2_regressions.py"
echo "[OK] Patch v1.4.2 applied."
