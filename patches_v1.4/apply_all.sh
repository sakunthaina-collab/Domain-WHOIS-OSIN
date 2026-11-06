#!/usr/bin/env bash
# patches_v1.4/apply_all.sh
set -euo pipefail

TARGET_DIR="${1:-agent}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Applying Patch v1.4: Property-Based Fuzzing Suite ==="
mkdir -p "$TARGET_DIR/tests/properties" "$TARGET_DIR/docs" ".github/workflows"

cp -r "$SCRIPT_DIR/02_property_tests/tests/properties/"* "$TARGET_DIR/tests/properties/"
cat "$SCRIPT_DIR/02_property_tests/tests/conftest.py.additions.py" >> "$TARGET_DIR/tests/conftest.py"
cp "$SCRIPT_DIR/04_docs/docs/FUZZING.md" "$TARGET_DIR/docs/"
cp "$SCRIPT_DIR/05_findings/FINDINGS.md" "$TARGET_DIR/docs/"
cp "$SCRIPT_DIR/03_ci_config/.github/workflows/fuzz.yml" ".github/workflows/"

echo "[OK] Patch v1.4 applied. Run: pytest agent/tests/properties -v"
