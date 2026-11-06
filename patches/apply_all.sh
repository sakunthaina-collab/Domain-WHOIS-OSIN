#!/usr/bin/env bash
set -e

TARGET="${1:-agent}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "Applying Trustworthy Agent v1.1 Patches to: $TARGET"
echo "Patch source: $SCRIPT_DIR"
echo "============================================================"

mkdir -p "$TARGET/core"
mkdir -p "$TARGET/scripts"
mkdir -p "$TARGET/tests"
mkdir -p "$TARGET/docs"
mkdir -p "$TARGET/artifacts"
mkdir -p "$TARGET/logs"
mkdir -p "$TARGET/checkpoints"

cp "$SCRIPT_DIR/01_audit_chain/core/guardrails.py" "$TARGET/core/guardrails.py"
cp "$SCRIPT_DIR/01_audit_chain/scripts/verify_audit.py" "$TARGET/scripts/verify_audit.py"
cp "$SCRIPT_DIR/02_run_manifest/core/run_manifest.py" "$TARGET/core/run_manifest.py"
cp "$SCRIPT_DIR/03_artifact_manifest/core/artifact_manifest.py" "$TARGET/core/artifact_manifest.py"
cp "$SCRIPT_DIR/04_resilience/core/resilience.py" "$TARGET/core/resilience.py"
cp "$SCRIPT_DIR/05_stub_management/scripts/detect_status.py" "$TARGET/scripts/detect_status.py"
cp "$SCRIPT_DIR/05_stub_management/scripts/reorganize_stubs.py" "$TARGET/scripts/reorganize_stubs.py"
cp "$SCRIPT_DIR/06_verification/scripts/verify_all.py" "$TARGET/scripts/verify_all.py"
cp "$SCRIPT_DIR/07_tests/tests/"*.py "$TARGET/tests/"
cp "$SCRIPT_DIR/08_docs/docs/TRUST.md" "$TARGET/docs/TRUST.md"

chmod +x "$TARGET/scripts/"*.py || true

echo "============================================================"
echo "All patches applied successfully!"
echo "To verify the system, run:"
echo "  python $TARGET/scripts/verify_all.py --base-dir $TARGET"
echo "============================================================"
