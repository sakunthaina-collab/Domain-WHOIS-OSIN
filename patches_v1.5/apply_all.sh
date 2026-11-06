#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-$(pwd)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "═══ Trustworthy Agent v1.5 — S3 WORM ═══"

files=(
    "01_s3_worm/core/s3_client.py:core/s3_client.py"
    "01_s3_worm/core/anchor.py:core/anchor.py"
    "02_tests/tests/test_s3_worm_adapter.py:tests/test_s3_worm_adapter.py"
    "02_tests/tests/properties/test_s3_worm_properties.py:tests/properties/test_s3_worm_properties.py"
    "03_scripts/scripts/run_localstack.ps1:scripts/run_localstack.ps1"
    "03_scripts/scripts/run_localstack.sh:scripts/run_localstack.sh"
    "04_docs/docs/ANCHOR_WORM.md:docs/ANCHOR_WORM.md"
    "requirements-dev.txt:requirements-dev.txt"
)

for pair in "${files[@]}"; do
    src="$HERE/${pair%%:*}"
    dst="$TARGET/${pair##*:}"
    mkdir -p "$(dirname "$dst")"
    if [ -f "$dst" ]; then
        cp "$dst" "$dst.bak.$(date +%Y%m%d%H%M%S)"
        echo "  ~ ${pair##*:}"
    else
        echo "  + ${pair##*:}"
    fi
    cp "$src" "$dst"
done

cp "$HERE/05_config/config.yaml.additions.yaml" "$TARGET/config.yaml.s3.additions.yaml"
echo "  📋 config.yaml.s3.additions.yaml"

echo ""
echo "✅ Files applied."
