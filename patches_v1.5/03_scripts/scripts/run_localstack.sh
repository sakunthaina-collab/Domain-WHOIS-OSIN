#!/usr/bin/env bash
set -euo pipefail
CONTAINER="${CONTAINER:-worm-localstack}"
PORT="${PORT:-4566}"

command -v docker >/dev/null || { echo "❌ docker not installed"; exit 1; }
docker rm -f "$CONTAINER" 2>/dev/null || true

echo "▶️  Starting LocalStack on :$PORT"
docker run -d --name "$CONTAINER" \
    -p "${PORT}:4566" \
    -e "SERVICES=s3" \
    -e "EAGER_SERVICE_LOADING=1" \
    localstack/localstack:3.0

echo "⏳ Waiting for S3..."
for _ in $(seq 1 30); do
    if curl -sf "http://localhost:$PORT/_localstack/health" \
       | grep -qE '"s3":\s*"(running|available)"'; then
        echo "✅ S3 ready"
        cat <<EOF

── Export for tests ──
export AWS_ENDPOINT_URL="http://localhost:$PORT"
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="us-east-1"
EOF
        exit 0
    fi
    sleep 1
done
echo "❌ LocalStack failed"
docker logs "$CONTAINER" --tail 20
exit 1
