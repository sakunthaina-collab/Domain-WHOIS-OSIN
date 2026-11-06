# scripts/run_localstack.ps1
param(
    [string]$ContainerName = "worm-localstack",
    [int]$Port = 4566
)
$ErrorActionPreference = "Stop"

# ── check docker ────────────────────────────────────────
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "❌ docker not found. Install Docker Desktop." -ForegroundColor Red
    exit 1
}

# ── remove old container ────────────────────────────────
docker rm -f $ContainerName 2>$null | Out-Null

# ── run ─────────────────────────────────────────────────
Write-Host "▶️  Starting LocalStack ($ContainerName) on :$Port" -ForegroundColor Cyan
docker run -d --name $ContainerName `
    -p "${Port}:4566" `
    -e "SERVICES=s3" `
    -e "EAGER_SERVICE_LOADING=1" `
    localstack/localstack:3.0

Write-Host "⏳ Waiting for S3 to be ready..." -ForegroundColor Yellow
for ($i = 0; $i -lt 30; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:$Port/_localstack/health" `
                                  -UseBasicParsing -TimeoutSec 2
        if ($resp.Content -match '"s3":\s*"(running|available)"') {
            Write-Host "✅ LocalStack S3 ready" -ForegroundColor Green
            Write-Host ""
            Write-Host "── Env vars for tests ──" -ForegroundColor Cyan
            Write-Host '  $env:AWS_ENDPOINT_URL = "http://localhost:4566"' -ForegroundColor Gray
            Write-Host '  $env:AWS_ACCESS_KEY_ID = "test"' -ForegroundColor Gray
            Write-Host '  $env:AWS_SECRET_ACCESS_KEY = "test"' -ForegroundColor Gray
            Write-Host '  $env:AWS_DEFAULT_REGION = "us-east-1"' -ForegroundColor Gray
            exit 0
        }
    } catch { Start-Sleep -Seconds 1 }
}
Write-Host "❌ LocalStack failed to start in 30s" -ForegroundColor Red
docker logs $ContainerName --tail 20
exit 1
