param([string]$Target = (Get-Location).Path)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "`n=== Trustworthy Agent v1.5 - S3 WORM ===" -ForegroundColor Cyan

$files = @(
    @("01_s3_worm/core/s3_client.py",                          "core/s3_client.py"),
    @("01_s3_worm/core/anchor.py",                             "core/anchor.py"),
    @("02_tests/tests/test_s3_worm_adapter.py",                "tests/test_s3_worm_adapter.py"),
    @("02_tests/tests/properties/test_s3_worm_properties.py",  "tests/properties/test_s3_worm_properties.py"),
    @("03_scripts/scripts/run_localstack.ps1",                 "scripts/run_localstack.ps1"),
    @("03_scripts/scripts/run_localstack.sh",                  "scripts/run_localstack.sh"),
    @("04_docs/docs/ANCHOR_WORM.md",                           "docs/ANCHOR_WORM.md"),
    @("requirements-dev.txt",                                  "requirements-dev.txt")
)
foreach ($f in $files) {
    $src = Join-Path $Here $f[0]; $dst = Join-Path $Target $f[1]
    $dir = Split-Path -Parent $dst
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path $dst) {
        Copy-Item $dst "$dst.bak.$((Get-Date).ToString('yyyyMMddHHmmss'))" -Force
        Write-Host "  ~ $($f[1])" -ForegroundColor Yellow
    } else { Write-Host "  + $($f[1])" -ForegroundColor Green }
    Copy-Item $src $dst -Force
}
Copy-Item (Join-Path $Here "05_config/config.yaml.additions.yaml") `
          (Join-Path $Target "config.yaml.s3.additions.yaml") -Force
Write-Host "  config.yaml.s3.additions.yaml" -ForegroundColor Magenta

Write-Host "`nFiles applied successfully." -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. pip install -r requirements-dev.txt" -ForegroundColor Gray
Write-Host "  2. pytest tests/test_s3_worm_adapter.py -v" -ForegroundColor Gray
Write-Host "  3. pytest tests/properties/test_s3_worm_properties.py -v" -ForegroundColor Gray
Write-Host "  4. (optional) .\scripts\run_localstack.ps1" -ForegroundColor Gray
Write-Host "  5. Merge config.yaml.s3.additions.yaml -> config.yaml" -ForegroundColor Gray
Write-Host "  6. pytest tests/ -v (expect all pass)" -ForegroundColor Gray
