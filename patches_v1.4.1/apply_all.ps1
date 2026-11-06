# patches_v1.4.1/apply_all.ps1
param([string]$Target = "agent")
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`n=== Trustworthy Agent v1.4.1 - Fuzz Hotfix ===" -ForegroundColor Cyan
Write-Host "Target: $Target`n" -ForegroundColor Gray

$files = @(
    @("01_normalize_fix/core/normalize.py", "core/normalize.py"),
    @("02_guardrails_fix/core/guardrails.py", "core/guardrails.py"),
    @("03_regression_tests/tests/test_fuzz_regressions.py", "tests/test_fuzz_regressions.py"),
    @("04_findings_update/docs/FINDINGS.md", "docs/FINDINGS.md")
)

foreach ($f in $files) {
    $src = Join-Path $Here $f[0]
    $dst = Join-Path $Target $f[1]
    $dir = Split-Path -Parent $dst
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path $dst) {
        $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
        Copy-Item $dst "$dst.bak.$timestamp" -Force
        Write-Host "  ~ $($f[1])" -ForegroundColor Yellow
    } else {
        Write-Host "  + $($f[1])" -ForegroundColor Green
    }
    Copy-Item $src $dst -Force
}

Write-Host "`n[OK] Files applied." -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. pytest agent/tests/test_fuzz_regressions.py -v" -ForegroundColor Gray
Write-Host "  2. pytest agent/tests/properties/ -v" -ForegroundColor Gray
Write-Host "  3. pytest agent/tests/ -v" -ForegroundColor Gray
