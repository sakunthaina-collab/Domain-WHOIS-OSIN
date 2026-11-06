# patches_v1.4.2/apply_all.ps1
param([string]$Target = "agent")
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "`n=== Trustworthy Agent v1.4.2 ===" -ForegroundColor Cyan

$files = @(
    @("01_executor_hardening/core/executor.py", "core/executor.py"),
    @("02_verifier_utf8/core/guardrails.py", "core/guardrails.py"),
    @("03_properties/tests/properties/test_executor_properties.py", "tests/properties/test_executor_properties.py"),
    @("03_properties/tests/properties/test_adversarial_json_properties.py", "tests/properties/test_adversarial_json_properties.py"),
    @("04_regressions/tests/test_fuzz_round2_regressions.py", "tests/test_fuzz_round2_regressions.py")
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
Write-Host "   pytest agent/tests/test_fuzz_round2_regressions.py -v" -ForegroundColor Gray
Write-Host "   pytest agent/tests/properties/ -v" -ForegroundColor Gray
Write-Host "   pytest agent/tests/ -v" -ForegroundColor Gray
