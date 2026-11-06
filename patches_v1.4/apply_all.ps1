#Requires -Version 5.1
# patches_v1.4/apply_all.ps1
param(
    [string]$TargetDir = "agent"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  APPLYING PATCH v1.4: PROPERTY-BASED FUZZING SUITE   " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# 1) Copy properties tests
$destProps = Join-Path $TargetDir "tests\properties"
New-Item -ItemType Directory -Path $destProps -Force | Out-Null
Copy-Item (Join-Path $ScriptDir "02_property_tests\tests\properties\*") $destProps -Recurse -Force
Write-Host "[OK] Copied property-based tests to $destProps" -ForegroundColor Green

# 2) Append hypothesis configuration to conftest.py
$conftest = Join-Path $TargetDir "tests\conftest.py"
$addition = Get-Content (Join-Path $ScriptDir "02_property_tests\tests\conftest.py.additions.py") -Raw
if (Test-Path $conftest) {
    $existing = Get-Content $conftest -Raw
    if ($existing -notmatch "register_profile") {
        Add-Content -Path $conftest -Value "`n$addition"
        Write-Host "[OK] Added Hypothesis profiles to $conftest" -ForegroundColor Green
    } else {
        Write-Host "[SKIP] Hypothesis profiles already present in $conftest" -ForegroundColor Gray
    }
} else {
    Set-Content -Path $conftest -Value $addition -Encoding utf8
    Write-Host "[OK] Created $conftest with Hypothesis profiles" -ForegroundColor Green
}

# 3) Copy docs & CI config
$destDocs = Join-Path $TargetDir "docs"
Copy-Item (Join-Path $ScriptDir "04_docs\docs\FUZZING.md") $destDocs -Force
Copy-Item (Join-Path $ScriptDir "05_findings\FINDINGS.md") $destDocs -Force
Write-Host "[OK] Copied FUZZING.md and FINDINGS.md to $destDocs" -ForegroundColor Green

$destCI = ".github\workflows"
New-Item -ItemType Directory -Path $destCI -Force | Out-Null
Copy-Item (Join-Path $ScriptDir "03_ci_config\.github\workflows\fuzz.yml") $destCI -Force
Write-Host "[OK] Installed GitHub Actions nightly fuzz workflow" -ForegroundColor Green

# 4) Install requirements
if (Get-Command pip -ErrorAction SilentlyContinue) {
    Write-Host "`nEnsuring hypothesis is installed..." -ForegroundColor Cyan
    pip install hypothesis --quiet
}

Write-Host "`n======================================================" -ForegroundColor Green
Write-Host "  PATCH v1.4 APPLIED SUCCESSFULLY!                    " -ForegroundColor Green
Write-Host "  Run: pytest agent/tests/properties -v               " -ForegroundColor Yellow
Write-Host "======================================================" -ForegroundColor Green
