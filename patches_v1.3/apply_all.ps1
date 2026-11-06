#Requires -Version 5.1
# patches_v1.3/apply_all.ps1
param([string]$Target = "")

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrWhiteSpace($Target)) {
    if (Test-Path -Path "core\registry.py") {
        $Target = "."
    } elseif (Test-Path -Path "agent\core\registry.py") {
        $Target = "agent"
    } elseif (Test-Path -Path "..\agent\core\registry.py") {
        $Target = "..\agent"
    } else {
        $Target = (Get-Location).Path
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Applying Trustworthy Agent v1.3 (GPG Anchor) to: $Target" -ForegroundColor Cyan
Write-Host "Patch source: $Here" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Check gpg
$gpgFound = (Get-Command gpg -ErrorAction SilentlyContinue) -or (Test-Path "C:\Program Files\Git\usr\bin\gpg.exe")
if (-not $gpgFound) {
    Write-Host "[WARN] gpg not found on PATH." -ForegroundColor Yellow
    Write-Host "   Install GPG4Win: https://gpg4win.org/download.html" -ForegroundColor Yellow
} else {
    Write-Host "[OK] GnuPG binary detected." -ForegroundColor Green
}

$files = @(
    @("01_gpg_anchor\core\gpg_signer.py",                   "core\gpg_signer.py"),
    @("01_gpg_anchor\core\anchor.py",                       "core\anchor.py"),
    @("02_setup_scripts\scripts\gpg_setup_org_key.ps1",     "scripts\gpg_setup_org_key.ps1"),
    @("02_setup_scripts\scripts\gpg_setup_org_key.sh",      "scripts\gpg_setup_org_key.sh"),
    @("02_setup_scripts\scripts\generate_mock_keyring.py",  "scripts\generate_mock_keyring.py"),
    @("03_verify_upgrade\scripts\verify_audit.py",          "scripts\verify_audit.py"),
    @("04_tests\tests\conftest_gpg.py",                     "tests\conftest_gpg.py"),
    @("04_tests\tests\test_gpg_anchor.py",                  "tests\test_gpg_anchor.py"),
    @("05_docs\docs\GPG_KEY_MANAGEMENT.md",                 "docs\GPG_KEY_MANAGEMENT.md")
)

foreach ($f in $files) {
    $src = Join-Path $Here $f[0]
    $dst = Join-Path $Target $f[1]
    $dir = Split-Path -Parent $dst
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path $dst) {
        $ts = (Get-Date).ToString("yyyyMMddHHmmss")
        Copy-Item $dst "$dst.bak.$ts" -Force
        Write-Host "  ~ $($f[1])" -ForegroundColor Yellow
    } else {
        Write-Host "  + $($f[1])" -ForegroundColor Green
    }
    Copy-Item $src $dst -Force
}

Copy-Item (Join-Path $Here "01_gpg_anchor\config.yaml.additions.yaml") `
          (Join-Path $Target "config.yaml.gpg.additions.yaml") -Force
Write-Host "  [SNIP] config.yaml.gpg.additions.yaml" -ForegroundColor Magenta

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Files applied successfully." -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Setup GPG key: .\scripts\gpg_setup_org_key.ps1" -ForegroundColor Gray
Write-Host "  2. Merge config.yaml.gpg.additions.yaml -> config.yaml" -ForegroundColor Gray
Write-Host "  3. pytest tests/ -v" -ForegroundColor Gray
Write-Host "  4. python main.py --dry-run --case-id SMOKE-V13" -ForegroundColor Gray
Write-Host "  5. python scripts/verify_audit.py logs/audit.jsonl SMOKE-V13 logs/anchor_ledger.json --strict-gpg" -ForegroundColor Gray
