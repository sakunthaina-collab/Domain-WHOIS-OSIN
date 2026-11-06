#Requires -Version 5.1
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
Write-Host "Applying Trustworthy Agent v1.2 Patches to: $Target" -ForegroundColor Cyan
Write-Host "Patch source: $Here" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$files = @(
    @("01_race_fix\core\file_lock.py",                "core\file_lock.py"),
    @("01_race_fix\core\guardrails.py",               "core\guardrails.py"),
    @("02_anchor\core\anchor.py",                     "core\anchor.py"),
    @("03_verify_upgrade\scripts\verify_audit.py",    "scripts\verify_audit.py"),
    @("04_normalizer\core\normalize.py",              "core\normalize.py"),
    @("05_adversarial_tests\tests\test_adversarial.py","tests\test_adversarial.py"),
    @("06_stub_transparency\tests\test_stubs_isolation.py","tests\test_stubs_isolation.py"),
    @("07_integration_tests\tests\test_anchor_integration.py","tests\test_anchor_integration.py"),
    @("08_court_docs\docs\AUDITOR_GUIDE.md",          "docs\AUDITOR_GUIDE.md"),
    @("08_court_docs\docs\INCIDENT_RESPONSE.md",      "docs\INCIDENT_RESPONSE.md"),
    @("08_court_docs\docs\CHAIN_OF_CUSTODY_SOP.md",   "docs\CHAIN_OF_CUSTODY_SOP.md"),
    @("08_court_docs\docs\THREAT_MODEL.md",           "docs\THREAT_MODEL.md"),
    @("08_court_docs\docs\SIGNED_HASHES.txt",         "docs\SIGNED_HASHES.txt")
)

$snips = @(
    @("02_anchor\config.yaml.additions.yaml", "config.yaml.additions.yaml"),
    @("02_anchor\main.py.additions.py",       "main.py.anchor.additions.py")
)

foreach ($f in $files) {
    $src = Join-Path $Here $f[0]
    $dst = Join-Path $Target $f[1]
    $dir = Split-Path -Parent $dst
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path $dst) {
        $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
        $bak = "$dst.bak.$timestamp"
        Copy-Item $dst $bak -Force
        Write-Host "  ~ $($f[1])" -ForegroundColor Yellow
    } else {
        Write-Host "  + $($f[1])" -ForegroundColor Green
    }
    Copy-Item $src $dst -Force
}

foreach ($s in $snips) {
    $srcSnip = Join-Path $Here $s[0]
    $dstSnip = Join-Path $Target $s[1]
    Copy-Item $srcSnip $dstSnip -Force
    Write-Host "  [SNIP] $($s[1])" -ForegroundColor Magenta
}

# generate _stubs/README.md
$readmeSrc = Join-Path $Here "06_stub_transparency\skills\_stubs\README.template.md"
$readmeDst = Join-Path $Target "skills\_stubs\README.md"
if ((Test-Path $readmeSrc) -and -not (Test-Path $readmeDst)) {
    $parentDir = Split-Path -Parent $readmeDst
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    Copy-Item $readmeSrc $readmeDst
    Write-Host "  + skills/_stubs/README.md (template created)" -ForegroundColor Green
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Files applied successfully." -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Paste 2 snippets:" -ForegroundColor Gray
Write-Host "     - config.yaml.additions.yaml -> config.yaml" -ForegroundColor Gray
Write-Host "     - main.py.anchor.additions.py -> main.py" -ForegroundColor Gray
Write-Host "  2. pytest tests/ -v" -ForegroundColor Gray
Write-Host "  3. python main.py --dry-run --case-id SMOKE-V12" -ForegroundColor Gray
Write-Host "  4. python scripts/verify_audit.py artifacts/SMOKE-V12/audit.jsonl SMOKE-V12" -ForegroundColor Gray
