#Requires -Version 5.1
<#
.SYNOPSIS
    Applies all Trustworthy Agent v1.1 patches to the target agent directory.
.PARAMETER TargetDir
    The root directory of the agent project (containing core/, skills/, etc.).
.PARAMETER RunTests
    Switch to immediately run pytest after copying files.
#>
[CmdletBinding()]
param (
    [string]$TargetDir = "",
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"

# Determine target directory
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    if (Test-Path -Path "core\registry.py") {
        $Target = "."
    } elseif (Test-Path -Path "agent\core\registry.py") {
        $Target = "agent"
    } elseif (Test-Path -Path "..\agent\core\registry.py") {
        $Target = "..\agent"
    } else {
        $Target = "."
    }
} else {
    $Target = $TargetDir
}

$PatchRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($PatchRoot)) {
    $PatchRoot = "."
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Applying Trustworthy Agent v1.1 Patches to: $Target" -ForegroundColor Cyan
Write-Host "Patch source: $PatchRoot" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Ensure target directories exist
$dirsToCreate = @(
    (Join-Path $Target "core"),
    (Join-Path $Target "scripts"),
    (Join-Path $Target "tests"),
    (Join-Path $Target "docs"),
    (Join-Path $Target "artifacts"),
    (Join-Path $Target "logs"),
    (Join-Path $Target "checkpoints")
)

foreach ($dir in $dirsToCreate) {
    if (-not (Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Green
    }
}

# File copy map
$copyPlan = @(
    @{ Src = "01_audit_chain\core\guardrails.py"; Dst = "core\guardrails.py" },
    @{ Src = "01_audit_chain\scripts\verify_audit.py"; Dst = "scripts\verify_audit.py" },
    @{ Src = "02_run_manifest\core\run_manifest.py"; Dst = "core\run_manifest.py" },
    @{ Src = "03_artifact_manifest\core\artifact_manifest.py"; Dst = "core\artifact_manifest.py" },
    @{ Src = "04_resilience\core\resilience.py"; Dst = "core\resilience.py" },
    @{ Src = "05_stub_management\scripts\detect_status.py"; Dst = "scripts\detect_status.py" },
    @{ Src = "05_stub_management\scripts\reorganize_stubs.py"; Dst = "scripts\reorganize_stubs.py" },
    @{ Src = "06_verification\scripts\verify_all.py"; Dst = "scripts\verify_all.py" },
    @{ Src = "07_tests\tests\test_audit_chain.py"; Dst = "tests\test_audit_chain.py" },
    @{ Src = "07_tests\tests\test_manifest.py"; Dst = "tests\test_manifest.py" },
    @{ Src = "07_tests\tests\test_resilience.py"; Dst = "tests\test_resilience.py" },
    @{ Src = "08_docs\docs\TRUST.md"; Dst = "docs\TRUST.md" }
)

foreach ($item in $copyPlan) {
    $srcPath = Join-Path $PatchRoot $item.Src
    $dstPath = Join-Path $Target $item.Dst
    if (Test-Path -Path $srcPath) {
        $parent = Split-Path -Path $dstPath -Parent
        if (-not (Test-Path -Path $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        Copy-Item -Path $srcPath -Destination $dstPath -Force
        Write-Host "  [OK] Copied $($item.Src) -> $($item.Dst)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Missing source: $srcPath" -ForegroundColor Yellow
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "All patches successfully copied!" -ForegroundColor Cyan

if ($RunTests) {
    Write-Host "Running pytest validation..." -ForegroundColor Yellow
    Push-Location $Target
    try {
        python -m pytest tests/ -v
    } finally {
        Pop-Location
    }
} else {
    Write-Host "To verify the system, run:" -ForegroundColor Gray
    Write-Host "  python $Target\scripts\verify_all.py --base-dir $Target" -ForegroundColor White
}
