param([string]$Target = (Get-Location).Path)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "=== Trustworthy Agent v1.6.1 - Case-ID Injection ===" -ForegroundColor Cyan

$files = @(
    @("01_core/core/case_id.py",           "core/case_id.py"),
    @("01_core/core/case_id_injector.py",  "core/case_id_injector.py"),
    @("04_tests/tests/test_case_id_injection.py","tests/test_case_id_injection.py")
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

# Copy snippet files for manual paste
Copy-Item (Join-Path $Here "02_orchestrator/core/orchestrator.additions.py") `
          (Join-Path $Target "core/orchestrator.additions.py") -Force
Copy-Item (Join-Path $Here "03_skill_patch/skills/case-dossier-exporter.additions.py") `
          (Join-Path $Target "skills/investigation/case-dossier-exporter/run.py.additions.py") -Force
Write-Host "  core/orchestrator.additions.py" -ForegroundColor Magenta
Write-Host "  skills/investigation/case-dossier-exporter/run.py.additions.py" -ForegroundColor Magenta

Write-Host "Files applied." -ForegroundColor Green
