#Requires -Version 5.1
# scripts/gpg_setup_org_key.ps1
param(
    [string]$NameReal = "Forensic Ops",
    [string]$Email    = "forensic-ops@example.org",
    [string]$Passphrase = $env:ANCHOR_GPG_PASSPHRASE,
    [string]$KeyType  = "RSA",
    [int]$KeyLength   = 4096,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# 1) check gpg
$gpgCmd = Get-Command gpg -ErrorAction SilentlyContinue
if ($gpgCmd) {
    $gpgBin = $gpgCmd.Source
} elseif (Test-Path "C:\Program Files\Git\usr\bin\gpg.exe") {
    $gpgBin = "C:\Program Files\Git\usr\bin\gpg.exe"
} elseif (Test-Path "C:\Program Files (x86)\GnuPG\bin\gpg.exe") {
    $gpgBin = "C:\Program Files (x86)\GnuPG\bin\gpg.exe"
} else {
    Write-Host "[FAIL] gpg not found on PATH." -ForegroundColor Red
    Write-Host "   Install GPG4Win: https://gpg4win.org/download.html" -ForegroundColor Yellow
    exit 1
}
Write-Host "[OK] gpg found: $gpgBin" -ForegroundColor Green

# Ensure ~/.gnupg exists and disable use-keyboxd on Git for Windows where keyboxd is not bundled
$gnupgDir = Join-Path $env:USERPROFILE ".gnupg"
if (-not (Test-Path $gnupgDir)) {
    New-Item -ItemType Directory -Path $gnupgDir -Force | Out-Null
}
$commonConf = Join-Path $gnupgDir "common.conf"
if (Test-Path $commonConf) {
    $confContent = Get-Content $commonConf -Raw -ErrorAction SilentlyContinue
    if ($confContent -match "use-keyboxd") {
        Set-Content -Path $commonConf -Value "# use-keyboxd disabled for Git for Windows compatibility`n" -Encoding ascii
    }
}

# 2) list existing keys
Write-Host "`n--- Existing secret keys ---" -ForegroundColor Cyan
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$existing = & $gpgBin --list-secret-keys --with-colons 2>$null | Select-String "^sec:"
$ErrorActionPreference = $prevEAP
if (-not $existing) { Write-Host "   (none)" -ForegroundColor Gray } else { Write-Host $existing }

# 3) generate key (batch mode, non-interactive)
if (-not $Passphrase -and -not $DryRun) {
    Write-Host "`n[FAIL] ANCHOR_GPG_PASSPHRASE env var not set." -ForegroundColor Red
    Write-Host '   Set it before running: $env:ANCHOR_GPG_PASSPHRASE = "your-strong-passphrase"' -ForegroundColor Yellow
    exit 1
}

$batch = @"
%no-protection
Key-Type: $KeyType
Key-Length: $KeyLength
Key-Usage: sign
Name-Real: $NameReal
Name-Email: $Email
Expire-Date: 2y
%commit
"@

if ($DryRun) {
    Write-Host "`n[dry-run] would generate key:" -ForegroundColor Yellow
    Write-Host $batch -ForegroundColor Gray
    exit 0
}

Write-Host "`n--- Generating key ---" -ForegroundColor Cyan
$ErrorActionPreference = "Continue"
$batch | & $gpgBin --batch --status-fd 1 --generate-key 2>$null | Out-String | Write-Host -ForegroundColor DarkGray
$genExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
if ($genExit -ne 0) {
    Write-Host "[FAIL] key generation failed" -ForegroundColor Red
    exit 1
}

# 4) get fingerprint
$ErrorActionPreference = "Continue"
$fprLine = (& $gpgBin --list-keys --with-colons $Email 2>$null | Select-String "^fpr:" | Select-Object -First 1).ToString()
$ErrorActionPreference = $prevEAP
$fpr = $fprLine.Split(":")[9]
Write-Host "`n[OK] Key generated" -ForegroundColor Green
Write-Host "   Fingerprint: $fpr" -ForegroundColor Yellow
Write-Host "`n--- Set this in your environment ---" -ForegroundColor Cyan
Write-Host "   `$env:ANCHOR_GPG_KEY = `"$fpr`"" -ForegroundColor Gray

# 5) export public key for auditors
$pubkeyPath = "docs/public-key-$($fpr.Substring(0,16)).asc"
New-Item -ItemType Directory -Path "docs" -Force | Out-Null
$ErrorActionPreference = "Continue"
& $gpgBin --armor --export $fpr 2>$null | Out-File -FilePath $pubkeyPath -Encoding ascii
$ErrorActionPreference = $prevEAP
Write-Host "`n[OK] Public key exported: $pubkeyPath" -ForegroundColor Green
Write-Host "   Share this with auditors so they can verify signatures." -ForegroundColor Gray
