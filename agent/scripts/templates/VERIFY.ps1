# One-command verifier for the Auditor Evidence Packet (Windows).
$ErrorActionPreference = "Continue"

function Ok   ($m) { Write-Host "[PASS] $m" -ForegroundColor Green }
function Fail ($m) { Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }
function Warn ($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

Write-Host "============================================================"
Write-Host "  Auditor Evidence Packet - Verifier (Windows)"
Write-Host "============================================================"
Write-Host ""

if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
    if (Test-Path 'C:\Program Files\Git\usr\bin') {
        $env:PATH = 'C:\Program Files\Git\usr\bin;' + $env:PATH
    }
}
$gpg = Get-Command gpg -ErrorAction SilentlyContinue
$expectedFp = "3892E3F2CEDAE88EDEF85D64892DBC9697F6927A"

# -- [1/5] import public key --------------------------------
Write-Host "-- [1/5] Importing org public key --"
if (-not (Test-Path "TRUST\public-key.asc")) { Fail "TRUST\public-key.asc missing" }

if ($gpg) {
    & gpg --batch --import "TRUST\public-key.asc" 2>&1 | Out-Null
    $fprLine = & gpg --batch --list-keys --with-colons $expectedFp 2>&1 |
               Select-String "^fpr:" | Select-Object -First 1
    if (-not $fprLine) {
        $fprLine = & gpg --batch --list-keys --with-colons 2>&1 |
                   Select-String "^fpr:" | Select-Object -First 1
    }
    if (-not $fprLine) { Fail "cannot extract fingerprint" }
    $fp = $fprLine.ToString().Split(":")[9]
    Write-Host "   fingerprint: $fp"
    if (-not $fp.StartsWith($expectedFp.Substring(0, 16))) {
        Fail "fingerprint MISMATCH - expected $expectedFp"
    }
    Ok "fingerprint matches"
} else {
    Warn "gpg not installed - signature checks will be SKIPPED"
}

# -- [2/5] SIGNED_HASHES.txt.asc ----------------------------
Write-Host ""
Write-Host "-- [2/5] Verifying SIGNED_HASHES.txt signature --"
if ($gpg) {
    $out = & gpg --batch --verify "TRUST\SIGNED_HASHES.txt.asc" "TRUST\SIGNED_HASHES.txt" 2>&1 | Out-String
    if ($out -match "Good signature") { Ok "signature valid" }
    else { Fail "SIGNED_HASHES.txt signature INVALID" }
} else {
    Warn "skipped"
}

# -- [3/5] MANIFEST.json.asc --------------------------------
Write-Host ""
Write-Host "-- [3/5] Verifying MANIFEST.json signature --"
if ($gpg) {
    $out = & gpg --batch --verify "MANIFEST.json.asc" "MANIFEST.json" 2>&1 | Out-String
    if ($out -match "Good signature") { Ok "signature valid" }
    else { Fail "MANIFEST.json signature INVALID" }
} else {
    Fail "MANIFEST.json signature INVALID (gpg missing)"
}

# -- [4/5] source file hashes -------------------------------
Write-Host ""
Write-Host "-- [4/5] Checking source file hashes --"
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid().ToString()))
try {
    $tarBin = if (Test-Path "$env:SystemRoot\System32\tar.exe") { "$env:SystemRoot\System32\tar.exe" } else { "tar" }
    & $tarBin -xzf "SOURCE\source.tar.gz" -C $tmp.FullName
    $bad = 0
    Get-Content "TRUST\SIGNED_HASHES.txt" | ForEach-Object {
        if (-not $_.Trim()) { return }
        $parts = $_ -split "\s+", 2
        $expected = $parts[0].Trim().ToLower()
        $rel = $parts[1].Trim()
        $p = Join-Path $tmp.FullName $rel
        if (-not (Test-Path $p)) { Write-Host "MISSING: $rel" -ForegroundColor Red; $bad++; return }
        $got = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
        if ($got -ne $expected) { Write-Host "TAMPERED: $rel" -ForegroundColor Red; $bad++ }
    }
    if ($bad -gt 0) { Fail "$bad source file(s) failed hash check" }
    Ok "all source files match"
} finally {
    Remove-Item -Recurse -Force $tmp.FullName
}

# -- [5/5] MANIFEST vs packet files -------------------------
Write-Host ""
Write-Host "-- [5/5] Checking MANIFEST.json against packet files --"
$mf = Get-Content "MANIFEST.json" -Raw | ConvertFrom-Json
$bad = 0
foreach ($f in $mf.files) {
    if (-not (Test-Path $f.path)) { Write-Host "MISSING: $($f.path)" -ForegroundColor Red; $bad++; continue }
    $got = (Get-FileHash $f.path -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $f.sha256) { Write-Host "TAMPERED: $($f.path)" -ForegroundColor Red; $bad++ }
}
if ($bad -gt 0) { Fail "$bad packet file(s) failed" }
Ok "$($mf.file_count) packet files verified (merkle $($mf.merkle_root.Substring(0,32))...)"

Write-Host ""
Write-Host "============================================================"
Write-Host "  [OK] PACKET VERIFIED - all checks passed" -ForegroundColor Green
Write-Host "============================================================"
