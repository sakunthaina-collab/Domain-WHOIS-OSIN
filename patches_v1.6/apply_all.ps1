param([string]$Target = (Get-Location).Path)

$ErrorActionPreference = "Stop"

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`n═══ Trustworthy Agent v1.6 — Release + Packet ═══" -ForegroundColor Cyan

$files = @(

    @("01_release_signing/scripts/pre_release_check.py", "scripts/pre_release_check.py"),

    @("01_release_signing/scripts/sign_release.py",      "scripts/sign_release.py"),

    @("01_release_signing/docs/RELEASE_v1.5.0.md",       "docs/RELEASE_v1.5.0.md"),

    @("01_release_signing/docs/RELEASE_PROCESS.md",      "docs/RELEASE_PROCESS.md"),

    @("02_auditor_packet/scripts/build_auditor_packet.py","scripts/build_auditor_packet.py"),

    @("02_auditor_packet/templates/README.md",           "scripts/templates/README.md"),

    @("02_auditor_packet/templates/VERIFY.sh",           "scripts/templates/VERIFY.sh"),

    @("02_auditor_packet/templates/VERIFY.ps1",          "scripts/templates/VERIFY.ps1")

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

Write-Host "`n✅ Files applied." -ForegroundColor Green

Write-Host "`n── Release workflow ──" -ForegroundColor Yellow

Write-Host "  1. python scripts/pre_release_check.py" -ForegroundColor Gray

Write-Host "  2. python scripts/sign_release.py --sign" -ForegroundColor Gray

Write-Host "  3. python scripts/sign_release.py --verify" -ForegroundColor Gray

Write-Host "  4. git add -A; git commit -m 'release: v1.5.0'" -ForegroundColor Gray

Write-Host "  5. git tag -s v1.5.0 -m 'Trustworthy Agent v1.5.0'" -ForegroundColor Gray

Write-Host "  6. git tag -v v1.5.0" -ForegroundColor Gray

Write-Host "  7. python scripts/build_auditor_packet.py --tag v1.5.0 --out dist/" -ForegroundColor Gray

Write-Host "  8. cd dist/auditor_packet_v1.5.0; ./VERIFY.sh  (or .\VERIFY.ps1)" -ForegroundColor Gray

Post-apply Checklist

#	คำสั่ง	ผลที่ต้องได้

1	python scripts/pre_release_check.py	✅ All checks passed

2	python scripts/sign_release.py --sign	✅ SIGNED_HASHES.txt + .asc

3	python scripts/sign_release.py --verify	✅ signature valid + all hashes match

4	git tag -s v1.5.0 -m "..."	สำเร็จ

5	git tag -v v1.5.0	Good signature from Forensic Ops

6	python scripts/build_auditor_packet.py --tag v1.5.0 --out dist/	ได้ dist/auditor_packet_v1.5.0.zip

7	unzip → ./VERIFY.sh (หรือ .\VERIFY.ps1)	✅ PACKET VERIFIED

8	ทดสอบ tamper: แก้ไฟล์ใน DOCS/ แล้วรัน VERIFY	❌ TAMPERED: ... (exit ≠ 0)

9	ทดสอบ packet tamper: ลบ
