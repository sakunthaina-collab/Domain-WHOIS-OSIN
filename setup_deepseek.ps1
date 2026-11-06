#Requires -Version 5.1
<#
.SYNOPSIS
    ตรวจสอบ/ตั้งค่า DEEPSEEK_API_KEY สำหรับ DeepSeek Harness (dsh)
    และเผยแพร่ patch layer ที่แก้ baseURL ของ web search

.DESCRIPTION
    ขั้นตอนการทำงาน
      1. ตรวจสอบ $env:DEEPSEEK_API_KEY ในโปรเซสปัจจุบัน
      2. ถ้ายังไม่มี -> สร้างไฟล์ .env ตัวอย่าง (ไม่ทับของเดิม) ให้ผู้ใช้แก้ไข
      3. ถ้าส่ง -CopyPatch -> คัดลอก .agents\cordis.patch.yml ไป .agents\patches\

    ข้อเท็จจริงสำคัญ 2 ข้อ (อ่านก่อนใช้)
      * dsh ไม่ได้อ่านไฟล์ .env เอง — credential มาจาก ctx.credentials หรือ
        environment ของ "โปรเซสที่ launch dsh" เท่านั้น ถ้าต้องการให้ถาวรบน
        Windows ให้ใช้ -PromptForKey (เขียนลง User environment variable)
        แล้วเปิด terminal ใหม่ / relaunch dsh
      * .agents\patches\ ไม่ใช่ path ที่ dsh โหลดอัตโนมัติ — dsh ประกอบ patch
        จากโฟลเดอร์ profile ($env:DSH_HOME\profiles\<profile>\) หรือจาก
        --patch ที่ส่งตอน launch การคัดลอกไป .agents\patches\ มีประโยชน์เฉพาะ
        กับ tooling/CI ที่อ่านโฟลเดอร์นั้นเอง จึงเป็น opt-in (-CopyPatch)

.PARAMETER PatchSource
    ไฟล์ patch ต้นทาง (ค่าเริ่มต้น: .agents\cordis.patch.yml)

.PARAMETER PatchDestination
    โฟลเดอร์ปลายทางเมื่อใช้ -CopyPatch (ค่าเริ่มต้น: .agents\patches)

.PARAMETER EnvFileName
    ชื่อไฟล์ตัวอย่างที่สร้างเมื่อไม่พบคีย์ (ค่าเริ่มต้น: .env)

.PARAMETER CopyPatch
    คัดลอก patch ไปยัง PatchDestination

.PARAMETER PromptForKey
    ขอคีย์แบบซ่อนตัวอักษร (Read-Host -AsSecureString) แล้วบันทึกลง
    User environment variable แบบถาวร — คีย์จะไม่ถูกเขียนลงไฟล์ .env

.PARAMETER TestEndpoint
    ทดสอบการเชื่อมต่อ baseURL แบบไม่ใช้คีย์ (คาดหวัง HTTP 401/400 ไม่ใช่ 404)
    ถือเป็น diagnostics ไม่บล็อกการทำงาน

.PARAMETER BaseUrl
    Endpoint ที่จะทดสอบ/เขียนแนะนำ (ค่าเริ่มต้น: https://api.deepseek.com/anthropic/v1)

.EXAMPLE
    .\setup_deepseek.ps1
    # ตรวจ env / สร้าง .env ตัวอย่างถ้ายังไม่มี

.EXAMPLE
    .\setup_deepseek.ps1 -PromptForKey
    # ตั้งค่า DEEPSEEK_API_KEY ระดับผู้ใช้แบบถาวร

.EXAMPLE
    .\setup_deepseek.ps1 -CopyPatch -TestEndpoint
    # คัดลอก patch + ทดสอบ endpoint

.NOTES
    Exit codes:  0 = พร้อมใช้งาน, 2 = ยังไม่มีคีย์, 1 = เกิดข้อผิดพลาด
#>
[CmdletBinding()]
param(
    [string] $PatchSource      = (Join-Path $PSScriptRoot '.agents\cordis.patch.yml'),
    [string] $PatchDestination = (Join-Path $PSScriptRoot '.agents\patches'),
    [string] $EnvFileName      = '.env',
    [switch] $CopyPatch,
    [switch] $PromptForKey,
    [switch] $TestEndpoint,
    [string] $BaseUrl          = 'https://api.deepseek.com/anthropic/v1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$KeyName = 'DEEPSEEK_API_KEY'

function Write-Step  { param([string] $Text) Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok    { param([string] $Text) Write-Host "   [OK]    $Text" -ForegroundColor Green }
function Write-Info  { param([string] $Text) Write-Host "   [INFO]  $Text" -ForegroundColor Gray }
function Write-Warn2 { param([string] $Text) Write-Host "   [WARN]  $Text" -ForegroundColor Yellow }
function Write-Err   { param([string] $Text) Write-Host "   [ERROR] $Text" -ForegroundColor Red }

# เขียนไฟล์เป็น UTF-8 แบบไม่มี BOM (กัน BOM ทำ dotenv parser พัง)
function Write-Utf8NoBom {
    param([string] $Path, [string] $Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

# ── 1. ตรวจสอบคีย์ในโปรเซสปัจจุบัน ────────────────────────────────────────────
Write-Step '1/3 ตรวจสอบ DEEPSEEK_API_KEY'

$hasKey = $false
$processKey = [System.Environment]::GetEnvironmentVariable($KeyName, 'Process')
if (-not [string]::IsNullOrWhiteSpace($processKey)) {
    $hasKey = $true
    Write-Ok "พบ $KeyName ใน environment ของโปรเซสนี้ (ความยาว $($processKey.Length) ตัวอักษร)"
}

if (-not $hasKey -and $PromptForKey) {
    Write-Info "ยังไม่พบคีย์ — กำลังขอคีย์แบบซ่อนตัวอักษร"
    $secure = Read-Host -AsSecureString "วาง $KeyName (จะไม่แสดงบนหน้าจอ)"
    $plain  = [System.Net.NetworkCredential]::new('', $secure).Password
    if ([string]::IsNullOrWhiteSpace($plain)) {
        Write-Warn2 'ไม่ได้ป้อนค่า — ข้ามการตั้งค่า'
    }
    else {
        [System.Environment]::SetEnvironmentVariable($KeyName, $plain, 'User')
        $env:DEEPSEEK_API_KEY = $plain
        $hasKey = $true
        Write-Ok "บันทึก $KeyName ลง User environment variable แล้ว"
        Write-Info 'ต้องเปิด terminal ใหม่ (หรือ relaunch dsh) ค่าใหม่จึงจะมีผลกับโปรเซสที่ launch'
    }
}

if (-not $hasKey) {
    Write-Warn2 "ไม่พบ $KeyName"
    $envFile = Join-Path $PSScriptRoot $EnvFileName
    if (Test-Path -LiteralPath $envFile) {
        Write-Info "พบไฟล์ $envFile อยู่แล้ว — ไม่ทับให้ ตรวจสอบว่ามีบรรทัด $KeyName=..."
    }
    else {
        $template = @"
# $EnvFileName — ตัวอย่าง environment สำหรับ DeepSeek
# รับคีย์ที่ https://platform.deepseek.com/
$KeyName=YOUR_DEEPSEEK_API_KEY_HERE
# (ไม่บังคับ) เปลี่ยน endpoint ของ web search
# DEEPSEEK_SEARCH_BASE_URL=$BaseUrl

# หมายเหตุ: dsh ไม่ได้อ่านไฟล์นี้เอง — ต้อง export เข้าโปรเซสที่ launch dsh
#   PowerShell : Get-Content .env -Encoding UTF8 | ForEach-Object { if (`$_ -match '^([^#=]+)=(.*)$') { Set-Item "env:`$(`$Matches[1])" "`$(`$Matches[2])" } }
#   หรือถาวร : .\setup_deepseek.ps1 -PromptForKey
"@
        Write-Utf8NoBom -Path $envFile -Content $template
        Write-Ok "สร้างไฟล์ตัวอย่าง: $envFile"
        Write-Info 'แก้ไขไฟล์ แล้วตั้งค่าเป็น environment variable ก่อน launch dsh'
    }
    Write-Host "`n[RESULT] ยังไม่พร้อมใช้งาน — ไม่มี $KeyName" -ForegroundColor Yellow
    exit 2
}

# ── 2. ตรวจสอบ patch ต้นทาง ────────────────────────────────────────────────────
Write-Step '2/3 ตรวจสอบไฟล์ patch'

if (-not (Test-Path -LiteralPath $PatchSource)) {
    Write-Err "ไม่พบไฟล์ patch: $PatchSource"
    Write-Info 'ระบุตำแหน่งด้วย -PatchSource <path> ถ้าเก็บไว้ที่อื่น'
    exit 1
}
$patchText = Get-Content -LiteralPath $PatchSource -Raw

# patch layer ต้องเป็น YAML array (บรรทัดที่มีเนื้อหาบรรทัดแรกต้องขึ้นต้นด้วย '-')
$firstContentLine = ($patchText -split "`r?`n" |
    Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') } |
    Select-Object -First 1)
if ($null -eq $firstContentLine -or -not $firstContentLine.Trim().StartsWith('-')) {
    Write-Err 'ไฟล์ patch ไม่ได้เป็น YAML array — dsh ต้องการรายการที่ขึ้นต้นด้วย "- id: ..." '
    exit 1
}
if ($patchText -notmatch 'api\.deepseek\.com/anthropic/v1') {
    Write-Warn2 'ไม่พบ baseURL ที่คาดไว้ (https://api.deepseek.com/anthropic/v1) — ตรวจสอบก่อนใช้'
}
Write-Ok "patch อยู่ในรูปแบบที่ถูกต้อง: $PatchSource"

# ── 3. คัดลอก patch (opt-in) ───────────────────────────────────────────────────
Write-Step '3/3 เผยแพร่ patch'

if ($CopyPatch) {
    if (-not (Test-Path -LiteralPath $PatchDestination)) {
        New-Item -ItemType Directory -Path $PatchDestination -Force | Out-Null
    }
    Copy-Item -LiteralPath $PatchSource -Destination $PatchDestination -Force
    Write-Ok "คัดลอกไปที่: $(Join-Path $PatchDestination (Split-Path -Leaf $PatchSource))"
    Write-Warn2 'โฟลเดอร์นี้ไม่ใช่ path ที่ dsh โหลดอัตโนมัติ — dsh ใช้ $env:DSH_HOME\profiles\<profile>\cordis.patch.yml หรือ --patch'
}
else {
    Write-Info 'ข้ามการคัดลอก (ใช้ -CopyPatch ถ้าต้องการ)'
}

# ── diagnostics: ทดสอบ endpoint ────────────────────────────────────────────────
if ($TestEndpoint) {
    Write-Step 'ทดสอบการเชื่อมต่อ endpoint'
    $probe = "$BaseUrl/messages"
    try {
        Invoke-WebRequest -Uri $probe -Method Post -ContentType 'application/json' `
            -Body '{}' -TimeoutSec 20 -UseBasicParsing | Out-Null
        Write-Ok "ติดต่อได้: $probe"
    }
    catch {
        $status = $null
        if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
            $status = [int] $_.Exception.Response.StatusCode
        }
        switch ($status) {
            404 { Write-Err "HTTP 404 — path ผิด: $probe  (ตรวจ baseURL ว่าไม่มี /messages ต่อท้ายอยู่แล้ว)" }
            401 { Write-Ok "HTTP 401 = endpoint ถูกต้อง แต่ยังไม่มี/ไม่ถูกต้องของคีย์" }
            400 { Write-Ok "HTTP 400 = endpoint ตอบรับ (body ว่างตามที่คาด)" }
            default {
                if ($null -eq $status) { Write-Warn2 "เชื่อมต่อไม่ได้: $($_.Exception.Message)" }
                else { Write-Info "HTTP $status จาก $probe" }
            }
        }
    }
}

Write-Host "`n[DONE] การตั้งค่าเสร็จสมบูรณ์" -ForegroundColor Green
Write-Host '   เปลี่ยน baseURL แบบสดได้ที่: Plugins -> Built-in plugin settings -> Web search -> "Messages API base URL"' -ForegroundColor Gray
Write-Host '   หรือกำหนด $env:DEEPSEEK_SEARCH_BASE_URL ก่อน launch dsh' -ForegroundColor Gray
exit 0
