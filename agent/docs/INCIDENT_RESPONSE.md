# INCIDENT_RESPONSE.md — แผนเผชิญเหตุเมื่อการตรวจสอบพยานหลักฐานล้มเหลว (Forensic Integrity Incident Response SOP)

- **เวอร์ชัน:** 1.0 · **ระบบ:** Trustworthy Agent v1.2 · **ปรับปรุงล่าสุด:** 2026-11-05
- **ระดับมาตรฐาน:** Court-grade (สอดคล้อง ISO/IEC 27035, ISO/IEC 27037:2012, ISO/IEC 27043)
- **กลุ่มเป้าหมาย:** พนักงานสอบสวน, Forensic Analyst, Evidence Custodian, IT Security, DPO / ฝ่ายกฎหมาย

---

## 1. วัตถุประสงค์ (Purpose)

เอกสารนี้กำหนดขั้นตอนปฏิบัติมาตรฐาน (SOP) ทันทีที่สคริปต์ตรวจสอบความสมบูรณ์ (`verify_audit.py`, `verify_all.py`, หรือ `--verify-artifacts`) รายงานความล้มเหลว เพื่อให้ผู้ปฏิบัติงานสามารถ **รักษาสภาพพยานหลักฐาน ณ เวลาเกิดเหตุ (Freeze & Quarantine)** ป้องกันการสูญเสียหลักฐานซ้ำซ้อน และวิเคราะห์หาสาเหตุรากเหง้า (Root Cause Analysis) ได้อย่างถูกต้องตามหลักนิติวิทยาศาสตร์

---

## 2. ตารางจำแนกระดับความรุนแรง (Severity Matrix)

| รหัสเหตุการณ์ | อาการ / ผลลัพธ์จากระบบ | ระดับความรุนแรง | ความหมายและผลกระทบต่อรูปคดี |
|---|---|:---:|---|
| **IR-01** | `verify_audit.py` คืนค่า **Exit Code 2** (`ZERO-ENTRY TRAP`, `TRUNCATION`, หรือ `HEAD MISMATCH`) | 🔴 **วิกฤต (SEV-1 Critical)** | Audit Log ถูกลบ ตัดทอนบรรทัดท้าย หรือเขียนทับหลังจากตรึง Anchor แล้ว — สงสัยว่ามีการทำลายพยานหลักฐานโดยเจตนา |
| **IR-02** | `verify_audit.py` คืนค่า **Exit Code 1** (`CHAIN BROKEN: prev_hash / entry_hash mismatch`) | 🔴 **วิกฤต (SEV-1 Critical)** | บรรทัดใดบรรทัดหนึ่งใน Audit Log ถูกแก้ไข ลบ หรือแทรกกลางลำดับ — โซ่ความน่าเชื่อถือของ Log ขาด |
| **IR-03** | `--verify-artifacts` รายงาน `TAMPERED`, `MISSING`, หรือ `MERKLE_ROOT_MISMATCH` | 🔴 **วิกฤต (SEV-1 Critical)** | ไฟล์พยานหลักฐานในโฟลเดอร์ `artifacts/<CASE_ID>/` ถูกแก้ไขหรือถูกลบหลังจากสร้าง Manifest |
| **IR-04** | ค่า SHA-256 ของสคริปต์ตรวจสอบไม่ตรงกับ `docs/SIGNED_HASHES.txt` | 🔴 **วิกฤต (SEV-1 Critical)** | เครื่องมือตรวจสอบ (`verify_*.py` / `guardrails.py`) อาจถูกดัดแปลงเพื่อปกปิดร่องรอย |
| **IR-05** | `--verify-artifacts` รายงาน `UNMANIFESTED_FILE` (แต่ไฟล์เดิมทุกไฟล์ยังมี Hash ตรง) | 🟠 **สูง (SEV-2 High)** | มีไฟล์แปลกปลอมถูกวางเพิ่มในโฟลเดอร์สำนวนคดี (เช่น เผลอเซฟไฟล์ชั่วคราว หรือมีการแอบยัดหลักฐานปลอม) |
| **IR-06** | `--replay <CASE_ID>` รายงาน Environment / Registry Diffs | 🟡 **ปานกลาง (SEV-3 Medium)** | เวอร์ชัน Python, โมเดล หรือจำนวนสกิลในเครื่องปัจจุบันต่างจากตอนรันเคสครั้งแรก (ไม่กระทบความสมบูรณ์ของไฟล์ที่เก็บไว้แล้ว) |
| **IR-07** | `verify_audit.py` คืนค่า **Exit Code 3** (`usage error`) | 🟢 **ต่ำ (SEV-4 Info)** | พิมพ์คำสั่งหรือพารามิเตอร์ไม่ครบถ้วน (ไม่ใช่เหตุละเมิดความปลอดภัย) |

---

## 3. การปฏิบัติการฉุกเฉินทันที (Immediate Actions: 15 นาทีแรก)

เมื่อเกิดเหตุระดับ **SEV-1** หรือ **SEV-2** ให้ปฏิบัติตามกฎ **"หยุด-กักกัน-ห้ามแก้" (STOP — QUARANTINE — DO NOT FIX)** ดังนี้:

### ❌ สิ่งที่ห้ามทำโดยเด็ดขาด (Strict Prohibitions)
1. **ห้ามสั่งรัน `main.py` ซ้ำใน `<CASE_ID>` เดิม** เพราะจะทำให้เกิดการเขียนไฟล์ทับหรือต่อท้าย Log ที่มีปัญหา
2. **ห้ามเปิดไฟล์ `.jsonl` หรือไฟล์ใน `artifacts/<CASE_ID>/` ด้วย Text Editor แล้วกด Save** แม้ไม่ได้แก้เนื้อหา เพราะอาจทำให้ Timestamp (MACB) หรือ Line Ending (`CRLF`/`LF`) เปลี่ยน
3. **ห้ามสั่ง `git commit --amend`, `git tag -d`, หรือ `git reset`** เพื่อพยายามซ่อมแซมความผิดปกติด้วยตนเอง
4. **ห้ามลบไฟล์แปลกปลอม (`UNMANIFESTED_FILE`) ทิ้งทันที** ต้องเก็บไว้ตรวจพิสูจน์ว่าใครเป็นผู้สร้างและสร้างเมื่อใด

### ✅ สิ่งที่ต้องทำทันทีตามลำดับ (Step-by-Step Quarantine)

#### ขั้นที่ 1: บันทึกภาพหน้าจอและข้อความ Error ดิบ (ภายใน 2 นาที)
คัดลอกข้อความ Output ทั้งหมดบน Terminal พร้อมบันทึกเวลาปัจจุบัน (UTC และเวลาท้องถิ่น UTC+7 / UTC+8)

#### ขั้นที่ 2: สำเนาโฟลเดอร์หลักฐานไปยังพื้นที่กักกันแบบ Read-Only (ภายใน 5 นาที)
ใช้คำสั่งที่รักษาระบบเวลาไฟล์เดิม (Preserve Timestamps & Attributes):

```powershell
# Windows (PowerShell)
$ts = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$qDir = "C:\Forensic_Quarantine\INCIDENT_${ts}"
New-Item -ItemType Directory -Force -Path $qDir | Out-Null
robocopy .\artifacts\<CASE_ID> "$qDir\artifacts_<CASE_ID>" /E /COPY:DAT /DCOPY:DAT /R:1 /W:1
robocopy .\logs "$qDir\logs" /E /COPY:DAT /DCOPY:DAT /R:1 /W:1
```

```bash
# Linux / macOS
TS=$(date -u +"%Y%m%dT%H%M%SZ")
QDIR="/var/forensic_quarantine/INCIDENT_${TS}"
mkdir -p "$QDIR"
cp -a ./artifacts/<CASE_ID> "$QDIR/artifacts_<CASE_ID>"
cp -a ./logs "$QDIR/logs"
```

#### ขั้นที่ 3: สร้างบัญชี SHA-256 และข้อมูลเวลาไฟล์ (MACB Timeline Snapshot) ของชุดกักกัน (ภายใน 15 นาที)

```powershell
# Windows (PowerShell)
Get-ChildItem -Path $qDir -Recurse -File | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    "$h  $($_.LastWriteTimeUtc.ToString('o'))  $($_.Length)  $($_.FullName)"
} | Out-File -FilePath "$qDir\QUARANTINE_MANIFEST_SHA256.txt" -Encoding utf8

# ตั้งค่า Read-Only ทั้งโฟลเดอร์กักกัน
Get-ChildItem -Path $qDir -Recurse -File | Set-ItemProperty -Name IsReadOnly -Value $true
```

---

## 4. ผังการแจ้งเหตุและกรอบเวลา (Notification Tree & SLA)

| ลำดับ | บทบาทผู้รับแจ้ง (Role) | กรอบเวลาแจ้งเหตุ (SEV-1) | กรอบเวลาแจ้งเหตุ (SEV-2) | สิ่งที่ต้องส่งมอบในการแจ้ง |
|:---:|---|:---:|:---:|---|
| 1 | **เจ้าของสำนวนคดี (Case Owner / Lead Investigator)** | **ภายใน 30 นาที** | ภายใน 2 ชั่วโมง | Case ID, รหัสเหตุการณ์ (IR-01..05), คำสั่งที่รันและข้อความ Error |
| 2 | **ผู้ควบคุมหลักฐาน (Evidence Custodian)** | **ภายใน 1 ชั่วโมง** | ภายใน 4 ชั่วโมง | พิกัดโฟลเดอร์กักกัน (`$qDir`) และไฟล์ `QUARANTINE_MANIFEST_SHA256.txt` |
| 3 | **ฝ่ายความมั่นคงปลอดภัยสารสนเทศ (IT Security / SOC)** | **ภายใน 2 ชั่วโมง** | ภายใน 8 ชั่วโมง | ข้อมูลผู้ใช้ที่ล็อกอินเครื่อง, ประวัติคำสั่ง Shell, และ System Event Logs |
| 4 | **ที่ปรึกษากฎหมาย / DPO (Legal Counsel & DPO)** | **ภายใน 4 ชั่วโมง** | ภายใน 24 ชั่วโมง | ประเมินผลกระทบต่อการยื่นบัญชีระบุพยานในชั้นศาล (ป.วิ.อาญา / 刑事訴訟法) |

---

## 5. รายการตรวจสอบหาสาเหตุรากเหง้า 10 ข้อ (10-Point Root Cause Checklist)

ทีมตรวจพิสูจน์ต้องไล่ตรวจสอบตามลำดับข้อ 1 ถึง 10 โดยทำงานบน **สำเนาในโฟลเดอร์กักกัน** เท่านั้น:

- [ ] **ข้อ 1 — ตรวจ Line Ending / Encoding Drift:** ไฟล์ `.jsonl` หรือ `.md` ถูกแปลงจาก `LF` (`\n`) เป็น `CRLF` (`\r\n`) โดยโปรแกรมจัดการไฟล์หรือ Git Auto-CRLF หรือไม่?
- [ ] **ข้อ 2 — เปรียบเทียบ Dual Audit Chain:** ตรวจสอบเทียบกันระหว่าง Global Chain (`logs/audit.jsonl`) กับ Case Chain (`artifacts/<CASE_ID>/audit.jsonl`) — หากพังเพียงไฟล์เดียว แต่อีกไฟล์ยังสมบูรณ์ 100% สามารถใช้ไฟล์ที่สมบูรณ์เป็นหลักฐานพิสูจน์จุดที่ถูกแก้ไขได้ทันที
- [ ] **ข้อ 3 — ตรวจตำแหน่งบรรทัดที่โซ่ขาด (`line N`):** ในกรณี `IR-02` ให้ดูบรรทัดที่ `N-1`, `N`, และ `N+1` ว่าค่า `prev_hash` ของบรรทัด `N+1` ชี้กลับไปที่ `entry_hash` ของ `N-1` (แปลว่ามีการลบบรรทัดกลาง) หรือค่า `entry_hash` ของบรรทัด `N` เปลี่ยนไปอย่างเดียว (แปลว่าเนื้อหาบรรทัด `N` ถูกแก้)
- [ ] **ข้อ 4 — ตรวจเปรียบเทียบกับ Git Object Database:** รัน `git log -p -n 5 logs/anchor_ledger.json` และ `git fsck --full` เพื่อดูว่ามีการลบ Tag หรือแก้ไข Commit ย้อนหลังหรือไม่
- [ ] **ข้อ 5 — ตรวจ MACB Timestamps ของไฟล์ที่ถูกแก้:** ดูค่า `LastWriteTimeUtc` (Modified) และ `CreationTimeUtc` ของไฟล์ที่ขึ้นสถานะ `TAMPERED` หรือ `UNMANIFESTED_FILE` ว่าเกิดขึ้นในเวลาใด และตรงกับช่วงเวลาทำงานของเจ้าหน้าที่คนใด
- [ ] **ข้อ 6 — ตรวจไฟล์สำรองอัตโนมัติ (`.bak.*` หรือ `checkpoint.json`):** ตรวจสอบว่ามีไฟล์ `.bak.<timestamp>` หรือ `artifacts/<CASE_ID>/checkpoint.json` ที่บันทึกสถานะก่อนเกิดเหตุหรือไม่
- [ ] **ข้อ 7 — ตรวจประวัติการใช้งานระบบปฏิบัติการ (OS Audit / PowerShell History):**
  - Windows: ตรวจ `(Get-PSReadLineOption).HistorySavePath` และ Windows Event Viewer (Security ID 4624/4663)
  - Linux/macOS: ตรวจ `~/.bash_history`, `~/.zsh_history`, `/var/log/auth.log`
- [ ] **ข้อ 8 — ตรวจความสมบูรณ์ของซอฟต์แวร์ระบบ:** รัน `Get-FileHash` เทียบกับ `docs/SIGNED_HASHES.txt` และรัน `git status --ignored` เพื่อหาไฟล์สคริปต์แปลกปลอม
- [ ] **ข้อ 9 — ตรวจสถานะฮาร์ดแวร์และดิสก์:** ตรวจสอบว่าเกิด Disk Full, Bad Sector, หรือไฟดับกะทันหันระหว่างรันหรือไม่ (ตรวจจาก `checkpoint.json` ว่าค้างที่ Step ใด)
- [ ] **ข้อ 10 — สรุปจำแนกสาเหตุ:** ระบุให้ชัดเจนว่าเกิดจาก **(ก) ความผิดพลาดทางเทคนิค/ระบบไฟล์**, **(ข) ความผิดพลาดโดยไม่เจตนาของผู้ปฏิบัติงาน**, หรือ **(ค) การกระทำโดยเจตนาเพื่อแก้ไข/ทำลายหลักฐาน**

---

## 6. แม่แบบรายงานสรุปเหตุการณ์หลังการสอบสวน (Post-Incident Report Template)

```markdown
# รายงานผลการสอบสวนเหตุความผิดปกติของพยานหลักฐานดิจิทัล (Forensic Integrity Incident Report)

## 1. ข้อมูลอ้างอิงเหตุการณ์ (Incident Identification)
- **หมายเลขเหตุการณ์ (Incident ID):** INC-<YYYYMMDD>-<SEQ>
- **หมายเลขสำนวนคดีที่เกี่ยวข้อง (Case ID):** <CASE_ID>
- **รหัสและระดับความรุนแรง:** <IR-01..06> / <SEV-1..3>
- **วันเวลาที่ตรวจพบเหตุ (UTC / UTC+7):** <YYYY-MM-DD HH:MM:SS>
- **ผู้ตรวจพบเหตุ:** <ชื่อ-นามสกุล, ตำแหน่ง>

## 2. รายละเอียดความผิดปกติที่ตรวจพบ (Observed Anomaly)
- **คำสั่งที่ใช้ตรวจสอบ:** `<เช่น python scripts/verify_audit.py ...>`
- **Exit Code และข้อความที่ได้รับ:**
  ```text
  <วางข้อความ Output ดิบที่นี่>
  ```
- **ไฟล์ที่ได้รับผลกระทบ:** `<ระบุพาธไฟล์และค่า SHA-256 ก่อนเกิดเหตุ vs หลังเกิดเหตุ>`

## 3. การกักกันและรักษาสภาพหลักฐาน (Containment & Preservation)
- **เวลาที่ทำสำเนากักกันสำเร็จ:** <YYYY-MM-DD HH:MM:SS>
- **พาธโฟลเดอร์กักกัน:** `<Path>`
- **SHA-256 ของไฟล์ QUARANTINE_MANIFEST_SHA256.txt:** `<HEX_64>`

## 4. ผลการวิเคราะห์สาเหตุรากเหง้า (Root Cause Analysis Findings)
- **ผลการเทียบเคียง Global Chain vs Case Chain:** <ระบุว่า Chain ใดยังคงสมบูรณ์>
- **ผลการตรวจตาม Checklist 10 ข้อ:** <สรุปข้อที่พบความผิดปกติ>
- **สรุปสาเหตุรากเหง้า:**
  - [ ] ความขัดข้องทางเทคนิค / การแปลงรหัสบรรทัด (Technical / Encoding Drift)
  - [ ] ความผิดพลาดในการปฏิบัติงานโดยไม่เจตนา (Human Operational Error)
  - [ ] การแทรกแซงหรือแก้ไขข้อมูลโดยไม่ได้รับอนุญาต (Unauthorized Tampering / Malicious Act)

## 5. ผลกระทบต่อความน่าเชื่อถือของพยานหลักฐานในชั้นศาล (Evidentiary Impact Assessment)
- **พยานหลักฐานส่วนที่ยังพิสูจน์ความบริสุทธิ์ได้ 100%:** <ระบุไฟล์ที่ SHA-256 ตรงกับ Manifest/Anchor>
- **พยานหลักฐานส่วนที่ต้องคัดออกหรือหมายเหตุในสำนวน:** <ระบุไฟล์ที่มีปัญหา>
- **แนวทางแก้ไขและป้องกันไม่ให้เกิดซ้ำ (Corrective & Preventive Actions):** <ระบุ>

ลงชื่อ ____________________________________ ผู้สอบสวนเหตุการณ์ (Incident Investigator)
ลงชื่อ ____________________________________ ผู้ควบคุมหลักฐาน (Evidence Custodian)
ลงชื่อ ____________________________________ ที่ปรึกษากฎหมาย / DPO (อนุมัติรายงาน)
วันที่ ________ / ________ / ____________
```
