# GPG_KEY_MANAGEMENT.md — นโยบายการบริหารจัดการกุญแจลงนามดิจิทัล (GPG Key Management Policy)

- **เจ้าของนโยบาย (Owner):** Forensic Ops Lead & Evidence Custodian
- **รอบการทบทวน (Review Cycle):** ทุก 6 เดือน
- **ระดับชั้นความลับ:** Internal / Auditor-Shareable (สอดคล้อง ISO/IEC 27037 & ISO/IEC 27001 A.10)

---

## 1. เหตุผลความจำเป็นทางนิติวิทยาศาสตร์ (Why GPG Matters in Court)

การสร้าง Git Tag แบบปกติ (`git tag -a`) พิสูจน์ได้เพียงว่า *"มีผู้ใช้งานคนหนึ่งในเครื่องนี้สร้าง Tag ณ เวลานั้น"* แต่การลงลายมือชื่อดิจิทัลด้วย GPG 2 ชั้น (**Dual-Layer GPG Attestation**):
1. **Layer 1 (`logs/anchor_ledger.json.asc`):** ลายมือชื่อดิจิทัลแบบแยกไฟล์ (Detached ASCII-armored Signature) รับรองความบริสุทธิ์ของบัญชีหมุดตรึงทั้งหมด
2. **Layer 2 (`git tag -s`):** ลายมือชื่อดิจิทัลฝังใน Git Tag Object ผูกกับ Commit Hash และ Timestamp

พิสูจน์ต่อศาลได้ว่า **"องค์กร (ผ่านกุญแจลับของผู้ควบคุมหลักฐานที่มี Fingerprint ระบุชัดเจน) เป็นผู้รับรองความสมบูรณ์ของพยานหลักฐานชุดนี้ ณ เวลานั้นจริง และไม่มีผู้ใดแก้ไขบัญชีหมุดตรึงในภายหลัง"**

---

## 2. โครงสร้างลำดับชั้นของกุญแจ (Key Hierarchy)

| ประเภทกุญแจ | วัตถุประสงค์ | อายุใช้งาน | สถานที่จัดเก็บ |
|---|---|---|---|
| **Org Signing Key (Secret Key)** | ลงนาม `anchor_ledger.json.asc` และ `git tag -s` | 2 ปี | HSM / YubiKey (หลัก) หรือ Encrypted Offline USB ในตู้เซฟนิรภัย (สำรอง) |
| **Auditor Verification Key (Public Key)** | แจกจ่ายให้ Auditor, ศาล, และพนักงานสอบสวนใช้ตรวจสอบลายมือชื่อ | 2 ปี (และเก็บถาวรเพื่อตรวจคดีย้อนหลัง) | `docs/public-key-<FPR16>.asc` และแนบในชุดสำนวนคดี (`artifacts/<CASE_ID>/`) |

---

## 3. ขั้นตอนการสร้างกุญแจประจำองค์กร (Key Generation Procedure)

### 3.1 สำหรับ Windows (PowerShell)
```powershell
$env:ANCHOR_GPG_PASSPHRASE = "<รหัสผ่านความยาวอย่างน้อย 24 ตัวอักษร>"
.\scripts\gpg_setup_org_key.ps1 -NameReal "Forensic Evidence Custodian" -Email "custodian@forensic.example.org"
$env:ANCHOR_GPG_KEY = "<FINGERPRINT_40_HEX>"
```

### 3.2 สำหรับ Linux / macOS (Bash)
```bash
export ANCHOR_GPG_PASSPHRASE="$(openssl rand -base64 32)"
./scripts/gpg_setup_org_key.sh
export ANCHOR_GPG_KEY="<FINGERPRINT_40_HEX>"
```

> **ข้อกำหนดสำคัญ:** ต้องระบุ `ANCHOR_GPG_KEY` ด้วย **Full Fingerprint 40 หลัก** เสมอ ห้ามใช้ Short Key ID (8 หลัก) เพื่อป้องกันการโจมตีแบบ Key Collision

---

## 4. ขั้นตอนการสำรองกุญแจลับและใบเพิกถอน (Backup & Revocation Certificate)

```bash
# 1. สร้างใบเพิกถอนกุญแจฉุกเฉินเก็บไว้ล่วงหน้า
gpg --output revoke-<FPR16>.asc --gen-revoke <FINGERPRINT>

# 2. ส่งออกกุญแจลับและเข้ารหัสซ้ำด้วย AES-256
gpg --armor --export-secret-keys <FINGERPRINT> \
    | gpg --symmetric --cipher-algo AES256 \
    > secret-key-backup.asc.gpg
```
- เก็บไฟล์ `secret-key-backup.asc.gpg` และ `revoke-<FPR16>.asc` ไว้ในสื่อบันทึกแบบ Offline ที่แยกสถานที่จัดเก็บ (Air-gapped Safe)
- ห้ามเก็บไฟล์สำรองกุญแจลับไว้บนเครื่องเซิร์ฟเวอร์เดียวกับที่รัน Agent

---

## 5. การหมุนเวียนและเพิกถอนกุญแจ (Key Rotation & Revocation)

| เหตุการณ์ | การดำเนินการ |
|---|---|
| **ครบกำหนด 2 ปี (Scheduled Rotation)** | สร้างกุญแจใหม่และใช้ลงนามคดีใหม่ทันที **ห้ามลบกุญแจเก่าออกจากคลัง Public Key** เพื่อให้ยังตรวจสอบสำนวนคดีเก่าได้ตลอดอายุความ 20 ปี |
| **สงสัยว่ากุญแจรั่วไหล (Key Compromise)** | นำเข้าใบเพิกถอน (`gpg --import revoke-*.asc`), แจ้งเหตุตาม `docs/INCIDENT_RESPONSE.md` ภายใน 4 ชั่วโมง, และลงนามรับรองสำนวนคดีที่ยังเปิดอยู่ใหม่ด้วยกุญแจชุดใหม่ |
| **ผู้ถือรหัสผ่านพ้นสภาพ/ย้ายงาน** | หมุนเวียนกุญแจชุดใหม่ทันทีตามหลัก Segregation of Duties |

---

## 6. การแบ่งแยกหน้าที่ในการถือครองกุญแจ (Segregation of Duties)

| บทบาท (Role) | ถือครอง Passphrase / Secret Key | สิทธิ์ลงนาม (`sign_file`) | สิทธิ์ตรวจสอบ (`verify_file`) |
|---|:---:|:---:|:---:|
| **Evidence Custodian / Ops Lead** | ✅ | ✅ | ✅ |
| **Forensic Analyst (ผู้รันเคส)** | ❌ | ❌ | ✅ |
| **Independent Auditor / ศาล** | ❌ | ❌ | ✅ |
| **Management / DPO** | ❌ | ❌ | ✅ |

---

## 7. ขั้นตอนสำหรับ Auditor ในการตรวจสอบลายมือชื่อ (Auditor Verification Steps)

```bash
# 1. นำเข้า Public Key ขององค์กร
gpg --import docs/public-key-*.asc

# 2. ตรวจสอบลายมือชื่อของบัญชี Anchor Ledger
gpg --verify logs/anchor_ledger.json.asc logs/anchor_ledger.json

# 3. หรือรันผ่านสคริปต์ตรวจสอบในโหมดบังคับ GPG (--strict-gpg)
python scripts/verify_audit.py logs/audit.jsonl <CASE_ID> logs/anchor_ledger.json --strict-gpg

# 4. ตรวจสอบลายมือชื่อบน Git Tag
git tag -v "anchor/<CASE_ID>/<HEAD_HASH_12>"
```
