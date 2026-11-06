# AUDITOR_GUIDE.md — คู่มือการตรวจสอบอิสระระดับชั้นศาล (Court-Grade Independent Verification Guide)

- **เวอร์ชัน:** 1.0 · **ระบบ:** Trustworthy Agent v1.2 · **ปรับปรุงล่าสุด:** 2026-11-05
- **ระดับมาตรฐาน:** Court-grade (สอดคล้อง ISO/IEC 27037:2012, ISO/IEC 27041:2015, พ.ร.บ. ป้องกันและปราบปรามการค้ามนุษย์ พ.ศ. 2551, พ.ร.บ. ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์, 臺灣人口販運防制法 & 刑事訴訟法)
- **กลุ่มเป้าหมาย:** Forensic Auditor, ทนายความฝ่ายจำเลย/โจทก์, ผู้เชี่ยวชาญศาล (Expert Witness), พนักงานสอบสวน (DSI / ตำรวจ / 臺灣移民署 NIA), DPO, Internal Audit

---

## 0. บทนำ: เอกสารนี้สำหรับใคร

เอกสารนี้จัดทำขึ้นเพื่อให้ **บุคคลภายนอกที่ไม่จำเป็นต้องเชื่อถือทีมผู้พัฒนา** สามารถตรวจสอบความสมบูรณ์ ความถูกต้องตามลำดับเวลา และความน่าเชื่อถือของระบบ **Trustworthy Agent v1.2** ได้ด้วยตนเองภายใน 30 นาที

> **หลักการสำคัญ (Zero-Trust Verification):** Auditor ไม่จำเป็นต้องเชื่อคำกล่าวอ้างของทีมผู้พัฒนา — Auditor สามารถ **พิสูจน์ด้วยคณิตศาสตร์และรหัสวิทยา (Cryptographic Proof)** ได้เองว่าข้อมูลที่ระบบสร้างขึ้นไม่ถูกแก้ไข ลบ หรือสวมรอย นับตั้งแต่วินาทีที่รันจนถึงเวลาที่ตรวจพิสูจน์

หากท่านปฏิบัติตามขั้นตอนใน **§3** ครบทุกข้อ และผลลัพธ์ตรงกับที่ระบุไว้ใน **§7** แสดงว่าระบบและพยานหลักฐานชุดนี้ **ผ่านการรับรองความสมบูรณ์ในระดับที่ใช้ยื่นเป็นพยานหลักฐานดิจิทัลในชั้นศาลได้** (ภายใต้ขอบเขตที่ระบุใน §4)

---

## 1. Scope & Authority (ขอบเขตและอำนาจการตรวจสอบ)

### 1.1 ระบบนี้ทำอะไร
**Trustworthy Agent v1.2** เป็นระบบ AI Agent สำหรับงานสืบสวนดิจิทัล (Passive-First Digital Forensics & OSINT) ที่:
1. เรียกใช้ **สกิลที่ผ่านการรับรอง (Runnable Tools)** ตามคำสั่งของผู้ใช้ ภายใต้การควบคุมของ Guardrails (บังคับ `passive_only=True` และกั้น High-Risk Actions)
2. บันทึกทุกการกระทำลง **Tamper-Evident Audit Log** แบบต่อเนื่องด้วย SHA-256 Hash Chain ทั้งระดับระบบ (`logs/audit.jsonl`) และระดับสำนวนคดี (`artifacts/<case_id>/audit.jsonl`)
3. สร้าง **Artifact (พยานหลักฐานดิจิทัล)** พร้อมคำนวณ **Merkle-Root Manifest** (`artifact_manifest.json`)
4. **Anchor (ตรึงค่า Hash สุดท้าย)** ของ Audit Chain ไว้ภายนอกระบบ (Git Annotated/Signed Tag, S3 Object Lock WORM, หรือ External Webhook)
5. รองรับ **การรันซ้ำเพื่อพิสูจน์ผล (Reproducibility)** ผ่าน `00_run_manifest.json`

### 1.2 สิ่งที่ระบบนี้ *ไม่* รับประกัน (Out of Scope)

| สิ่งที่ไม่รับประกัน | เหตุผลทางเทคนิคและนิติวิทยาศาสตร์ |
|---|---|
| **ความถูกต้องเชิงข้อเท็จจริงของข้อมูลต้นทาง** | ระบบรับประกันว่า *"ผลลัพธ์ที่ได้รับมาไม่ถูกแก้ไขหลังการเก็บ"* (Integrity) แต่ไม่ได้แปลว่าข้อมูลจากแหล่งภายนอก (เช่น WHOIS/Carrier) เป็นความจริงเสมอ — พนักงานสอบสวนต้องวิเคราะห์ประกอบพยานหลักฐานอื่น |
| **การป้องกันผู้โจมตีระดับ Root/Kernel ณ ขณะรัน** | ผู้ที่ควบคุม OS ด้วยสิทธิ์ Administrator/Root ก่อนที่ข้อมูลจะส่งเข้าฟังก์ชันคำนวณ SHA-256 สามารถดักจับหรือปลอมแปลงข้อมูลในหน่วยความจำได้ (ดู §4.3) |
| **ความคงที่ของโมเดล AI ภายนอก (Upstream Drift)** | ผู้ให้บริการ LLM (เช่น DeepSeek / Gemini) อาจปรับปรุงน้ำหนักโมเดลเบื้องหลัง — Run Manifest บันทึกชื่อรุ่นและพารามิเตอร์ ณ เวลารัน แต่ไม่ควบคุมเซิร์ฟเวอร์ผู้ให้บริการ |
| **การป้องกันการทำลายฮาร์ดแวร์และสำเนาทั้งหมด** | หากผู้โจมตีลบทั้งไฟล์ Audit, ลบ Anchor Ledger, และทำลาย Git Repository ทั้งหมด — ระบบจะฟ้องว่าหลักฐานถูกทำลาย แต่ไม่สามารถกู้คืนข้อมูลที่ไม่ได้สำรองไว้ภายนอกได้ |
| **ความชอบด้วยกฎหมายของการนำไปใช้** | ระบบบันทึกอย่างซื่อสัตย์ว่า *"ใครสั่งรันอะไร เมื่อใด"* แต่การมีอำนาจตามกฎหมายในการสืบสวนเป็นความรับผิดชอบของผู้ใช้งานตามวิธีพิจารณาความอาญา |

### 1.3 สิทธิและข้อห้ามของ Auditor
- ✅ **มีสิทธิ์:** เข้าถึงโฟลเดอร์ `artifacts/`, `logs/`, `skills/`, `patches*/`, `docs/` ในโหมดอ่านอย่างเดียว (Read-Only)
- ✅ **มีสิทธิ์:** รันคำสั่ง Verification ทั้งหมดในเอกสารนี้
- ✅ **มีสิทธิ์:** ขอตรวจสอบ Signed Hashes Sheet (`docs/SIGNED_HASHES.txt`) และตรวจสอบ Git History / Tags
- ❌ **ห้าม:** รันสกิลที่มี `risk: high` (เช่น `counter-fraud-disruption`) โดยไม่มีหนังสืออนุมัติเป็นลายลักษณ์อักษร
- ❌ **ห้าม:** แก้ไข เขียนทับ หรือลบไฟล์ใดๆ ใน `artifacts/<case_id>/` หรือ `logs/` โดยเด็ดขาด (ต้องทำสำเนาแยกก่อนเสมอหากต้องการทดสอบการโจมตี)

---

## 2. Trust Model Overview (สถาปัตยกรรมความน่าเชื่อถือ 5 เสาหลัก)

ระบบสร้างความน่าเชื่อถือจาก **5 เสาหลัก (5 Pillars of Forensic Trust)** ที่ Auditor สามารถตรวจสอบแยกกันได้อย่างอิสระ:

```text
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   Pillar 1 ── Audit Chain        (เกิดอะไรขึ้น, ลำดับใด, เมื่อไหร่)     │
│   Pillar 2 ── External Anchor    (ป้องกันการลบ/ตัดทอน Audit Log)      │
│   Pillar 3 ── Artifact Manifest  (รับรองไฟล์ผลลัพธ์ด้วย Merkle Root)  │
│   Pillar 4 ── Run Manifest       (พารามิเตอร์ครบถ้วน รันซ้ำตรวจสอบได้) │
│   Pillar 5 ── Stub Isolation     (แยกสกิลพร้อมใช้ 100% ไม่ปนของจำลอง) │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.1 หลักการพื้นฐาน
| หลักการ | คำอธิบาย |
|---|---|
| **Append-Only & Race-Safe** | Audit Log เขียนต่อท้ายได้อย่างเดียว ภายใต้ OS-Level File Lock (`msvcrt.locking` / `fcntl.flock`) ป้องกัน Race Condition เมื่อรันหลายเคสขนานกัน |
| **Tamper-Evident** | ทุกบรรทัดผูก `prev_hash` เข้ากับ `entry_hash = SHA256(payload + prev_hash)` หากแก้ไขแม้แต่ตัวอักษรเดียว Hash Chain จะขาดทันที |
| **Externally Anchored** | ค่า `head_hash` และจำนวนบรรทัด (`entry_count`) ถูกตรึงไว้ใน `anchor_ledger.json` และ Git Tag ป้องกันการลบไฟล์ทิ้งทั้งก้อน (Zero-Entry Trap) หรือการตัดท้ายไฟล์ (Truncation Attack) |
| **Independently Verifiable** | Auditor สามารถคำนวณ SHA-256 ซ้ำด้วยสคริปต์มาตรฐานหรือคำสั่ง OS โดยไม่ต้องพึ่งพาซอฟต์แวร์เฉพาะทาง |
| **Reproducible** | `00_run_manifest.json` บันทึก Seed, Temperature, Model Pin, และ Registry Hash เพื่อรองรับการรันซ้ำ (`--replay`) |

### 2.2 แผนผังการไหลของความน่าเชื่อถือ (Chain of Trust)

```text
Skill Execution
      │
      ▼
Guardrails.audit() ──► [OS File Lock] ──► อ่าน last_hash จากท้ายไฟล์จริง
      │                                              │
      │                                              ▼
      │                                   คำนวณ entry_hash (SHA-256)
      │                                              │
      │                                              ▼
      │                                      append + os.fsync()
      ▼                                              ▼
Global Chain: logs/audit.jsonl          Case Chain: artifacts/<case>/audit.jsonl
      │                                              │
      └──────────────────────┬───────────────────────┘
                             ▼
                      Anchor.anchor()
                             │
                             ▼
                logs/anchor_ledger.json
                             │
                             ▼
            Git Tag: anchor/<case>/<head_hash[:12]>
```

---

## 3. Independent Verification Procedure (ขั้นตอนการตรวจสอบอิสระ)

### 3.1 Prerequisites & Tool Integrity Check (ตรวจสอบเครื่องมือก่อนเริ่ม)

**สิ่งที่ต้องมี:** Python 3.10+ (`python --version`) และ Git 2.30+ (`git --version`)

**ขั้นที่ 0 (บังคับ):** ตรวจสอบค่า SHA-256 ของสคริปต์ตรวจสอบก่อนรัน เพื่อยืนยันว่าสคริปต์ไม่ถูกดัดแปลงให้รายงานผลเท็จ:

```powershell
# Windows (PowerShell)
Get-FileHash scripts\verify_all.py, scripts\verify_audit.py, core\guardrails.py, core\anchor.py, core\artifact_manifest.py, core\run_manifest.py, core\file_lock.py -Algorithm SHA256
```

```bash
# Linux / macOS
sha256sum scripts/verify_all.py scripts/verify_audit.py core/guardrails.py core/anchor.py core/artifact_manifest.py core/run_manifest.py core/file_lock.py
```

เทียบค่าที่ได้กับตารางอ้างอิงใน `docs/SIGNED_HASHES.txt`:
- `scripts/verify_all.py`: `4DCF6DC33EC90BDD8E89D1392221238C7C4C1164A9E8DEB88F578277A1B53405`
- `scripts/verify_audit.py`: `F4CE343F8EDEE48BEF516C6AE2587960E0228AF1266B09A3C0FB43F300229225`
- `core/guardrails.py`: `DD6216F3358E1359F0DDD2F3AAF707B296417F7E2F9F74D628B22B17BBABDC05`
- `core/anchor.py`: `16507693A8C15A2E15887173E39FDD820BDEBAAE51D0D6A0DFADA2EE4B35FDAF`
- `core/artifact_manifest.py`: `5015BD69EEF747D1D4ED668F2B4BDF5D62B153120212BDE0381792A2BF963695`
- `core/run_manifest.py`: `1F3778FE6B354B7A986E1A4EE03781F28A05DDFAA0440F9FC6A033310272B8C7`
- `core/file_lock.py`: `F3F3D29EF433E2D1868428E594A2A93470134E048558924DC9EAD836AE46E54E`

> ⚠️ **คำเตือน:** หากค่า Hash ของสคริปต์ตัวใดตัวหนึ่งไม่ตรงกับ `docs/SIGNED_HASHES.txt` **ให้หยุดการตรวจสอบทันที** และแจ้งเหตุตาม `docs/INCIDENT_RESPONSE.md` (§6.2)

---

### 3.2 Pillar 1 — Audit Chain Integrity (ตรวจสอบความสมบูรณ์ของ Hash Chain)

**วัตถุประสงค์:** ยืนยันว่า Audit Log ไม่ถูกแก้ไข ลบ หรือแทรกบรรทัด และตรงกับ External Anchor

**คำสั่ง (รันจากโฟลเดอร์ `agent/`):**
```bash
# 1. ตรวจสอบ Global Chain เทียบกับ Anchor ของเคส
python scripts/verify_audit.py logs/audit.jsonl <CASE_ID> logs/anchor_ledger.json

# 2. ตรวจสอบ Case-Specific Chain ประจำสำนวนคดี
python scripts/verify_audit.py artifacts/<CASE_ID>/audit.jsonl
```

**ตารางแปลผล Exit Code และข้อความ Output:**

| Exit Code | Output | ความหมายทางนิติวิทยาศาสตร์ |
|:---:|---|---|
| `0` | `✅ OK — N entries verified, head matches anchor (...)` | **ผ่านสมบูรณ์** — Hash Chain ไม่ขาด และตรงกับ Anchor ภายนอก |
| `1` | `❌ CHAIN BROKEN: line N: prev_hash mismatch` | **ล้มเหลว (Tampered)** — มีการลบบรรทัด หรือแทรกบรรทัดที่บรรทัด N |
| `1` | `❌ CHAIN BROKEN: line N: entry_hash mismatch` | **ล้มเหลว (Tampered)** — เนื้อหาในบรรทัดที่ N ถูกแก้ไขหลังบันทึก |
| `2` | `🚨 ZERO-ENTRY TRAP: audit log empty/missing...` | **ล้มเหลวร้ายแรง (Destruction)** — ไฟล์ Audit ถูกลบหรือทำให้ว่างเปล่า แต่มีหลักฐาน Anchor ยืนยันว่าเคยมีข้อมูล |
| `2` | `🚨 TRUNCATION: chain has X entries, anchor expected Y` | **ล้มเหลวร้ายแรง (Truncation)** — บรรทัดท้ายของ Audit Log ถูกตัดทอนออกไป |
| `2` | `🚨 HEAD MISMATCH: chain head=..., anchor=...` | **ล้มเหลวร้ายแรง (Fork/Rewrite)** — มีการเขียน Chain ใหม่ทับหลังเวลา Anchor |
| `3` | `usage: verify_audit.py ...` | พารามิเตอร์คำสั่งไม่ครบ (ไม่ใช่ความผิดพลาดของหลักฐาน) |

---

### 3.3 Pillar 2 — External Anchor Verification (ตรวจสอบหมุดตรึงภายนอก)

**วัตถุประสงค์:** ยืนยันว่าค่า `head_hash` ถูกตรึงไว้ในระบบควบคุมเวอร์ชัน (Git Tag / Ledger) ซึ่งไม่สามารถแก้ไขย้อนหลังได้โดยไม่ทิ้งร่องรอย

**คำสั่ง:**
```bash
# 1. ตรวจสอบประวัติการตรึงทั้งหมดใน Anchor Ledger
python -m json.tool logs/anchor_ledger.json

# 2. ตรวจสอบ Git Tag ของเคส
git tag -l "anchor/<CASE_ID>/*"

# 3. ดูรายละเอียด Annotation และเวลาที่สร้าง Tag
git show "anchor/<CASE_ID>/<HEAD_HASH_12_CHARS>"

# 4. (กรณีเปิดใช้ GPG Signing) ตรวจสอบลายมือชื่อดิจิทัล
git tag -v "anchor/<CASE_ID>/<HEAD_HASH_12_CHARS>"
```

**จุดตรวจรับรอง:**
- พบรายการของ `<CASE_ID>` ใน `logs/anchor_ledger.json`
- ค่า `entry_count` และ `head_hash` ใน Ledger ตรงกับผลลัพธ์จาก Pillar 1
- เวลา `anchored_iso` เกิดขึ้นหลังหรือพร้อมกับเวลา `iso_ts` ของ Audit Entry บรรทัดสุดท้าย
- Git Tag `anchor/<CASE_ID>/<head_hash[:12]>` มีอยู่จริงในประวัติ Git

---

### 3.4 Pillar 3 — Artifact Manifest & Merkle Root (ตรวจสอบไฟล์พยานหลักฐาน)

**วัตถุประสงค์:** ยืนยันว่าไฟล์ผลลัพธ์ทุกไฟล์ในสำนวนคดี (เช่น รายงาน 2 ภาษา, ผลวิเคราะห์ OSINT, ไฟล์ JSON) ไม่ถูกแก้ไข ลบ หรือแอบวางไฟล์แปลกปลอมเพิ่มเข้ามา

**คำสั่ง:**
```bash
python main.py --verify-artifacts <CASE_ID>
```
หรือตรวจสอบเนื้อหา Manifest โดยตรง:
```bash
python -m json.tool artifacts/<CASE_ID>/artifact_manifest.json
```

**ผลลัพธ์ที่คาดหวัง:**
- `[PASS] Artifact integrity verified for case '<CASE_ID>' (Merkle root matched, 0 tampering).` (Exit code `0`)
- หากพบการแก้ไข จะรายงาน `TAMPERED: <filename>`, หากไฟล์หายรายงาน `MISSING: <filename>`, หากมีไฟล์แปลกปลอมรายงาน `UNMANIFESTED_FILE: <filename>`, พร้อม `MERKLE_ROOT_MISMATCH`

---

### 3.5 Pillar 4 — Run Manifest & Reproducibility (ตรวจสอบความสามารถในการทำซ้ำ)

**วัตถุประสงค์:** ตรวจสอบสภาพแวดล้อม พารามิเตอร์ของโมเดล AI และรายการสกิลที่ถูกคัดเลือกในขณะรันคดี

**คำสั่ง:**
```bash
# 1. ตรวจสอบข้อมูลใน 00_run_manifest.json
python -m json.tool artifacts/<CASE_ID>/00_run_manifest.json

# 2. ทดสอบเปรียบเทียบสภาพแวดล้อมและตรวจสอบ Hash ซ้ำ
python main.py --replay <CASE_ID> --compare-hash
```

**เกณฑ์การตรวจ:**
- `llm_params.temperature` ≤ `0.3` (ค่ามาตรฐานสำหรับงานสืบสวนคือ `0.2`)
- `llm_params.seed` มีการระบุชัดเจน (ค่ามาตรฐานคือ `42`)
- `registry.runnable_skills` = `123` และมีค่า `registry_hash` (Hex 16 หลัก)

---

### 3.6 Pillar 5 — Stub Isolation (ตรวจสอบการคัดแยกสกิลจำลอง)

**วัตถุประสงค์:** ยืนยันว่า Production Registry โหลดเฉพาะสกิลที่ทำงานได้จริง (`status: runnable`) จำนวน 123 สกิล และไม่นำสกิลที่เป็นเพียงเอกสาร (`_stubs/` จำนวน 334 รายการ) มาใช้ในคดี

**คำสั่ง:**
```bash
# 1. รันสคริปต์ตรวจสอบบัญชีสกิล
python scripts/audit_skill_inventory.py

# 2. รันชุดทดสอบยืนยันการแยก Stub
pytest tests/test_stubs_isolation.py -v
```

**ผลลัพธ์ที่คาดหวัง:**
- `runnable: 123`, `stubs: 334 (isolated in _stubs/)`, `broken: 0`, `Duplicates found: 0`
- `test_stubs_never_loaded PASSED` และ `test_registry_filters_by_status PASSED`

---

### 3.7 Master Verification (คำสั่งเดียวตรวจครบทั้ง 5 เสาหลัก + ชุดทดสอบ 40 ข้อ)

```bash
python scripts/verify_all.py --base-dir .
```
- **ผ่านสมบูรณ์:** แสดงข้อความ `🎉 ALL VERIFICATION CHECKS PASSED: SYSTEM FULLY TRUSTWORTHY` และคืนค่า Exit Code `0`

---

## 4. What We Prove vs What We Don't (สรุปสิ่งที่พิสูจน์ได้และข้อจำกัด)

### 4.1 สิ่งที่ระบบพิสูจน์ได้ทางคณิตศาสตร์ ✅
1. **ความครบถ้วนและไม่ถูกแก้ไขของประวัติการทำงาน (Audit Integrity):** พิสูจน์ด้วย SHA-256 Hash Chain + External Git/Ledger Anchor
2. **ความบริสุทธิ์ของไฟล์พยานหลักฐาน (Artifact Integrity):** พิสูจน์ด้วย SHA-256 รายไฟล์และราก Merkle Tree (`merkle_root`)
3. **การปฏิบัติตามกฎ OPSEC & Passive Reconnaissance:** พิสูจน์ด้วย Guardrails Gate และ Unit Tests เชิงรุก (`test_passive_only_enforced`) ว่าไม่มีการยิง Active Probe ไปยังเป้าหมาย
4. **การป้องกันอักขระอำพรางและช่องโหว่พื้นฐาน:** พิสูจน์ด้วย `test_adversarial.py` (ป้องกัน SQL/Shell Injection ใน Log, ป้องกัน Path Traversal `../`, ป้องกันการรันคำสั่งทำลายระบบ `rm`, และแปลงเลขอารบิกตะวันออก `+66٨...` เป็นเลขอารบิกสากล)

### 4.2 ความเสี่ยงคงเหลือ (Residual Risks) ที่ Auditor ต้องทราบ ⚠️
| ความเสี่ยงคงเหลือ | ระดับ | มาตรการบรรเทาในปัจจุบัน | ข้อเสนอแนะเพิ่มเติมสำหรับองค์กร |
|---|:---:|---|---|
| ผู้ดูแลระบบระดับ Root แก้ไขโค้ดก่อนรัน | 🔴 สูง | ตรวจสอบ SHA-256 ของสคริปต์เทียบกับ `SIGNED_HASHES.txt` | รันบนเครื่อง Air-gapped หรือใช้ HSM/TPM เก็บกุญแจลงนาม |
| การลบทั้งโฟลเดอร์เครื่องและ Git Local | 🟡 กลาง | Zero-Entry Trap (หาก Ledger ยังอยู่) | Push Git Tag ไปยัง Remote Repository แบบ Protected หรือใช้ S3 Object Lock (WORM) |
| โมเดล LLM ต้นทางเปลี่ยนพฤติกรรม | 🟡 กลาง | บันทึกผลลัพธ์จริงลง Artifact พร้อม SHA-256 ทันทีที่รัน | เก็บ Raw Response ในสำนวนคดีเป็นหลักฐานหลัก |

### 4.3 Residual Risk & Architectural Boundaries (FIND-04)

**Tail deletion is undetectable in pure-chain mode.**

A hash chain is append-only by construction: each entry binds to its
predecessor. But a *prefix* of a valid chain is itself a valid chain.
Therefore, if an attacker deletes the last N entries of `audit.jsonl`
(without leaving any trace of them), `verify_audit_chain()` — in
isolation — returns `True`. This is mathematical, not a bug.

**This is why v1.2 introduced external anchoring.** `verify_audit.py`
compares:

  1. entry count (anchor vs actual) → catches tail deletion
  2. head hash (anchor vs actual)   → catches any tampering after anchor
  3. zero-entry trap                → catches full-file deletion

**The property-based proof** (`test_find04_anchored_detects_tail_deletion`)
runs randomized trials (N ∈ [2,10], k ∈ [1,N-1]) and asserts every
tail-deletion is caught with exit code 2. Auditors can run this test as
evidence that the anchored chain is complete, not merely plausible.

**Remaining residual risks** (accepted, documented):

| Risk | Mitigation status | Note |
|---|---|---|
| DNS rebinding for `http` skills | Not mitigated | Requires egress ACL at org network (`allow_redirects=False` enforced) |
| Root compromise before anchor | Not mitigated | Requires HSM/TPM (out of scope) |
| Anchor ledger deletion | Partial | Git tag survives in remote |
| `python -c` bypass via interpreter | Mitigated | First arg must resolve in `skill.dir` |
| `uv --from <pkg>` supply chain | Mitigated | `uv run <local-script>` only |
| `npx` supply chain | Mitigated | `npx` on denylist |

---

## 5. การเทียบเคียงมาตรฐานสากลและข้อกฎหมาย (Legal & Standards Mapping)

| เสาหลัก / กลไกของระบบ | ISO/IEC 27037:2012 | กฎหมายไทย (พ.ร.บ. ค้ามนุษย์ 2551 / พ.ร.บ. คอมพิวเตอร์ฯ) | กฎหมายไต้หวัน (人口販運防制法 / 刑事訴訟法) |
|---|---|---|---|
| **Pillar 1: Dual Hash-Chain Audit Log** | §7.1.2 & §7.2.2 (Audit trail & Log integrity) | มาตรา 26 พ.ร.บ.คอมพิวเตอร์ฯ / ความน่าเชื่อถือของข้อมูลอิเล็กทรอนิกส์ | 刑事訴訟法 第 159-4 條 (บันทึกที่จัดทำขึ้นตามปกติในงานด้วยระบบอัตโนมัติที่น่าเชื่อถือ) |
| **Pillar 2: External Anchor & Zero-Entry Trap** | §7.2.3 (Preservation against alteration/deletion) | ป้องกันการทำลายพยานหลักฐานตาม ป.วิ.อาญา มาตรา 226 | ยืนยันความไม่ถูกตัดทอนของพยานหลักฐานดิจิทัล (驗真與同一性) |
| **Pillar 3: Merkle Root Artifact Manifest** | §7.2.1 & §7.2.4 (Cryptographic hashing & separate storage) | รับรองความถูกต้องของต้นฉบับข้อมูลอิเล็กทรอนิกส์ (พ.ร.บ.ธุรกรรมทางอิเล็กทรอนิกส์) | พิสูจน์ความเหมือนกันของสำเนาพยานหลักฐานดิจิทัล (數位證據原件與複本同一性) |
| **Pillar 4: Run Manifest (`00_run_manifest.json`)** | §7.3.1 (Documentation of tools & repeatable processes) | แสดงวิธีการได้มาซึ่งพยานหลักฐานโดยชอบและตรวจสอบซ้ำได้ | มาตรฐานการพิสูจน์วิธีการทางนิติวิทยาศาสตร์ (科學鑑定方法之可重複性) |
| **Bilingual Output (`th` / `zh-TW`)** | การส่งมอบหลักฐานข้ามพรมแดน (Cross-border handover) | คงอักษรจีนดั้งเดิม (เช่น 新北市中和區自立路147–149號) คู่คำแปลไทย ป้องกันความคลาดเคลื่อนในการขอหมายค้น | รองรับการออกหมายค้นและประสานงานกับ 臺灣移民署 (NIA) และอัยการไต้หวันได้ทันที |

---

## 6. Red Flags & Summary Action Matrix

หาก Auditor พบเหตุการณ์ต่อไปนี้ระหว่างตรวจ **ให้หยุดกระบวนการทันที** และดำเนินการตาม `docs/INCIDENT_RESPONSE.md`:
1. **Hash ของไฟล์สคริปต์ไม่ตรงกับ `docs/SIGNED_HASHES.txt`** → สงสัยว่าเครื่องมือตรวจถูกวางยา (Tool Compromise)
2. **`verify_audit.py` คืนค่า Exit Code `1` หรือ `2`** → พยานหลักฐานถูกแก้ไข ลบ หรือตัดทอน (Evidence Tampering / Destruction)
3. **`main.py --verify-artifacts` รายงาน `TAMPERED` หรือ `MERKLE_ROOT_MISMATCH`** → ไฟล์รายงานถูกแก้ไขหลังจบเคส

---

## 7. แบบฟอร์มรายงานผลการตรวจสอบอิสระ (Sample Independent Audit Report Template)

Auditor สามารถคัดลอกแบบฟอร์มด้านล่างนี้เพื่อจัดทำรายงานรับรองผลส่งศาลหรือผู้บริหาร:

```markdown
# รายงานการตรวจสอบความสมบูรณ์ของพยานหลักฐานดิจิทัล (Independent Forensic Audit Report)

## 1. ข้อมูลทั่วไป (Metadata)
- **หมายเลขสำนวนคดี (Case ID):** <CASE_ID>
- **ผู้ตรวจสอบ (Auditor):** <ชื่อ-นามสกุล, ตำแหน่ง, หน่วยงาน>
- **วันที่และเวลาที่ตรวจสอบ:** <YYYY-MM-DD HH:MM UTC+7>
- **เวอร์ชันของระบบ:** Trustworthy Agent v1.2
- **ความเป็นอิสระของผู้ตรวจสอบ:** [ ] บุคคลภายนอกอิสระ  [ ] ผู้ตรวจสอบภายใน (Internal Audit)  [ ] ผู้เชี่ยวชาญศาล

## 2. การตรวจสอบความสมบูรณ์ของเครื่องมือ (Tool Integrity Check)
- `scripts/verify_all.py` SHA-256:    [ ] ตรงกับ SIGNED_HASHES.txt  [ ] ไม่ตรง
- `scripts/verify_audit.py` SHA-256:  [ ] ตรงกับ SIGNED_HASHES.txt  [ ] ไม่ตรง
- `core/guardrails.py` SHA-256:       [ ] ตรงกับ SIGNED_HASHES.txt  [ ] ไม่ตรง

## 3. ผลการตรวจสอบ 5 เสาหลัก (5-Pillar Verification Results)

### Pillar 1 — Audit Chain Integrity
- จำนวนรายการใน Global Chain: <N> รายการ | Case Chain: <M> รายการ
- Head Hash: `<HEX_64>`
- Exit Code จาก `verify_audit.py`: `<0 / 1 / 2>`
- ผลการตรวจ: [ ] ✅ PASS  [ ] ❌ FAIL

### Pillar 2 — External Anchor Verification
- พบข้อมูลใน `anchor_ledger.json`: [ ] พบ  [ ] ไม่พบ
- รูปแบบ Anchor (Adapter): `<git / s3 / http / file>`
- เวลาที่ตรึง (Anchored ISO): `<TIMESTAMP>`
- Git Tag `anchor/<CASE_ID>/<HASH>` มีอยู่จริง: [ ] ใช่  [ ] ไม่ใช่
- ผลการตรวจ: [ ] ✅ PASS  [ ] ❌ FAIL

### Pillar 3 — Artifact Manifest (Merkle Root)
- จำนวนไฟล์ในสำนวน (`file_count`): <N> ไฟล์
- ค่า Merkle Root: `<HEX_64>`
- ไฟล์สูญหาย / ถูกแก้ไข / แปลกปลอม: `<0 ไฟล์ / ระบุชื่อไฟล์>`
- ผลการตรวจ: [ ] ✅ PASS  [ ] ❌ FAIL

### Pillar 4 — Run Manifest & Determinism
- โมเดลที่ใช้: `<model>` | Seed: `<42>` | Temperature: `<0.2>`
- Registry Hash: `<HEX_16>`
- ผลการตรวจ: [ ] ✅ PASS  [ ] ⚠️ PARTIAL  [ ] ❌ FAIL

### Pillar 5 — Stub Isolation & Adversarial Suite
- สกิลพร้อมใช้งาน (Runnable): `123` | สกิลจำลองที่แยกกักกัน (Stubs): `334` | สกิลรั่วไหล: `0`
- ผลการรัน Pytest Suite ทั้งหมด: `<40 / 40 passed>`
- ผลการตรวจ: [ ] ✅ PASS  [ ] ❌ FAIL

## 4. ความเห็นสรุปของผู้ตรวจสอบ (Auditor Verdict)
- [ ] **✅ รับรองความสมบูรณ์ (TRUSTED / ADMISSIBLE):** พยานหลักฐานดิจิทัลชุดนี้ไม่ถูกแก้ไขหรือตัดทอน สามารถใช้เป็นพยานหลักฐานในชั้นศาลได้
- [ ] **⚠️ รับรองแบบมีเงื่อนไข (TRUSTED WITH CAVEATS):** <ระบุข้อจำกัด>
- [ ] **❌ ไม่รับรอง (NOT TRUSTED / REJECTED):** <ระบุสาเหตุที่ตรวจพบความผิดปกติ>

ลงชื่อ ____________________________________ ผู้ตรวจสอบ (Auditor)
      (                                    )
วันที่ ________ / ________ / ____________

ลงชื่อ ____________________________________ พยาน / ผู้ควบคุมหลักฐาน (Custodian)
      (                                    )
วันที่ ________ / ________ / ____________
```

---

## 8. ภาคผนวก: สรุปคำสั่งด่วน (Quick Command Reference)

```bash
# ตรวจครบทุก Pillar ในคำสั่งเดียว (รันจากโฟลเดอร์ agent/)
python scripts/verify_all.py --base-dir .

# ตรวจเฉพาะ Audit Chain + Anchor ของเคส
python scripts/verify_audit.py logs/audit.jsonl <CASE_ID> logs/anchor_ledger.json
python scripts/verify_audit.py artifacts/<CASE_ID>/audit.jsonl

# ตรวจเฉพาะ Merkle Root ของไฟล์ในสำนวนคดี
python main.py --verify-artifacts <CASE_ID>

# รันชุดทดสอบความปลอดภัยและ Adversarial Suite ทั้ง 40 ข้อ
pytest tests/ -v
```
