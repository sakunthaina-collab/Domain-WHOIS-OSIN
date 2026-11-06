# THREAT_MODEL.md — การวิเคราะห์ภัยคุกคามและขอบเขตความมั่นคงปลอดภัย (Forensic Agent STRIDE Threat Model)

- **เวอร์ชัน:** 1.0 · **ระบบ:** Trustworthy Agent v1.2 · **ปรับปรุงล่าสุด:** 2026-11-05
- **ระดับมาตรฐาน:** Court-grade (สอดคล้อง ISO/IEC 27005, ISO/IEC 27037:2012, Microsoft STRIDE Framework)
- **กลุ่มเป้าหมาย:** Forensic Auditor, Security Architect, ทนายความ/ผู้เชี่ยวชาญศาล, DPO

---

## 1. บทนำและหลักความโปร่งใส (Purpose & Radical Transparency)

ในงานนิติวิทยาศาสตร์ดิจิทัล ระบบที่น่าเชื่อถือที่สุดไม่ใช่ระบบที่อ้างว่า *"ไม่มีช่องโหว่เลย"* แต่คือระบบที่ **ระบุขอบเขตการป้องกันและข้อจำกัดอย่างตรงไปตรงมา (Explicit Threat & Boundary Disclosure)** เพื่อให้ศาล ผู้ตรวจสอบอิสระ (Auditor) และพนักงานสอบสวนประเมินน้ำหนักพยานหลักฐานได้อย่างถูกต้อง

เอกสารนี้วิเคราะห์ภัยคุกคามของระบบ **Trustworthy Agent v1.2** ด้วยกรอบมาตรฐาน **STRIDE** พร้อมแผนผังต้นไม้การโจมตี (Attack Trees) และการเชื่อมโยงกับชุดทดสอบเชิงรุก (`tests/test_adversarial.py`)

---

## 2. บัญชีทรัพย์สินสำคัญของระบบ (Critical Forensic Assets)

| รหัส | ทรัพย์สิน (Asset) | ตำแหน่งที่ตั้ง | คุณค่าทางนิติวิทยาศาสตร์และรูปคดี |
|:---:|---|---|---|
| **A-01** | **Global & Case Audit Chains** | `logs/audit.jsonl`, `artifacts/<CASE>/audit.jsonl` | พิสูจน์ลำดับเวลาและการกระทำทุกขั้นตอนของ Agent (Chain of Actions) |
| **A-02** | **External Anchor Ledger & Git Tags** | `logs/anchor_ledger.json`, `.git/refs/tags/anchor/*` | หมุดตรึงภายนอกที่ใช้ตรวจจับการลบไฟล์ทั้งก้อนหรือการตัดทอนท้ายไฟล์ |
| **A-03** | **Case Artifacts & Merkle Manifest** | `artifacts/<CASE>/*`, `artifact_manifest.json` | ไฟล์พยานหลักฐานดิจิทัลและสำนวนคดีสองภาษา (`th` / `zh-TW`) ที่ใช้ยื่นต่อศาล |
| **A-04** | **Run Manifest & Checkpoints** | `00_run_manifest.json`, `checkpoint.json` | พิสูจน์พารามิเตอร์ของโมเดล AI และความสามารถในการทำซ้ำ (Reproducibility) |
| **A-05** | **Skill Registry & Guardrails Engine** | `core/guardrails.py`, `core/registry.py`, `skills/` | ปราการบังคับใช้กฎ `passive_only=True` (OPSEC) และการแยก Stubs ออกจากระบบจริง |
| **A-06** | **Verification Scripts & Signed Hashes** | `scripts/verify_*.py`, `docs/SIGNED_HASHES.txt` | เครื่องมือของผู้ตรวจสอบอิสระในการพิสูจน์ความบริสุทธิ์ของทรัพย์สิน A-01 ถึง A-05 |

---

## 3. การวิเคราะห์ภัยคุกคามตามกรอบ STRIDE (STRIDE Threat Matrix)

| หมวดหมู่ STRIDE | ภัยคุกคามจำเพาะ (Specific Threat) | ทรัพย์สินที่กระทบ | สถานะการจัดการ | กลไกป้องกันและชุดทดสอบที่ยืนยัน (Mitigation & Verification Test) |
|---|---|---|:---:|---|
| **S — Spoofing** (การสวมรอย) | การใช้ตัวเลขอารบิกตะวันออกหรืออักขระ Unicode ที่หน้าตาคล้ายกันเพื่อหลบเลี่ยงการตรวจจับเบอร์โทรผู้ต้องสงสัย (`+66٨٩٤...`) | A-05 | ✅ **Mitigated** | `core/normalize.py` แปลง NFKC + Arabic-Indic digits ก่อนเข้า Router (`test_unicode_phone_normalization`) |
| **S — Spoofing** | การแอบอ้างสร้าง Anchor ปลอมโดยไม่ระบุตัวตนผู้ลงนาม | A-02 | 🟡 **Partial (v1.2)** | ใช้ Git Annotated Tag + Ledger; แผนขั้นถัดไป (Phase 2) เพิ่ม GPG Signed Tag (`git tag -s`) |
| **T — Tampering** (การแก้ไขข้อมูล) | การแก้ไขข้อความในบรรทัดใดบรรทัดหนึ่งของ `audit.jsonl` หลังเกิดเหตุ | A-01 | ✅ **Mitigated** | SHA-256 Hash Chain (`entry_hash = sha256(rec + prev_hash)`) ตรวจพบทันที (`test_hash_chain_detects_content_tampering`) |
| **T — Tampering** | การลบบรรทัดกลางของ `audit.jsonl` เพื่อซ่อนการเรียกสกิลบางตัว | A-01 | ✅ **Mitigated** | ตัวชี้ `prev_hash` จะไม่ตรงกับบรรทัดก่อนหน้า (`test_hash_chain_detects_entry_deletion`) |
| **T — Tampering** | การตัดบรรทัดท้ายของ `audit.jsonl` (Truncation) หรือลบไฟล์ทิ้งทั้งก้อนแล้วสร้างใหม่ | A-01, A-02 | ✅ **Mitigated** | ตรวจเทียบ `entry_count` และ `head_hash` กับ `anchor_ledger.json` คืนค่า Exit Code 2 (`test_log_truncation_detected`, `test_log_deletion_with_anchor_fails`) |
| **T — Tampering** | การแก้ไขไฟล์รายงานใน `artifacts/<CASE>/` หรือแอบวางไฟล์หลักฐานเท็จเพิ่มเข้ามา | A-03 | ✅ **Mitigated** | `verify_artifacts()` ตรวจ SHA-256 รายไฟล์, ตรวจไฟล์เกิน (`UNMANIFESTED_FILE`), และตรวจ Merkle Root (`test_artifact_manifest_merkle_root_and_tamper_detection`) |
| **T — Tampering** | Race Condition เมื่อรันหลายโปรเซสพร้อมกันทำให้ Hash Chain แตกโดยไม่ตั้งใจ | A-01 | ✅ **Mitigated** | ล็อกไฟล์ระดับ OS (`core/file_lock.py`) + อ่าน `last_hash` ใหม่จากท้ายไฟล์ใต้ Lock เสมอ (`test_concurrent_audit_writes` — 5 procs × 50 entries) |
| **R — Repudiation** (การปฏิเสธความรับผิด) | ผู้ปฏิบัติงานอ้างว่าผลลัพธ์ได้มาจากพารามิเตอร์อื่น หรือไม่ทราบว่าใช้สกิลเวอร์ชันใด | A-04 | ✅ **Mitigated** | `00_run_manifest.json` บันทึก Python version, OS, Model Pin, Seed, และ `registry_hash` (`test_run_manifest_generation_and_reproducibility`) |
| **I — Information Disclosure** (การรั่วไหลของข้อมูล / แจ้งเตือนเป้าหมาย) | สกิลเผลอยิงสัญญาณ Active Probe (เช่น โทรออก, ส่ง SMS, ยิง Reset Password) ไปยังผู้ต้องหา | A-05 | ✅ **Mitigated** | บังคับ `passive_only=True` ทั้งใน Guardrails และในโค้ดสกิล หากเป็น `False` จะโยน `ValueError` ทันที (`test_passive_only_enforced`) |
| **I — Information Disclosure** | Path Traversal ผ่านชื่อ `case_id` เช่น `../../etc/passwd` เพื่อเขียนหรืออ่านไฟล์นอกโฟลเดอร์สำนวน | A-01, A-03 | ✅ **Mitigated** | `Guardrails.__init__` ตรวจสอบ `relative_to(artifacts_root)` และปฏิเสธ `..` ทันที (`test_path_traversal_case_id_rejected`) |
| **D — Denial of Service** (การทำให้ระบบหยุดชะงัก) | สกิลค้างไม่จบ (Infinite Loop / Sleep) หรือ API ของ LLM ล่มชั่วคราว | A-04, A-05 | ✅ **Mitigated** | `Executor` บังคับ `MAX_TIMEOUT_SEC = 900`, `RateLimiter` จำกัดความถี่, และ `ResilientLLM` ทำ Exponential Backoff + `checkpoint.json` (`test_resilient_llm_recovers_after_retry`) |
| **E — Elevation of Privilege** (การยกระดับสิทธิ์) | การยัดคำสั่งอันตรายใน `skill.yaml` (เช่น `runtime.bin = "rm"`) หรือทำ SQL/Shell Injection ผ่าน Arguments | A-01, A-05 | ✅ **Mitigated** | `Executor` บล็อกคำสั่งทำลายระบบ (`rm`, `del`, `format`, ฯลฯ) และ JSON Serialization ป้องกัน Injection ใน Audit Log (`test_malicious_runtime_blocked`, `test_sql_shell_injection_safe_in_audit`) |

---

## 4. แผนผังต้นไม้การโจมตี 4 สถานการณ์หลัก (Core Forensic Attack Trees)

### 4.1 สถานการณ์ที่ 1: ความพยายามแก้ไขหรือลบประวัติการทำงาน (Audit Log Tampering & Destruction)

```text
เป้าหมายผู้โจมตี: ซ่อนร่องรอยการรันสกิลบางขั้นตอนไม่ให้ศาลเห็น
 ├── วิธีที่ 1.1: แก้ไขข้อความในบรรทัดที่ N ของ audit.jsonl
 │    └── 🛡️ ถูกจับได้โดย: verify_audit.py (entry_hash != SHA256(rec + prev_hash)) -> Exit Code 1
 ├── วิธีที่ 1.2: ลบบรรทัดที่ N ออก แล้วปล่อยบรรทัดที่ N+1 ไว้ตามเดิม
 │    └── 🛡️ ถูกจับได้โดย: verify_audit.py (บรรทัด N+1 มี prev_hash ไม่ตรงกับ N-1) -> Exit Code 1
 ├── วิธีที่ 1.3: ลบบรรทัดท้ายสุด (บรรทัดที่ K..M) ออกเพื่อให้ Hash Chain ส่วนแรกยังต่อกันติด
 │    └── 🛡️ ถูกจับได้โดย: verify_audit.py เทียบกับ anchor_ledger.json (TRUNCATION: count != expected) -> Exit Code 2
 ├── วิธีที่ 1.4: ลบไฟล์ audit.jsonl ทิ้งทั้งหมด (หวังให้ระบบเข้าใจว่ายังไม่เคยรัน)
 │    └── 🛡️ ถูกจับได้โดย: ZERO-ENTRY TRAP ใน verify_audit.py (ไฟล์ว่างแต่มี Anchor อยู่) -> Exit Code 2
 └── วิธีที่ 1.5: ลบทั้ง logs/audit.jsonl + ลบ logs/anchor_ledger.json + ลบ Git Tag
      ├── 🛡️ ปราการชั้นใน: ยังมีสำเนาแยกใน artifacts/<CASE_ID>/audit.jsonl และบันทึกในใบ CoC-01
      └── ⚠️ Residual Risk: หากทำลายทุกสำเนาในเครื่องและยังไม่ได้ Push ไป Remote WORM -> ต้องพึ่งพาสำเนานอกเครื่อง
```

### 4.2 สถานการณ์ที่ 2: การปลอมแปลงหรือยัดเยียดพยานหลักฐานในสำนวน (Artifact Forgery / Planting)

```text
เป้าหมายผู้โจมตี: แก้ไขตัวเลขในรายงานสรุป หรือแอบใส่ไฟล์หลักฐานเท็จในโฟลเดอร์คดี
 ├── วิธีที่ 2.1: เปิดไฟล์ 004_case-dossier-exporter.md แล้วแก้ชื่อผู้ต้องสงสัยหรือเบอร์โทร
 │    └── 🛡️ ถูกจับได้โดย: verify_artifacts() พบ SHA-256 ของไฟล์ไม่ตรงกับ artifact_manifest.json (TAMPERED)
 ├── วิธีที่ 2.2: วางไฟล์ 005_fake_evidence.json เพิ่มเข้าไปในโฟลเดอร์ artifacts/<CASE_ID>/
 │    └── 🛡️ ถูกจับได้โดย: verify_artifacts() ตรวจพบไฟล์ไม่อยู่ในบัญชี (UNMANIFESTED_FILE)
 └── วิธีที่ 2.3: แก้ไขไฟล์หลักฐาน แล้วรันสร้าง artifact_manifest.json ทับใหม่
      └── 🛡️ ถูกจับได้โดย:
           1) เวลา created_at ของ Manifest จะใหม่กว่าเวลา Anchor ใน anchor_ledger.json
           2) ค่า result_sha256 ที่บันทึกอยู่ใน audit.jsonl (ซึ่งตรึงด้วย Anchor แล้ว) จะไม่ตรงกับไฟล์ที่ถูกแก้
```

### 4.3 สถานการณ์ที่ 3: การโจมตีผ่านข้อมูลนำเข้าจากเป้าหมาย (Adversarial Input & Evasion)

```text
เป้าหมายผู้โจมตี (ผู้ต้องสงสัย): วางข้อมูลลวงในโปรไฟล์สาธารณะเพื่อให้ระบบพังหรือค้นไม่เจอ
 ├── วิธีที่ 3.1: ใช้เลขอารบิกตะวันออก/เปอร์เซีย หรืออักขระพิเศษคั่นเบอร์โทร (+66 ٨٩٤-٢٦٣...)
 │    └── 🛡️ ถูกจัดการโดย: core/normalize.py แปลงเป็น +66894263... มาตรฐานเดียวกันก่อนประมวลผล
 ├── วิธีที่ 3.2: ใส่ Payload `'; DROP TABLE--` หรือ `$(rm -rf /)` ในชื่อโปรไฟล์เพื่อให้ Log พังหรือรันคำสั่ง Shell
 │    └── 🛡️ ถูกจัดการโดย: บันทึกผ่าน json.dumps() ลง JSONL อย่างปลอดภัย และไม่ใช้ shell=True ใน Executor
 └── วิธีที่ 3.3: หลอกให้ระบบเรียกใช้สกิลที่ยังเขียนไม่เสร็จ (Stub) เพื่อสร้างผลลัพธ์มั่ว
      └── 🛡️ ถูกจัดการโดย: Registry แยกกักกัน 334 Stubs ไว้ใน skills/_stubs/ และไม่โหลดเข้า Router (test_stubs_never_loaded)
```

---

## 5. ความเสี่ยงคงเหลือและการเปิดเผยต่อศาล (Residual Risks & Accepted Boundaries)

ตารางด้านล่างคือข้อจำกัดทางเทคนิคที่ทีมวิศวกรเปิดเผยอย่างตรงไปตรงมา (Out-of-Band / Hardware Boundaries):

| ลำดับ | ความเสี่ยงคงเหลือ (Residual Risk) | เงื่อนไขที่จะทำให้เกิดผลกระทบ | การควบคุมชดเชยตามระเบียบปฏิบัติ (Compensating Controls ใน SOP) |
|:---:|---|---|---|
| **RR-01** | **การแทรกแซงระดับผู้ดูแลระบบสูงสุดขณะรัน (Root / Kernel Compromise at Runtime)** | ผู้โจมตีมีสิทธิ์ Administrator/Root บนเครื่องขณะกำลังรัน และแก้ไขโค้ด Python ในหน่วยความจำก่อนส่งเข้าฟังก์ชัน Hash | ตรวจสอบ SHA-256 ของไฟล์สคริปต์ทั้งหมดเทียบกับ `docs/SIGNED_HASHES.txt` ก่อนและหลังรันทุกครั้ง |
| **RR-02** | **การปลอมแปลงเวลาของนาฬิกาเครื่อง (System Clock Rollback)** | ผู้ใช้งานตั้งเวลาเครื่องคอมพิวเตอร์ย้อนหลังก่อนสั่งรัน `main.py` | เทียบเวลา `iso_ts` ในระบบกับเวลาของข้อมูลภายนอก (เช่น เวลาโพสต์ Telegram / เวลาจดโดเมน WHOIS) และเวลา Commit บน Git Server ภายนอก |
| **RR-03** | **การทำลายข้อมูลทั้งหมดในเครื่องเดียว (Total Local Storage Wipe)** | ฮาร์ดดิสก์พังเสียหายทั้งหมด หรือผู้ไม่หวังดีลบทั้งโฟลเดอร์โปรเจกต์และ `.git` ก่อนส่งออก | ปฏิบัติตาม `CHAIN_OF_CUSTODY_SOP.md` ขั้นที่ 4: สำรองชุดสำนวนและ `anchor_ledger.json` ออกไปยังพื้นที่จัดเก็บภายนอก (WORM / S3 Object Lock) ทันทีที่จบเคส |
| **RR-04** | **การเปลี่ยนแปลงน้ำหนักโมเดล LLM ต้นทาง (External LLM Non-Determinism)** | เมื่อรัน `--replay` ในอีกหลายเดือนข้างหน้า ผู้ให้บริการ API อาจอัปเดตโมเดลย่อยทำให้ข้อความสรุปต่างจากเดิมเล็กน้อย | ใช้ไฟล์ผลลัพธ์ดิบจากสกิล (`001_*.json`) ซึ่งมีความแน่นอนเชิงประจักษ์ (Deterministic) เป็นพยานหลักฐานหลัก ส่วนข้อความสรุปของ AI ใช้เป็นเพียงดัชนีช่วยอ่าน |
