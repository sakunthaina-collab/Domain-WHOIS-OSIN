# 🛡️ Trustworthy AI Cyber Defense Platform — SecOps & Threat Intelligence UI

**Developer:** NAKARIN SAKULTHAI  
**License:** MIT License ([LICENSE](./LICENSE))  
**Platform Version:** v1.7.0  
**Reference Standards:** NIST Cybersecurity Framework (CSF) 2.0 · OWASP GenAI Security Project  

---

## 📖 แก่นของแพลตฟอร์ม (Core Architecture & Identity)

โปรเจกต์นี้คือ **ระบบป้องกัน ตรวจจับ วิเคราะห์ และตอบสนองต่อ Cyber Attack ด้วย AI Agent ที่ตรวจสอบได้ (Trustworthy AI Cyber Defense Platform)** โดยวางบทบาทของ AI Agent ให้เป็น **นักวิเคราะห์และผู้ช่วยฝ่ายป้องกัน (Defensive Security Analyst)** ที่อยู่ภายใต้การกำกับดูแลของมนุษย์ (Human-in-the-Loop)

แทนที่จะเป็นเพียงเครื่องมือค้นหาโดเมนเดี่ยวๆ ระบบได้จัดวาง **`Domain & WHOIS OSINT`**, **`IP Enrichment`** และ **`Email OSINT`** ให้เป็นโมดูลย่อยภายใต้ **Threat Intelligence → External Infrastructure Analysis** เพื่อเสริมการตัดสินใจของระบบป้องกันและตอบสนองต่อภัยคุกคามแบบครบวงจร

---

## 🏛️ โครงสร้าง 6 เสาหลักของระบบ (6-Pillar Cyber Defense Lifecycle)

1. **1. Prevention (การป้องกันก่อนเกิดเหตุ):**
   - บังคับใช้จริงผ่าน [`agent/core/executor.py`](../core/executor.py) และ [`agent/core/guardrails.py`](../core/guardrails.py)
   - **Least Privilege & CLI Allowlist:** อนุญาตเฉพาะ `python`, `python3`, `py`, `node`, `uv`
   - **SSRF & Cloud Metadata Protection:** บล็อกการเข้าถึง `169.254.169.254` และ Private IP Ranges
   - **Path Confinement & Rate Limit:** จำกัดการทำงานภายในโฟลเดอร์ของ Skill (`_resolve_within`) และจำกัดอัตราเรียกใช้ที่ `60 calls / 60s`
2. **2. Detection (การตรวจจับพฤติกรรมผิดปกติ):**
   - ตรวจจับ **Agentic Attack Behavior** (เรียก API หลายบริการต่อเนื่อง, พยายามค้นหา credential, เปลี่ยนเส้นทางเมื่อถูกปฏิเสธ, เข้าถึง resource นอก pattern ปกติ)
   - ตรวจจับ Login Anomaly, Token Abuse, Suspicious API Calls และ Indirect Prompt Injection
3. **3. Triage & Investigation / Threat Intelligence (การคัดกรองและสืบสวน):**
   - [`domain-whois-osint`](../skills/investigation/domain-whois-osint/run.py) — ตรวจสอบอายุโดเมน, RDAP/WHOIS, DNS, Certificate Transparency และประเมิน Scam Risk Score (0–100) แบบอธิบายเหตุผลได้ (19/19 Tests Passed)
   - [`ip-geolocation-osint`](../skills/investigation/ip-geolocation-osint/run.py) — ตรวจสอบพิกัด ASN และความเสี่ยงของ IP ต้นทาง (15/15 Tests Passed)
   - [`email-osint`](../skills/investigation/email-osint/run.py) — ตรวจสอบความถูกต้องของอีเมล ระเบียน MX/SPF/DMARC และความเสี่ยงโดเมน (15/15 Tests Passed)
4. **4. Response & Containment (การตอบสนองและจำกัดความเสียหาย):**
   - รองรับการ **Revoke Token**, **Quarantine Case** และ **Block IOC**
   - บังคับใช้ **Human Approval Gate (`require_confirm=True`)** สำหรับทุกคำสั่งที่มีผลกระทบสูง
5. **5. Evidence & Accountability (หลักฐานและการตรวจสอบย้อนกลับ):**
   - แยกแยะ **Fact / Risk Signal / Inference / Unknown** อย่างชัดเจน
   - ผูกทุกหลักฐานด้วย **SHA-256 Digest**, **Tamper-Evident Audit JSONL (29/29 Verified)** และ **Merkle Root Verification**
6. **6. Trustworthy Agent Control (การควบคุม AI Agent):**
   - **Passive-Only OSINT by Default** (`passive_only=False` จะถูกปฏิเสธด้วย `PermissionError`)
   - **No Attack-Back / No Exploit / No Brute Force**

---

## 🖥️ โครงสร้างหน้าจอ SecOps Dashboard (`index.html`)

- **หน้าหลัก (Primary Landing Page):** `1. Security Overview`
  - แสดง KPI หลัก 6 ตัว (`Active Threats`, `Blocked Attempts`, `Pending Human Approval`, `Compromised Credentials`, `Agent Policy Violations`, `Evidence Integrity`)
  - แสดงการ์ดแจ้งเตือนภัยคุกคามลำดับความสำคัญสูง (`HIGH: Agentic behavior detected`) พร้อมปุ่ม **`[ระงับ Token]`** (เปิดหน้าต่างขอ Human Approval), **`[แยก Case]`** และ **`[ดูหลักฐาน & OSINT]`**
  - แสดงแผนภาพ **End-to-End Defensive Workflow (9 ขั้นตอน)** ที่คลิกเพื่อเจาะลึกไปยังแต่ละโมดูลได้ทันที
- **เมนูด้านซ้าย (9 โมดูลทำงานเชื่อมโยงกันครบทุกปุ่ม):**
  1. `Security Overview`
  2. `Active Threats`
  3. `Detection & Alerts`
  4. `Prevention Controls`
  5. `Response & Containment`
  6. `Threat Intelligence` *(ประกอบด้วย Domain & WHOIS OSINT, IP Enrichment, Email OSINT)*
  7. `Evidence & Audit` *(ประกอบด้วย Evidence Integrity 100%, Fact/Signal/Inference Breakdown, SHA-256 Chain of Custody, Audit Log)*
  8. `Agent Policies`
  9. `System Settings`

---

## 🚀 วิธีเปิดใช้งาน (PowerShell แบบเต็ม Path ไม่เกิดปัญหา Wrong Directory)

### วิธีที่ 1: เปิดหน้า UI ทันทีแบบไม่ต้องรัน Server (Instant Zero-Hang Mode)
สามารถคัดลอกคำสั่งนี้ไปวางใน PowerShell จากโฟลเดอร์ใดก็ได้ (รวมถึง `C:\WINDOWS\system32`):
```powershell
Start-Process "C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\agent\ui\index.html"
```

### วิธีที่ 2: รัน Live SecOps API Server (`server.py`)
หากต้องการเชื่อมต่อกับเครื่องยนต์ Python จริง (`/api/overview`, `/api/analyze`, `/api/analyze-ip`, `/api/analyze-email`):
```powershell
cd "C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill"
python "C:\Users\Administrator\.gemini\antigravity\worktrees\adventurous-pasteur\install_new_skill\agent\ui\server.py"
```
จากนั้นเปิดเบราว์เซอร์ไปที่ `http://localhost:8000`
