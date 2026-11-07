# Trustworthy Agent — Security Overview Dashboard

ต้นแบบหน้า Security Overview Dashboard แบบ HTML/Tailwind สำหรับระบบป้องกันไซเบอร์ โดยแบ่งภาพรวมเป็น 4 ชั้น: Prevention, Detection & Threat Intelligence, Response & Containment และ Evidence & Governance

## วิธีเปิดใช้งาน

เปิด `index.html` ด้วย browser ได้โดยตรง หรือรัน static server:

```bash
python3 -m http.server 8000 --directory /home/ubuntu/security-overview-dashboard
```

จากนั้นเปิด `http://localhost:8000`

## Backend defensive API

โปรเจกต์มี backend FastAPI อยู่ในโฟลเดอร์ `backend/` สำหรับรับ telemetry, สร้าง incident, คำนวณ risk signal แบบอธิบายได้, สร้าง evidence SHA-256, ตรวจสอบ audit hash chain และบังคับ Human Approval ก่อน containment โดยค่าเริ่มต้นยังไม่เชื่อมต่อระบบภายนอกและทุก containment เป็น demo record เท่านั้น

ติดตั้ง dependency และรัน API:

```bash
python3 -m pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8001
```

เปิดเอกสาร API ได้ที่ `http://127.0.0.1:8001/docs`

ตัวอย่างส่ง telemetry:

```bash
curl -X POST http://127.0.0.1:8001/api/v1/telemetry/events \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: soc-analyst' \
  -d '{
    "event_type": "telemetry_deviation",
    "source": "ics-telemetry",
    "asset_id": "cold-storage-01",
    "severity": "high",
    "attributes": {
      "temperature_before": -18.5,
      "temperature_after": -15.2,
      "authoritative_source": true
    }
  }'
```

จากผลลัพธ์ ให้นำ `incident_id` ไปตรวจสอบ `/api/v1/incidents/{incident_id}/integrity` หรือขอ containment ผ่าน `/api/v1/incidents/{incident_id}/containment/request` จากนั้นจึงอนุมัติผ่าน `/api/v1/incidents/{incident_id}/containment/approve` การอนุมัติในรุ่นนี้บันทึก audit แบบ demo และจะไม่ revoke token, freeze transaction หรือเปลี่ยนแปลงระบบจริง

รันชุดทดสอบ:

```bash
PYTHONPATH=backend python3 -m unittest discover -s backend -p 'test_*.py' -v
```

### Real-time Webhook

`POST /api/v1/webhooks/telemetry` รับ JSON telemetry จาก producer ที่ได้รับอนุญาต โดยตรวจ `X-Webhook-Timestamp`, `X-Webhook-Signature` และ `X-Event-Id` ด้วย HMAC-SHA256, จำกัดอายุ webhook และป้องกัน replay event ก่อนสร้าง incident

ลายเซ็นคำนวณจาก:

```
HMAC_SHA256(WEBHOOK_SECRET, timestamp + "." + raw_body)
```

ตั้งค่า secret ด้วย environment variable `WEBHOOK_SECRET` เท่านั้น ห้ามใส่ secret จริงใน source code หรือ commit

### SIEM / Telemetry Adapter

`POST /api/v1/siem/events` รับ normalized event contract ที่มี `vendor`, `event_id`, `event_type`, `source`, `asset_id`, `severity`, `observed_at` และ `attributes` แล้วแปลงเข้าสู่ risk/evidence/audit pipeline เดียวกัน โดยไม่มีการส่งคำสั่งกลับไปยัง SIEM หรือระบบเป้าหมาย

### Forensic Reports

ดาวน์โหลดรายงานจาก incident ได้ที่:

```
GET /api/v1/incidents/{incident_id}/report.md
GET /api/v1/incidents/{incident_id}/report.pdf
```

รายงานมี risk signal breakdown, evidence SHA-256, audit chain status, timeline, attribution status, human approval note, Developer และ MIT License โดย Markdown และ PDF สร้างจาก incident data ชุดเดียวกัน

## สิ่งที่มีในต้นแบบ

หน้า Dashboard มี Security metrics, Active Incident, End-to-End Defense Workflow, guardrail status, threat intelligence status, evidence integrity และ governance status โดยข้อมูลทั้งหมดเป็น Demo Data

ปุ่ม `Revoke Token` และ `Quarantine Case` จะแสดง Human Approval modal และบันทึกสถานะแบบ Demo เท่านั้น ยังไม่เรียก API จริงและไม่เปลี่ยนแปลงระบบภายนอก

## หมายเหตุด้านความปลอดภัย

ต้นแบบนี้ออกแบบเป็น defensive-only interface: read-only passive OSINT, human approval ก่อน containment, ไม่มี exploit, brute force, credential abuse หรือ attack-back

Developer: NAKARIN SAKULTHAI
License: MIT License

## เชื่อมต่อ GitHub

สคริปต์ `scripts/publish_to_github.sh` จะ initialize Git, ตรวจไฟล์ที่มีลักษณะเป็น secret, สร้าง commit, สร้าง GitHub repository แบบ private โดยค่าเริ่มต้น และ push branch `main` โดยใช้ GitHub CLI ที่ล็อกอินอยู่แล้ว

ตรวจสอบแผนงานโดยยังไม่แก้ไข GitHub:

```bash
./scripts/publish_to_github.sh \
  --repo OWNER/REPOSITORY \
  --create \
  --dry-run
```

เมื่อยืนยันชื่อ repository แล้วจึง publish:

```bash
./scripts/publish_to_github.sh \
  --repo OWNER/REPOSITORY \
  --create
```

หากต้องการ repository สาธารณะ ให้เพิ่ม `--public` อย่างชัดเจน สคริปต์จะไม่ทำ attack-back, exploit, brute force หรือเรียก action ไปยังระบบภายนอกนอกจาก GitHub repository ที่ระบุ
