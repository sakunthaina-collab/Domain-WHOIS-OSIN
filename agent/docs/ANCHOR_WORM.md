# S3 WORM Anchor Adapter

## Why WORM?

Hash chain + GPG prove **integrity** and **attribution**. S3 Object Lock
proves **immutability at the storage layer** — even someone with root
AWS access cannot delete an object before retention expires. This is the
strongest anchor available without on-premises HSM.

## Retention modes

| Mode | Delete before expiry | Override by | Recommended for |
|---|---|---|---|
| **COMPLIANCE** | ❌ Impossible | Nobody (not even root) | Court cases, criminal evidence |
| **GOVERNANCE** | ✅ With `s3:BypassGovernanceRetention` | IAM users with the permission | Dev/staging, logs |

**⚠️ COMPLIANCE cannot be reversed** — if you set 7 years and change your
mind, you must wait 7 years. Choose retention based on case type:

| Case type | Recommended retention |
|---|---|
| Criminal (Thai statute of limitations) | **7 years (2555 days)** |
| Civil | 5 years |
| Administrative | 3 years |
| Dev / testing | 1 day |

## Setup (one-time)

### 1. Create bucket with Object Lock

```bash
aws s3api create-bucket \
    --bucket my-forensic-anchors \
    --object-lock-enabled-for-bucket \
    --region ap-southeast-1
```

> [!NOTE]
> You cannot enable Object Lock after bucket creation. If the bucket
> already exists, create a new one.

### 2. Configure IAM
Minimum permissions for the agent:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectRetention",
        "s3:GetObject",
        "s3:GetObjectRetention",
        "s3:GetObjectAttributes"
      ],
      "Resource": "arn:aws:s3:::my-forensic-anchors/anchors/*"
    }
  ]
}
```

> [!WARNING]
> Do NOT grant `s3:BypassGovernanceRetention` or `s3:DeleteObject` to
> the agent — those should only be held by a separate compliance officer
> for GOVERNANCE mode audits.

### 3. Configure the agent

```yaml
# config.yaml
anchor:
  adapter: s3                 # git | s3 | http | file
  ledger_path: logs/anchor_ledger.json
  bucket: my-forensic-anchors
  region: ap-southeast-1
  mode: COMPLIANCE            # COMPLIANCE (court) | GOVERNANCE (dev)
  retention_days: 2555        # 7 years
  prefix: anchors/
  gpg:
    enabled: true
    strict: true
```

### 4. Verify write

```bash
python main.py --dry-run --case-id SMOKE-WORM
# Expected: s3-worm-compliance anchor with version_id + retain_until

aws s3api get-object-retention \
    --bucket my-forensic-anchors \
    --key anchors/SMOKE-WORM/<head16>.json
# Expected: Mode=COMPLIANCE, RetainUntilDate=<7y from now>
```

---

## Auditor verification procedure
An independent auditor (no code access) can verify an anchor exists:

```bash
# 1. List all anchors for a case
aws s3api list-objects-v2 \
    --bucket my-forensic-anchors \
    --prefix anchors/<CASE_ID>/ \
    --query 'Contents[].Key'

# 2. Download the anchor record
aws s3api get-object \
    --bucket my-forensic-anchors \
    --key anchors/<CASE_ID>/<head16>.json \
    /tmp/anchor.json

# 3. Verify retention
aws s3api get-object-retention \
    --bucket my-forensic-anchors \
    --key anchors/<CASE_ID>/<head16>.json
# Must show Mode=COMPLIANCE and a future RetainUntilDate

# 4. Verify signature inside payload
python -c "
import json
rec = json.load(open('/tmp/anchor.json'))
open('/tmp/sig.asc','w').write(rec['signature_asc'])
open('/tmp/payload.json','w').write(json.dumps(rec['record']))
"
# then: gpg --verify /tmp/sig.asc (see GPG_KEY_MANAGEMENT.md)
```

---

## Local development (LocalStack)

```bash
./scripts/run_localstack.sh
# exports AWS_ENDPOINT_URL=http://localhost:4566 etc.
export AWS_ENDPOINT_URL=http://localhost:4566
python main.py --dry-run --case-id LOCAL-WORM
```

LocalStack simulates Object Lock but does not enforce true WORM —
it's only for integration testing, not for evidence preservation.

---

## Cost estimate

| Retention | Cases/yr | Size/anchor | Storage cost (S3 Standard) |
|---|---|---|---|
| 7 years | 100 | ~2 KB | ~$0.05/yr (negligible) |

Storage cost is trivial. The real cost is irreversibility — once
uploaded, you cannot delete. Plan accordingly.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Object Lock not enabled | Bucket created without `--object-lock-enabled-for-bucket` | Create new bucket (cannot retrofit) |
| AccessDenied on put | Missing `s3:PutObjectRetention` | Update IAM permissions |
| InvalidRequest: retention date in the past | Clock skew | Check system time, use NTP |
| verify_checksum fails | Network corruption or wrong body | Retry; if persistent, check S3 endpoint |
