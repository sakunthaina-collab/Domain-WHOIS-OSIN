# SecOps UI Command Center — Cloud Functions for Firebase (2nd Gen)

Developer: **NAKARIN SAKULTHAI**  
License: **MIT License**

Defensive-Only AI Cyber Defense Platform and Telemetry Engine migrated to modern Cloud Functions for Firebase v2 (`functions/src/`).

---

## 1. Installation & Local Development

### Requirements
- Node.js `>=22`
- Firebase CLI (`npm install -g firebase-tools`)

### Local Setup
```bash
cd functions
npm install
npm run build
```

### Run Firebase Emulator Suite
```bash
# Starts both Cloud Functions v2 and SecOps UI Hosting locally
firebase emulators:start --only functions,hosting
```

---

## 2. Deployment

Deploy functions to Google Cloud / Firebase:
```bash
# Set production webhook secret
firebase functions:secrets:set WEBHOOK_SECRET

# Deploy functions and hosting rewrites
firebase deploy --only functions,hosting
```

---

## 3. Parameterized Configuration Reference

| Parameter Name | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `WEBHOOK_SECRET` | Secret (`defineSecret`) | *Required in Prod* | Shared HMAC-SHA256 secret for signed telemetry ingestion |
| `DEFENSIVE_MODE` | String (`defineString`) | `enforced` | Strict defensive guardrails (forbids exploit, attack_back, port_scan) |
| `WEBHOOK_TOLERANCE_SECONDS` | Int (`defineInt`) | `300` | Allowed timestamp drift window (seconds) to prevent replay attacks |

> [!IMPORTANT]
> **Zero Global Scope Parameter Evaluation:** Parameters are never evaluated with `.value()` at the top-level load scope; they are evaluated safely inside `onInit()` or execution scope.

---

## 4. What Changed (Legacy / Local Architecture vs Functions v2)

| Feature | Local Backend (FastAPI / Server.py) | Cloud Functions for Firebase (v2) |
| :--- | :--- | :--- |
| **Compute Model** | Long-running dedicated Python Process | Serverless auto-scaling Cloud Functions v2 |
| **Trigger Type** | Traditional HTTP Socket Binding (8000/8001) | Managed HTTPS Trigger (`onRequest`) via Cloud Run v2 |
| **Secret Management** | Local `.env` / Process Environment | Google Cloud Secret Manager via `defineSecret` |
| **IAM & Permissions** | OS-level user credentials | Managed Service Account & Declarative IAM |
| **UI Integration** | Local static file server | Firebase Hosting with `/api/**` URL rewrites to `secopsApi` |
| **Concurrency** | Single/Multi-threaded Python worker | Configured with `concurrency: 80`, `cpu: "gcf_gen1"` |
| **Anti-Replay** | Python memory lock | Dual memory-cache / Firestore idempotency |
| **Evidence & Hash Chain** | SHA-256 Merkle chain in memory | Cryptographic SHA-256 chain verified per incident |
