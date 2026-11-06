# Auditor Evidence Packet — Trustworthy Agent v1.5.0

**This packet is self-verifiable.** You do not need to trust the

development team. Follow the three steps below and you will know, with

cryptographic certainty, whether this release has been tampered with.

## Contents

auditor_packet_v1.5.0/

├── README.md ← you are here

├── MANIFEST.json ← SHA-256 of every file in this packet

├── MANIFEST.json.asc ← GPG signature over MANIFEST.json

├── VERIFY.sh ← one-command verifier (Linux/macOS)

├── VERIFY.ps1 ← one-command verifier (Windows)

├── SOURCE/

│ └── source.tar.gz ← source code at tag v1.5.0

├── TRUST/

│ ├── SIGNED_HASHES.txt ← SHA-256 of each source file

│ ├── SIGNED_HASHES.txt.asc ← GPG signature over SIGNED_HASHES.txt

│ └── public-key.asc ← org public key (fingerprint below)

└── DOCS/

├── AUDITOR_GUIDE.md

├── ANCHOR_WORM.md

├── CHAIN_OF_CUSTODY_SOP.md

├── INCIDENT_RESPONSE.md

├── THREAT_MODEL.md

├── GPG_KEY_MANAGEMENT.md

├── FINDINGS.md

├── TRUST.md

└── RELEASE_v1.5.0.md

text

## The trust chain (in one diagram)

Org GPG key (fingerprint: 3892E3F2CEDAE88EDEF85D64892DBC9697F6927A)

│ signs

▼

SIGNED_HASHES.txt.asc ──proves──► SIGNED_HASHES.txt is authentic

│ contains

▼

SHA-256 of each source file ──verify──► source.tar.gz contents

│

▼

MANIFEST.json ──covers──► every file in this packet (incl. docs)

│ signed by same key

▼

MANIFEST.json.asc ──proves──► packet itself not tampered

text

## Step 1 — Verify (30 seconds)

### Linux / macOS

```bash

unzip auditor_packet_v1.5.0.zip

cd auditor_packet_v1.5.0/

./VERIFY.sh

Windows (PowerShell)

powershell

Expand-Archive auditor_packet_v1.5.0.zip

cd auditor_packet_v1.5.0

.\VERIFY.ps1

Expected final line: ✅ PACKET VERIFIED — all checks passed

Step 2 — Inspect the evidence (optional)

bash

# extract source

tar -xzf SOURCE/source.tar.gz -C /tmp/agent-v1.5.0/

# run the project's own verifier

cd /tmp/agent-v1.5.0/

python scripts/verify_all.py --base-dir .

# → expect 5 pillars + 154 tests passed

Step 3 — Record your audit (mandatory)

Use DOCS/AUDITOR_GUIDE.md §7 (Sample Audit Report Template).

Return it to the case owner with your signature.

What this packet proves

✅ The source code is exactly what the org signed at v1.5.0.

✅ The packet itself has not been altered since signing.

✅ The documented procedures (AUDITOR_GUIDE, CoC, Incident Response)

are part of the signed release.

What this packet does NOT prove

❌ That the code is correct (only that it's the code we signed).

❌ That the audits were performed correctly (see docs).

❌ Anything about real case data (this packet contains a DEMO case only).

Support

Technical questions: technical-lead@example.org

Key management: dpo@example.org

Incident reporting: see DOCS/INCIDENT_RESPONSE.md §2

Fingerprint verification

Before trusting any GPG output, verify the org key fingerprint against

a second channel (email, phone, paper document). This packet contains

the fingerprint on the first page — cross-check it.

Fingerprint: 3892E3F2CEDAE88EDEF85D64892DBC9697F6927A

text
