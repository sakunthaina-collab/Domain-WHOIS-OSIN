# Trustworthy Agent v1.3 — Dual-Layer GPG-Signed Anchor Patch

This patch upgrades external anchoring from unsigned Git annotated tags (`git tag -a`) to **Dual-Layer Cryptographic GPG Signatures**:
1. **Layer 1 (`logs/anchor_ledger.json.asc`):** Detached ASCII-armored GPG signature over the entire anchor ledger.
2. **Layer 2 (`git tag -s`):** GPG-signed Git tag binding the case ID, entry count, head hash, and commit timestamp to the organization's signing key.

---

## 📁 Directory Structure

```text
patches_v1.3/
├── 01_gpg_anchor/
│   ├── core/gpg_signer.py               # Subprocess-based GPG wrapper (zero pip deps)
│   ├── core/anchor.py                   # Dual-layer GPG signing in Anchor engine
│   └── config.yaml.additions.yaml       # GPG config block
├── 02_setup_scripts/
│   ├── scripts/gpg_setup_org_key.ps1    # Windows org key generator & public key exporter
│   ├── scripts/gpg_setup_org_key.sh     # Linux/macOS org key generator
│   └── scripts/generate_mock_keyring.py # Ephemeral GNUPGHOME generator for CI/testing
├── 03_verify_upgrade/
│   └── scripts/verify_audit.py          # Adds exit codes 4 (BADSIG) & 5 (missing sig in --strict-gpg)
├── 04_tests/
│   ├── tests/conftest_gpg.py            # Pytest ephemeral keyring fixtures
│   └── tests/test_gpg_anchor.py         # 9 GPG signing, tampering, and strict-mode tests
├── 05_docs/
│   └── docs/GPG_KEY_MANAGEMENT.md       # Key hierarchy, rotation, revocation & SoD policy
├── apply_all.ps1
├── apply_all.sh
└── README.md
```

---

## 🚀 How to Apply & Verify

```powershell
# 1. Apply patch bundle to agent/
powershell -ExecutionPolicy Bypass -File patches_v1.3\apply_all.ps1 -Target agent

# 2. Run the 9 GPG unit tests (and full 49-test suite)
pytest agent/tests -v
```
