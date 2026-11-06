from __future__ import annotations
import json
import pathlib
import sys
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.artifact_manifest import build_artifact_manifest, verify_artifacts
from core.guardrails import Guardrails
from core.memory import Memory
from core.registry import Profile, Registry
from core.router import Router
from core.run_manifest import compare_with_current, create_manifest
from scripts.verify_audit import verify as verify_audit_log


@pytest.fixture
def registry():
    return Registry(AGENT_DIR / "skills")


@pytest.fixture
def profile():
    return Profile.from_yaml(AGENT_DIR / "profiles" / "investigator.yaml")


def test_audit_hash_chain_valid_and_tamper_detection(tmp_path, registry):
    log_file = tmp_path / "audit_chain.jsonl"
    guard = Guardrails(log_path=log_file)
    skill = registry.get("phone-email-osint")

    # 1. Log 3 sequential actions
    guard.audit(skill, {"target": "+661"}, step=1, case_id="C1", result={"ok": True}, parent_step=None)
    guard.audit(skill, {"target": "+662"}, step=2, case_id="C1", result={"ok": True}, parent_step=1)
    guard.audit(skill, {"target": "+663"}, step=3, case_id="C1", result={"ok": True}, parent_step=2)

    ok, msg = verify_audit_log(log_file)
    assert ok is True
    assert "3 audit entries cryptographically verified" in msg

    # 2. Tamper test: modify payload of line 2
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    bad_rec = json.loads(lines[1])
    bad_rec["status"] = "tampered_status"
    lines[1] = json.dumps(bad_rec)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok_tampered, err_msg = verify_audit_log(log_file)
    assert ok_tampered is False
    assert "tampered" in err_msg.lower() or "mismatch" in err_msg.lower()

    # 3. Deletion test: remove line 2 completely
    lines.pop(1)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok_deleted, del_msg = verify_audit_log(log_file)
    assert ok_deleted is False
    assert "prev_hash mismatch" in del_msg


def test_artifact_manifest_merkle_root_and_tamper_detection(tmp_path):
    case_dir = tmp_path / "CASE-INTEGRITY"
    case_dir.mkdir()
    (case_dir / "001_phone.json").write_text('{"carrier": "AIS"}', encoding="utf-8")
    (case_dir / "002_dossier.md").write_text("# Official Case Report", encoding="utf-8")

    manifest = build_artifact_manifest(case_dir)
    assert manifest["file_count"] == 2
    assert len(manifest["merkle_root"]) == 64

    # Verification must pass with zero issues
    issues = verify_artifacts(case_dir)
    assert len(issues) == 0

    # Tamper with one file
    (case_dir / "001_phone.json").write_text('{"carrier": "TAMPERED"}', encoding="utf-8")
    tampered_issues = verify_artifacts(case_dir)
    assert len(tampered_issues) >= 2
    assert any("TAMPERED" in iss for iss in tampered_issues)
    assert any("MERKLE_ROOT_MISMATCH" in iss for iss in tampered_issues)


def test_run_manifest_generation_and_reproducibility(tmp_path, registry, profile):
    router = Router(registry, allowed_categories=profile.categories)
    router.route("ตรวจสอบเบอร์ +66942638165", k=5)
    llm_cfg = {
        "models": {"main": "deepseek-chat", "escalate": "deepseek-reasoner"},
        "base_url": "https://api.deepseek.com/v1",
    }

    manifest = create_manifest(
        case_id="CASE-REPRODUCE",
        profile=profile,
        task="Test reproducible task",
        registry=registry,
        router=router,
        llm_config=llm_cfg,
        seed=42,
        artifacts_root=tmp_path,
    )

    manifest_file = tmp_path / "CASE-REPRODUCE" / "00_run_manifest.json"
    assert manifest_file.exists()
    assert manifest["llm_params"]["seed"] == 42
    assert manifest["profile"] == "Investigator Agent"

    # Comparison against identical state yields 0 differences
    diffs = compare_with_current(manifest, profile, registry, llm_cfg)
    assert len(diffs) == 0

    # Injected diff test
    manifest["environment"]["python"] = "2.7.0"
    diffs_modified = compare_with_current(manifest, profile, registry, llm_cfg)
    assert len(diffs_modified) == 1
    assert "Python version differs" in diffs_modified[0]


def test_memory_checkpoint_snapshot_and_restore(tmp_path):
    mem = Memory(case_id="CASE-SNAP", artifacts_root=tmp_path)
    mem.add("user", "Initial query")
    mem.add("assistant", "Step 1 thinking")
    snapshot = mem.snapshot()

    mem_restored = Memory(case_id="OTHER", artifacts_root=tmp_path)
    mem_restored.restore(snapshot)

    assert mem_restored.case_id == "CASE-SNAP"
    assert len(mem_restored.messages) == 2
    assert mem_restored.messages[0]["content"] == "Initial query"
