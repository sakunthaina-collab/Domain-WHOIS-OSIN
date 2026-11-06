from __future__ import annotations
import hashlib
import json
import pathlib
import sys
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.artifact_manifest import build_artifact_manifest, verify_artifacts
from core.registry import Profile, Registry
from core.router import Router
from core.run_manifest import compare_with_current, create_manifest


def test_artifact_manifest_and_merkle_verification(tmp_path):
    case_dir = tmp_path / "CASE-TEST"
    case_dir.mkdir()
    (case_dir / "doc1.txt").write_text("Hello World", encoding="utf-8")
    (case_dir / "doc2.json").write_text('{"status": "ok"}', encoding="utf-8")

    manifest = build_artifact_manifest(case_dir)
    assert manifest["file_count"] == 2
    assert len(manifest["merkle_root"]) == 64

    # Verification passes
    issues = verify_artifacts(case_dir)
    assert len(issues) == 0

    # Tampering detected
    (case_dir / "doc1.txt").write_text("Tampered Content", encoding="utf-8")
    tampered_issues = verify_artifacts(case_dir)
    assert len(tampered_issues) > 0
    assert any("TAMPERED" in iss for iss in tampered_issues)


def test_run_manifest_generation_and_diff(tmp_path):
    # Dummy mock registry and profile
    class MockProfile:
        name = "test-profile"
        model = "model-v1"
        temperature = 0.2
        top_k = 5
        categories = ["investigation"]

    class MockRegistry:
        skills = {}
        all_loaded = []

    profile = MockProfile()
    registry = MockRegistry()

    class MockRouter:
        last_selection = ["skill-a"]

    llm_cfg = {
        "models": {"main": "test-chat", "escalate": "test-reasoner"},
        "base_url": "http://localhost",
    }

    manifest = create_manifest(
        case_id="CASE-REPRO",
        profile=profile,
        task="Test task",
        registry=registry,
        router=MockRouter(),
        llm_config=llm_cfg,
        seed=100,
        artifacts_root=tmp_path,
    )

    assert manifest["case_id"] == "CASE-REPRO"
    assert manifest["llm_params"]["seed"] == 100

    # Test diff
    diffs = compare_with_current(manifest, profile, registry, llm_cfg)
    assert len(diffs) == 0

    # Modify model in config and verify diff
    altered_cfg = {"models": {"main": "different-chat"}}
    diffs_altered = compare_with_current(manifest, profile, registry, altered_cfg)
    assert len(diffs_altered) == 1
    assert "Main model differs" in diffs_altered[0]
