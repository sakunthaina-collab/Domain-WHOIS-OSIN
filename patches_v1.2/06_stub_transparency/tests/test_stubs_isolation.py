"""Prove that Registry never loads stubs."""
import pathlib
import sys
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.registry import Registry


def test_stubs_never_loaded(tmp_path, monkeypatch):
    # build a fake skills tree
    skills = tmp_path / "skills"
    (skills / "real" / "skill.yaml").parent.mkdir(parents=True)
    (skills / "real" / "skill.yaml").write_text(
        "name: real\nversion: 1.0.0\ncategory: real\n"
        "description: ok\ninput_schema: {type: object}\n"
        "runtime: {type: http, url: http://x}\n"
        "risk: low\nstatus: runnable\n",
        encoding="utf-8",
    )
    stub_dir = skills / "_stubs" / "stubbed"
    stub_dir.mkdir(parents=True)
    (stub_dir / "skill.yaml").write_text(
        "name: stubbed\nversion: 1.0.0\ncategory: stubbed\n"
        "description: stub\ninput_schema: {type: object}\n"
        "runtime: {type: python, entry: run.py}\n"  # file missing
        "risk: low\nstatus: stub\n",
        encoding="utf-8",
    )

    reg = Registry(str(skills))
    assert "real" in reg.skills
    assert "stubbed" not in reg.skills, "stub leaked into production registry"


def test_registry_filters_by_status():
    # integration: real registry must have 0 stubs loaded
    skills_dir = pathlib.Path("skills") if pathlib.Path("skills").exists() else AGENT_DIR / "skills"
    real_reg = Registry(skills_dir)
    assert all(
        getattr(s, "status", "runnable") == "runnable"
        for s in real_reg.skills.values()
    )
