"""Regression tests for Patch v1.6.1 — case_id injection."""
import json, pathlib, pytest

from core.case_id import validate_case_id, is_valid_case_id
from core.case_id_injector import inject_case_id


# ── fake skill factory ──────────────────────────────────────
class _Skill:
    def __init__(self, name="dossier", schema=None):
        self.name = name
        self.risk = "low"
        self.category = "investigation"
        self.runtime = {"type": "python", "entry": "run.py"}
        self.input_schema = schema or {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        }


# ══════════════════════════════════════════════════════════
# Unit — validate_case_id
# ══════════════════════════════════════════════════════════
@pytest.mark.parametrize("good", [
    "2026-11-06-CASE-B-FULL",
    "2026-11-05-CASE-001",
    "2024-01-01-CASE-A",
    "2026-12-31-CASE-XYZ-ABC",
])
def test_validate_accepts_good_ids(good):
    assert validate_case_id(good) == good


@pytest.mark.parametrize("bad", [
    "",
    "../../etc/passwd",
    "2026/11/06-CASE-001",
    "CASE-001",
    "2026-11-06-case-001",            # lowercase
    "2026-11-06-CASE-" + "A" * 70,    # too long
    "2026-11-06-CASE-001\x00",        # NUL
    "2026-11-06-CASE-001; rm -rf /",  # injection
])
def test_validate_rejects_bad_ids(bad):
    with pytest.raises(ValueError):
        validate_case_id(bad)


# ══════════════════════════════════════════════════════════
# Unit — inject_case_id
# ══════════════════════════════════════════════════════════
def test_inject_no_schema_skips():
    skill = _Skill(schema={"type": "object", "properties": {}})
    args, meta = inject_case_id(skill, {"x": 1}, "2026-11-06-CASE-001")
    assert args == {"x": 1}
    assert meta["injected"] is False


def test_inject_overrides_llm_value():
    skill = _Skill()
    args, meta = inject_case_id(
        skill,
        {"case_id": "2026-11-05-CASE-001", "lang": ["th"]},
        "2026-11-06-CASE-B-FULL",
    )
    assert args["case_id"] == "2026-11-06-CASE-B-FULL"
    assert args["lang"] == ["th"]
    assert meta["injected"] is True
    assert meta["overridden"] is True
    assert meta["llm_value"] == "2026-11-05-CASE-001"


def test_inject_no_override_when_match():
    skill = _Skill()
    args, meta = inject_case_id(
        skill, {"case_id": "2026-11-06-CASE-B-FULL"},
        "2026-11-06-CASE-B-FULL")
    assert args["case_id"] == "2026-11-06-CASE-B-FULL"
    assert meta["overridden"] is False


def test_inject_rejects_invalid_canonical():
    skill = _Skill()
    with pytest.raises(ValueError):
        inject_case_id(skill, {}, "../../etc/passwd")


# ══════════════════════════════════════════════════════════
# Integration — orchestrator loop simulation
# ══════════════════════════════════════════════════════════
def test_llm_cannot_redirect_dossier_to_wrong_case(tmp_path):
    """Simulate: LLM sends wrong case_id → skill receives correct one."""
    # record what skill actually receives
    received = {}

    def fake_skill_run(**kwargs):
        received.update(kwargs)
        # write dossier into tmp_path/case_id/
        case_dir = tmp_path / kwargs["case_id"]
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "dossier_th.md").write_text("# dossier", encoding="utf-8")
        return {"ok": True}

    canonical = "2026-11-06-CASE-B-FULL"
    llm_sent = {"case_id": "2026-11-05-CASE-001", "lang": ["th"]}

    # Step 1: orchestrator injects
    args, meta = inject_case_id(_Skill(), llm_sent, canonical)
    assert meta["overridden"] is True

    # Step 2: skill receives injected args
    fake_skill_run(**args)

    # Step 3: dossier is in the CORRECT folder
    assert (tmp_path / canonical / "dossier_th.md").exists()
    assert not (tmp_path / "2026-11-05-CASE-001").exists()
    assert received["case_id"] == canonical
