from __future__ import annotations
import hashlib
import json
import pathlib
import platform
import sys
import time
from typing import Any
from core.registry import Profile, Registry
from core.router import Router


def _hash_registry(registry: Registry) -> str:
    """Deterministic hash of sorted (skill_name, version, status) across registry."""
    items = sorted(
        (s.name, getattr(s, "version", "1.0.0"), getattr(s, "status", "runnable"))
        for s in registry.skills.values()
    )
    return hashlib.sha256(json.dumps(items, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def create_manifest(
    case_id: str,
    profile: Profile,
    task: str,
    registry: Registry,
    router: Router,
    llm_config: dict[str, Any],
    seed: int = 42,
    artifacts_root: str | pathlib.Path = "artifacts",
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "case_id": case_id,
        "created_at": round(time.time(), 3),
        "task": task,
        "profile": profile.name,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "agent_version": "1.0.0",
        },
        "models": {
            "main": llm_config.get("models", {}).get("main", "deepseek-chat"),
            "escalate": llm_config.get("models", {}).get("escalate", "deepseek-reasoner"),
            "base_url": llm_config.get("base_url", "https://api.deepseek.com/v1"),
        },
        "llm_params": {
            "temperature": profile.temperature,
            "top_k": profile.top_k,
            "seed": seed,
        },
        "registry": {
            "total_skills": len(registry.all_loaded),
            "runnable_skills": len(registry.skills),
            "registry_hash": _hash_registry(registry),
        },
        "skill_selection": getattr(router, "last_selection", []),
    }
    out_dir = pathlib.Path(artifacts_root) / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "00_run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def compare_with_current(
    saved_manifest: dict[str, Any],
    current_profile: Profile,
    current_registry: Registry,
    current_llm_config: dict[str, Any],
) -> list[str]:
    diffs = []
    saved_env = saved_manifest.get("environment", {})
    curr_python = sys.version.split()[0]
    if saved_env.get("python") != curr_python:
        diffs.append(f"Python version differs: saved={saved_env.get('python')} vs current={curr_python}")

    saved_reg = saved_manifest.get("registry", {})
    curr_reg_hash = _hash_registry(current_registry)
    if saved_reg.get("registry_hash") != curr_reg_hash:
        diffs.append(
            f"Registry hash differs: saved={saved_reg.get('registry_hash')} vs current={curr_reg_hash}"
        )

    saved_models = saved_manifest.get("models", {})
    curr_main = current_llm_config.get("models", {}).get("main")
    if saved_models.get("main") != curr_main:
        diffs.append(f"Main model differs: saved={saved_models.get('main')} vs current={curr_main}")

    return diffs
