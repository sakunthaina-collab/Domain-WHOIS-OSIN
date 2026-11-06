from __future__ import annotations
import hashlib
import json
import pathlib
import time
from typing import Any


def _compute_merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        return "0" * 64
    current_level = sorted(leaf_hashes)
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
            next_level.append(combined)
        current_level = next_level
    return current_level[0]


def build_artifact_manifest(case_dir: str | pathlib.Path) -> dict[str, Any]:
    c_dir = pathlib.Path(case_dir)
    if not c_dir.exists():
        raise FileNotFoundError(f"Case directory does not exist: {c_dir}")

    files_info = []
    for p in sorted(c_dir.rglob("*")):
        if p.is_file() and p.name != "artifact_manifest.json":
            raw_bytes = p.read_bytes()
            sha = hashlib.sha256(raw_bytes).hexdigest()
            files_info.append({
                "path": str(p.relative_to(c_dir)).replace("\\", "/"),
                "size_bytes": len(raw_bytes),
                "sha256": sha,
            })

    leaf_hashes = [f["sha256"] for f in files_info]
    merkle_root = _compute_merkle_root(leaf_hashes)

    manifest = {
        "case_dir": str(c_dir.resolve()),
        "created_at": round(time.time(), 3),
        "file_count": len(files_info),
        "merkle_root": merkle_root,
        "files": files_info,
    }

    manifest_path = c_dir / "artifact_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def verify_artifacts(case_dir: str | pathlib.Path) -> list[str]:
    c_dir = pathlib.Path(case_dir)
    manifest_path = c_dir / "artifact_manifest.json"
    if not manifest_path.exists():
        return ["MANIFEST_MISSING: artifact_manifest.json not found"]

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        return [f"MANIFEST_CORRUPTED: {e}"]

    issues = []
    recorded_paths = set()
    current_hashes = []

    for item in manifest.get("files", []):
        rel_path = item["path"]
        recorded_paths.add(rel_path)
        file_path = c_dir / rel_path
        if not file_path.exists():
            issues.append(f"MISSING: {rel_path}")
            continue

        actual_sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_sha != item["sha256"]:
            issues.append(f"TAMPERED: {rel_path} (expected {item['sha256'][:12]}..., got {actual_sha[:12]}...)")
        current_hashes.append(actual_sha)

    # Check for unmanifested / injected files
    for p in sorted(c_dir.rglob("*")):
        if p.is_file() and p.name != "artifact_manifest.json":
            rel = str(p.relative_to(c_dir)).replace("\\", "/")
            if rel not in recorded_paths:
                issues.append(f"UNMANIFESTED_FILE: {rel}")

    computed_merkle = _compute_merkle_root(current_hashes)
    if computed_merkle != manifest.get("merkle_root"):
        issues.append(
            f"MERKLE_ROOT_MISMATCH: expected {manifest.get('merkle_root')[:12]}..., computed {computed_merkle[:12]}..."
        )

    return issues
