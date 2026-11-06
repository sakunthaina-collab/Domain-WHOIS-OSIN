#!/usr/bin/env python3
"""
Reorganize Stubs into _stubs/ Isolation Directory
Moves documentation-only or stub skills to skills/_stubs/<category>/ to prevent router noise.
"""
from __future__ import annotations
import argparse
import pathlib
import shutil
import sys
import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def reorganize(skills_root: str | pathlib.Path, dry_run: bool = False) -> None:
    root = pathlib.Path(skills_root).resolve()
    stubs_dir = root / "_stubs"

    moved = 0
    for p in sorted(root.rglob("skill.yaml")):
        if "_stubs" in p.parts:
            continue
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            continue

        status = data.get("status", "runnable")
        rtype = data.get("runtime", {}).get("type", "stub")
        parent = p.parent

        is_stub = False
        if status == "stub" or rtype == "stub":
            is_stub = True
        elif rtype == "python":
            entry = data.get("runtime", {}).get("entry")
            if not entry or not (parent / entry).exists():
                is_stub = True

        if is_stub:
            cat = data.get("category", "uncategorized")
            target_parent = stubs_dir / cat / parent.name
            print(f"[{'DRY-RUN' if dry_run else 'MOVE'}] {parent.name} -> _stubs/{cat}/{parent.name}")
            if not dry_run:
                target_parent.parent.mkdir(parents=True, exist_ok=True)
                if target_parent.exists():
                    shutil.rmtree(target_parent)
                shutil.move(str(parent), str(target_parent))
                # update status in YAML to stub
                sy = target_parent / "skill.yaml"
                if sy.exists():
                    doc = yaml.safe_load(sy.read_text(encoding="utf-8")) or {}
                    doc["status"] = "stub"
                    sy.write_text(yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
            moved += 1

    print(f"\nDone! {'Would move' if dry_run else 'Moved'} {moved} stub skills into {stubs_dir}")


def main():
    parser = argparse.ArgumentParser(description="Reorganize stubs to _stubs/ isolation")
    parser.add_argument("--root", default="skills", help="Root skills directory")
    parser.add_argument("--dry-run", action="store_true", help="Preview without moving files")
    args = parser.parse_args()
    reorganize(args.root, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
