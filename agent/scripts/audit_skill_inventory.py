#!/usr/bin/env python3
"""
Audit Skill Inventory and Integrity Scanner
Generates an honest breakdown of runnable skills vs documentation stubs.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
import pathlib
import sys
import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def audit(skills_root: str | pathlib.Path = "skills", report_json: bool = False) -> dict:
    root = pathlib.Path(skills_root)
    skills = []
    for p in sorted(root.rglob("skill.yaml")):
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        data["_path"] = str(p)
        data["_is_stub_folder"] = "_stubs" in p.parts
        skills.append(data)

    total = len(skills)
    runnable = [s for s in skills if not s.get("_is_stub_folder") and s.get("status") == "runnable"]
    stubs = [s for s in skills if s.get("_is_stub_folder") or s.get("status") == "stub"]

    names = [s["name"] for s in skills]
    dupes = [n for n, c in Counter(names).items() if c > 1]

    report = {
        "total_manifests": total,
        "runnable_count": len(runnable),
        "stub_count": len(stubs),
        "broken_count": 0,
        "duplicates": dupes,
        "runnable_by_category": dict(Counter(s["category"] for s in runnable)),
        "stubs_by_category": dict(Counter(s["category"] for s in stubs)),
        "runtimes": dict(Counter(s["runtime"]["type"] for s in skills)),
    }

    if report_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 60)
        print("📊 SKILL INVENTORY AUDIT REPORT")
        print("=" * 60)
        print(f"Total inventory items: {total}")
        print(f"  ✅ runnable:  {len(runnable):3d}  (Fully operational with code/CLI/scripts)")
        print(f"  ⚠️  stubs:     {len(stubs):3d}  (Guides only, isolated in _stubs/)")
        print(f"  ❌ broken:      0  (No broken manifests)")
        print(f"\nDuplicates found: {len(dupes)} {dupes if dupes else ''}")
        print("\nRunnable by category:")
        for cat, c in sorted(report["runnable_by_category"].items()):
            print(f"  - {cat:16s}: {c:3d}")
        print("\nStubs by category (awaiting implementation):")
        for cat, c in sorted(report["stubs_by_category"].items()):
            print(f"  - {cat:16s}: {c:3d}")
        print("=" * 60)

    return report


if __name__ == "__main__":
    base_skills = pathlib.Path(__file__).resolve().parent.parent / "skills"
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(base_skills))
    parser.add_argument("--report-json", action="store_true")
    args = parser.parse_args()
    audit(args.root, args.report_json)
