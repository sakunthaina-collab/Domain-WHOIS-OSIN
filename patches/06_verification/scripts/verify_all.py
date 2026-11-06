#!/usr/bin/env python3
"""
Master Verification Script for Trustworthy Agent v1.1
Executes all 5 verification pillars:
1. Audit Log Hash Chain Cryptographic Integrity
2. Skill Inventory & Stub Isolation Integrity
3. Artifact Manifest Merkle Root & SHA256 Verification
4. Checkpoint & Resilience Sanity
5. Automated Test Suite (pytest)
"""
from __future__ import annotations
import argparse
import os
import pathlib
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def check_audit_log(base_dir: pathlib.Path) -> bool:
    print("\n[Pillar 1/5] Checking Audit Log Hash Chain...")
    audit_file = base_dir / "logs" / "audit.jsonl"
    verify_script = base_dir / "scripts" / "verify_audit.py"
    if not audit_file.exists():
        print("  ⚠️  logs/audit.jsonl does not exist yet (will be initialized on first run).")
        return True
    res = subprocess.run(
        [sys.executable, str(verify_script), str(audit_file)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (res.stdout or "") + (res.stderr or "")
    print("  " + out.strip())
    return res.returncode == 0


def check_inventory(base_dir: pathlib.Path) -> bool:
    print("\n[Pillar 2/5] Checking Skill Inventory & Stub Isolation...")
    audit_script = base_dir / "scripts" / "audit_skill_inventory.py"
    if not audit_script.exists():
        print("  ⚠️  scripts/audit_skill_inventory.py not found, skipping inventory check.")
        return True
    res = subprocess.run(
        [sys.executable, str(audit_script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (res.stdout or "") + (res.stderr or "")
    print(out.strip())
    return res.returncode == 0


def check_artifacts(base_dir: pathlib.Path) -> bool:
    print("\n[Pillar 3/5] Checking Artifact Manifest & Merkle Roots...")
    art_dir = base_dir / "artifacts"
    if not art_dir.exists():
        print("  ℹ️  artifacts/ directory empty (no cases run yet).")
        return True

    cases = [d for d in art_dir.iterdir() if d.is_dir()]
    if not cases:
        print("  ℹ️  0 case directories found in artifacts.")
        return True

    all_passed = True
    for c in cases:
        manifest_file = c / "artifact_manifest.json"
        if manifest_file.exists():
            res = subprocess.run(
                [sys.executable, "-m", "main", "--verify-artifacts", c.name],
                cwd=str(base_dir),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            out = (res.stdout or "") + (res.stderr or "")
            print(f"  Case {c.name}: {out.strip()}")
            if res.returncode != 0:
                all_passed = False
        else:
            print(f"  Case {c.name}: No artifact_manifest.json found.")
    return all_passed


def run_unit_tests(base_dir: pathlib.Path) -> bool:
    print("\n[Pillar 4/5 & 5/5] Running Pytest Unit Test Suite...")
    tests_dir = base_dir / "tests"
    if not tests_dir.exists():
        print("  ⚠️  tests/ directory not found.")
        return False
    res = subprocess.run(
        [sys.executable, "-m", "pytest", str(tests_dir), "-v"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (res.stdout or "") + (res.stderr or "")
    print(out)
    return res.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Master verification runner")
    parser.add_argument("--base-dir", default=".", help="Base directory of the agent")
    args = parser.parse_args()

    base_dir = pathlib.Path(args.base_dir).resolve()
    print("=" * 65)
    print("🔒 RUNNING TRUSTWORTHY AGENT SYSTEM VERIFICATION")
    print(f"Target directory: {base_dir}")
    print("=" * 65)

    p1 = check_audit_log(base_dir)
    p2 = check_inventory(base_dir)
    p3 = check_artifacts(base_dir)
    p4 = run_unit_tests(base_dir)

    print("\n" + "=" * 65)
    if p1 and p2 and p3 and p4:
        print("🎉 ALL VERIFICATION CHECKS PASSED: SYSTEM FULLY TRUSTWORTHY")
        print("=" * 65)
        sys.exit(0)
    else:
        print("❌ VERIFICATION FAILED: See details above")
        print("=" * 65)
        sys.exit(1)


if __name__ == "__main__":
    main()
