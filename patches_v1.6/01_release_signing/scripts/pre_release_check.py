import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
#!/usr/bin/env python3

"""Pre-release gate — fail hard if anything is off.

Run BEFORE sign_release.py. Exit 0 = clear to release.

"""

import pathlib, subprocess, sys, re

ROOT = pathlib.Path(__file__).resolve().parent.parent

EXCLUDE_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules",

                "artifacts", "logs", "sandbox"}

EXCLUDE_PATTERNS = (".bak.", ".pyc", ".pyo")

def fail(msg: str) -> None:

    print(f"❌ {msg}")

    sys.exit(1)

def check_version_bump() -> None:

    """Ensure docs/RELEASE_v*.md exists for current version."""

    release_docs = sorted((ROOT / "docs").glob("RELEASE_v*.md"))

    if not release_docs:

        fail("no docs/RELEASE_v*.md found — write release notes first")

    latest = release_docs[-1].stem  # RELEASE_v1.5.0

    print(f"   version doc: {latest}")

def check_tests() -> None:

    print("   running pytest...")

    r = subprocess.run(

        [sys.executable, "-m", "pytest", "tests/", "-q", "--no-header"],

        cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace')

    tail = (r.stdout + r.stderr).strip().splitlines()[-1]

    if r.returncode != 0:

        fail(f"pytest failed: {tail}")

    print(f"   {tail}")

def check_verify_all() -> None:

    print("   running verify_all.py...")

    r = subprocess.run(

        [sys.executable, "scripts/verify_all.py", "--base-dir", str(ROOT)],

        cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace')

    if r.returncode != 0:

        fail(f"verify_all.py failed:\n{r.stdout[-800:]}\n{r.stderr[-400:]}")

    print("   5 pillars: PASS")

def check_no_junk() -> None:

    bad = []

    for p in ROOT.rglob("*"):

        if any(part in EXCLUDE_DIRS for part in p.parts):

            continue

        if not p.is_file():

            continue

        if any(pat in p.name for pat in EXCLUDE_PATTERNS):

            bad.append(p.relative_to(ROOT))

    if bad:

        fail(f"junk files present: {bad[:10]}")

    print("   no junk files")

def check_gpg_available() -> None:

    import shutil

    if not shutil.which("gpg"):

        fail("gpg not installed — required for signed release")

    print("   gpg available")

def check_clean_git() -> None:

    """Warn (not fail) if working tree dirty — release still OK."""

    try:

        r = subprocess.run(["git", "status", "--porcelain"],

                           cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace',

                           timeout=10)

    except (FileNotFoundError, subprocess.TimeoutExpired):

        print("   (git not available — skipping)")

        return

    dirty = [l for l in r.stdout.splitlines() if not l.startswith("??")]

    if dirty:

        print(f"   ⚠️  {len(dirty)} modified file(s) — will be included in commit")

    else:

        print("   git tree clean")

def main() -> int:

    print("═══ Pre-release check ═══")

    check_version_bump()

    check_no_junk()

    check_gpg_available()

    check_tests()

    check_verify_all()

    check_clean_git()

    print("\n✅ All checks passed — ready to sign release")

    return 0

if __name__ == "__main__":

    sys.exit(main())
