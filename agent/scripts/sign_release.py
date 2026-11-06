
import os, shutil
for _p in [r'C:\Program Files\Git\usr\bin', r'C:\Program Files (x86)\GnuPG\bin']:
    if os.path.isdir(_p) and _p not in os.environ.get('PATH', ''):
        os.environ['PATH'] = _p + os.pathsep + os.environ.get('PATH', '')

import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
#!/usr/bin/env python3

"""Generate SIGNED_HASHES.txt and sign with GPG.

Usage:

    python scripts/sign_release.py           # build only

    python scripts/sign_release.py --sign    # build + sign

    python scripts/sign_release.py --verify  # verify existing

Format: standard `sha256sum` output — auditor can run `sha256sum -c`

on Linux/macOS or `Get-FileHash` compare on Windows.

"""

import argparse, hashlib, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

OUT_HASHES = ROOT / "docs" / "SIGNED_HASHES.txt"

OUT_SIG = ROOT / "docs" / "SIGNED_HASHES.txt.asc"

# Files included in the release manifest.

# Order matters for reproducibility (sorted).

INCLUDE_DIRS = ["core", "scripts", "tests", "docs", "profiles"]

INCLUDE_TOP = ["main.py", "config.yaml", "requirements-dev.txt"]

EXCLUDE_PATTERNS = (

    ".bak.", ".pyc", ".pyo",

    "SIGNED_HASHES.txt",          # never hash the manifest itself

    "SIGNED_HASHES.txt.asc",

)

def _excluded(p: pathlib.Path) -> bool:

    if p.name == "__init__.py" or p.name.endswith(".py"):

        return False  # include all .py

    for pat in EXCLUDE_PATTERNS:

        if pat in p.name:

            return True

    if p.suffix in (".pyc", ".pyo"):

        return True

    return False

def _walk(d: pathlib.Path) -> list[pathlib.Path]:

    out = []

    if not d.exists():

        return out

    for p in d.rglob("*"):

        if not p.is_file():

            continue

        if any(part in ("__pycache__", ".pytest_cache", ".git") for part in p.parts):

            continue

        if _excluded(p):

            continue

        out.append(p)

    return out

def collect_files() -> list[pathlib.Path]:

    files = []

    for d in INCLUDE_DIRS:

        files.extend(_walk(ROOT / d))

    for f in INCLUDE_TOP:

        p = ROOT / f

        if p.exists():

            files.append(p)

    return sorted(set(files))

def sha256(p: pathlib.Path) -> str:

    h = hashlib.sha256()

    with p.open("rb") as f:

        for chunk in iter(lambda: f.read(65536), b""):

            h.update(chunk)

    return h.hexdigest()

def build() -> int:

    files = collect_files()

    lines = []

    for p in files:

        rel = p.relative_to(ROOT).as_posix()

        lines.append(f"{sha256(p)}  {rel}")

    OUT_HASHES.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"✅ {OUT_HASHES.relative_to(ROOT)} — {len(lines)} files")

    return 0

def sign() -> int:

    try:

        subprocess.run(

            ["gpg", "--batch", "--yes", "--armor", "--detach-sign",

             "--output", str(OUT_SIG), str(OUT_HASHES)],

            check=True, capture_output=True, timeout=60)

    except (subprocess.CalledProcessError, FileNotFoundError) as e:

        print(f"❌ gpg sign failed: {e}", file=sys.stderr)

        return 1

    print(f"✅ {OUT_SIG.relative_to(ROOT)}")

    return 0

def verify() -> int:

    if not OUT_SIG.exists():

        print(f"❌ signature missing: {OUT_SIG}", file=sys.stderr)

        return 1

    try:

        r = subprocess.run(

            ["gpg", "--verify", str(OUT_SIG), str(OUT_HASHES)],

            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)

    except FileNotFoundError:

        print("❌ gpg not installed", file=sys.stderr); return 1

    if r.returncode != 0:

        print(f"❌ signature INVALID:\n{r.stderr}", file=sys.stderr)

        return 1

    if "Good signature" not in r.stderr and "Good signature" not in r.stdout:

        print(f"❌ no 'Good signature' in output", file=sys.stderr)

        return 1

    print("✅ signature valid")

    # also verify every file in SIGNED_HASHES.txt

    bad = []

    for line in OUT_HASHES.read_text(encoding="utf-8").splitlines():

        if not line.strip():

            continue

        expected, rel = line.split("  ", 1)

        p = ROOT / rel

        if not p.exists():

            bad.append(f"MISSING: {rel}")

            continue

        if sha256(p) != expected:

            bad.append(f"TAMPERED: {rel}")

    if bad:

        print(f"❌ {len(bad)} file(s) failed:", file=sys.stderr)

        for b in bad[:20]:

            print(f"   {b}", file=sys.stderr)

        return 1

    print("✅ all file hashes match")

    return 0

def main() -> int:

    ap = argparse.ArgumentParser()

    ap.add_argument("--sign", action="store_true")

    ap.add_argument("--verify", action="store_true")

    args = ap.parse_args()

    if args.verify:

        return verify()

    rc = build()

    if rc == 0 and args.sign:

        rc = sign()

    return rc

if __name__ == "__main__":

    sys.exit(main())
