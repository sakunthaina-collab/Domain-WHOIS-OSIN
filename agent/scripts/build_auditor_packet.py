
import os, shutil
for _p in [r'C:\Program Files\Git\usr\bin', r'C:\Program Files (x86)\GnuPG\bin']:
    if os.path.isdir(_p) and _p not in os.environ.get('PATH', ''):
        os.environ['PATH'] = _p + os.pathsep + os.environ.get('PATH', '')

import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
#!/usr/bin/env python3

"""Build a self-verifiable auditor evidence packet (ZIP).

The packet is designed so an auditor can:

  1. Verify the GPG signature on SIGNED_HASHES.txt.asc

  2. Verify every source file's SHA-256 matches the manifest

  3. Optionally run pytest to reproduce test results

  — all WITHOUT trusting the dev team or having prior context.

Usage:

    python scripts/build_auditor_packet.py --tag v1.5.0 --out dist/

"""

import argparse, hashlib, json, pathlib, subprocess, sys, zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

TEMPLATES = pathlib.Path(__file__).resolve().parent / "templates"

def git_archive(tag: str, out_dir: pathlib.Path) -> None:

    out_dir.mkdir(parents=True, exist_ok=True)

    archive = out_dir / "source.tar.gz"

    subprocess.run(["git", "archive", "--format=tar.gz",

                    f"--output={archive}", tag],

                   cwd=ROOT, check=True, capture_output=True)

    print(f"   source: {archive.name} ({archive.stat().st_size // 1024} KB)")

def copy_required(src: pathlib.Path, dst: pathlib.Path) -> None:

    dst.parent.mkdir(parents=True, exist_ok=True)

    dst.write_bytes(src.read_bytes())

def build_manifest(packet_root: pathlib.Path) -> dict:

    files = []

    for p in sorted(packet_root.rglob("*")):

        if not p.is_file():

            continue

        rel = p.relative_to(packet_root).as_posix()

        if rel in ("MANIFEST.json", "MANIFEST.json.asc", "VERIFY.sh", "VERIFY.ps1"):

            continue

        files.append({

            "path": rel,

            "size": p.stat().st_size,

            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),

        })

    merkle = hashlib.sha256(

        "".join(f["sha256"] for f in files).encode()).hexdigest()

    return {"file_count": len(files), "merkle_root": merkle, "files": files}

def sign_manifest(manifest_path: pathlib.Path) -> pathlib.Path:

    sig = manifest_path.with_suffix(manifest_path.suffix + ".asc")

    subprocess.run(

        ["gpg", "--batch", "--yes", "--armor", "--detach-sign",

         "--output", str(sig), str(manifest_path)],

        check=True, capture_output=True, timeout=60)

    return sig

def build_packet(tag: str, out_dir: pathlib.Path) -> pathlib.Path:

    version = tag.lstrip("v")

    packet_name = f"auditor_packet_{tag}"

    packet = out_dir / packet_name

    if packet.exists():

        import shutil

        shutil.rmtree(packet)

    packet.mkdir(parents=True)

    print(f"═══ Building {packet_name} ═══")

    # 1. Source snapshot (git archive)

    git_archive(tag, packet / "SOURCE")

    # 2. Copy trust anchors

    print("   copying trust anchors...")

    copy_required(ROOT / "docs" / "SIGNED_HASHES.txt",

                  packet / "TRUST" / "SIGNED_HASHES.txt")

    copy_required(ROOT / "docs" / "SIGNED_HASHES.txt.asc",

                  packet / "TRUST" / "SIGNED_HASHES.txt.asc")

    pubkey_src = sorted((ROOT / "docs").glob("public-key-*.asc"))

    if pubkey_src:

        copy_required(pubkey_src[0], packet / "TRUST" / "public-key.asc")

    # 3. Copy docs

    print("   copying docs...")

    for name in ("AUDITOR_GUIDE.md", "ANCHOR_WORM.md",

                 "CHAIN_OF_CUSTODY_SOP.md", "INCIDENT_RESPONSE.md",

                 "THREAT_MODEL.md", "GPG_KEY_MANAGEMENT.md",

                 "FINDINGS.md", "TRUST.md", "FUZZING.md",

                 f"RELEASE_{tag}.md"):

        src = ROOT / "docs" / name

        if src.exists():

            copy_required(src, packet / "DOCS" / name)

    # 4. Copy templates

    print("   writing README + verify scripts...")

    copy_required(TEMPLATES / "README.md", packet / "README.md")

    for name in ("VERIFY.sh", "VERIFY.ps1"):

        copy_required(TEMPLATES / name, packet / name)

        (packet / name).chmod(0o755)

    # 5. Manifest

    print("   computing manifest...")

    manifest = build_manifest(packet)

    (packet / "MANIFEST.json").write_text(

        json.dumps(manifest, indent=2), encoding="utf-8")

    print("   signing manifest...")

    sign_manifest(packet / "MANIFEST.json")

    # 6. Zip

    zip_path = out_dir / f"{packet_name}.zip"

    print(f"   zipping → {zip_path.name}")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:

        for p in sorted(packet.rglob("*")):

            if p.is_file():

                zf.write(p, p.relative_to(packet))

    print(f"\n✅ Packet: {zip_path}")

    print(f"   Size: {zip_path.stat().st_size // 1024} KB")

    print(f"   Files: {manifest['file_count']}")

    print(f"   Merkle: {manifest['merkle_root'][:32]}...")

    return zip_path

def main() -> int:

    ap = argparse.ArgumentParser()

    ap.add_argument("--tag", required=True)

    ap.add_argument("--out", default="dist")

    args = ap.parse_args()

    out = pathlib.Path(args.out)

    out.mkdir(parents=True, exist_ok=True)

    try:

        build_packet(args.tag, out)

    except subprocess.CalledProcessError as e:

        print(f"❌ {e}", file=sys.stderr); return 1

    return 0

if __name__ == "__main__":

    sys.exit(main())
