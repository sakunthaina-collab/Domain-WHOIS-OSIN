#!/usr/bin/env python3
"""Generate ephemeral GNUPGHOME for CI/testing.

Usage:
    python scripts/generate_mock_keyring.py --outdir /tmp/gpg-test
Prints JSON with: gpg_home, fingerprint, env
"""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys

BATCH = """%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: Test Signer
Name-Email: test@example.org
Expire-Date: 1d
%commit
"""


def _get_gpg_bin() -> str | None:
    for name in ("gpg", "gpg2", "gpg.exe", "gpg2.exe"):
        p = shutil.which(name)
        if p:
            return p
    if os.name == "nt":
        for c in (
            r"C:\Program Files\Git\usr\bin\gpg.exe",
            r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
            r"C:\Program Files\GnuPG\bin\gpg.exe",
        ):
            if pathlib.Path(c).exists():
                return c
    return None


def main(outdir: str) -> int:
    gpg_bin = _get_gpg_bin()
    if not gpg_bin:
        print("gpg not installed", file=sys.stderr)
        return 1

    home = pathlib.Path(outdir)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)

    try:
        subprocess.run(
            [gpg_bin, "--batch", "--generate-key"],
            input=BATCH,
            text=True,
            env=env,
            capture_output=True,
            check=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as e:
        print(f"key generation failed: {e.stderr}", file=sys.stderr)
        return 1

    out = subprocess.run(
        [gpg_bin, "--list-keys", "--with-colons"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    fingerprint = next(
        (l.split(":")[9] for l in out.splitlines() if l.startswith("fpr:")),
        None,
    )
    if not fingerprint:
        print("could not extract fingerprint", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "gpg_home": str(home),
                "fingerprint": fingerprint,
                "env": {
                    "GNUPGHOME": str(home),
                    "ANCHOR_GPG_KEY": fingerprint,
                },
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--outdir", default="/tmp/gpg-test")
    sys.exit(main(p.parse_args().outdir))
