"""Pytest fixtures for GPG-signed anchor tests."""
from __future__ import annotations
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import uuid
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.gpg_signer import GPGSigner, _find_gpg, _to_gpg_path

BATCH = """%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: Test Signer
Name-Email: test@example.org
Expire-Date: 1d
%commit
"""


@pytest.fixture(scope="session")
def _base_gpg_keyring():
    gpg_bin = _find_gpg()
    if not gpg_bin:
        pytest.skip("gpg binary not available")

    base_dir = pathlib.Path(tempfile.gettempdir()) / f"gpg_base_{uuid.uuid4().hex[:8]}"
    base_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    gpg_home_str = _to_gpg_path(base_dir, gpg_bin)

    env = os.environ.copy()
    env["GNUPGHOME"] = gpg_home_str
    gpg_dir = str(pathlib.Path(gpg_bin).parent)
    if gpg_dir not in env.get("PATH", ""):
        env["PATH"] = f"{gpg_dir}{os.pathsep}{env.get('PATH', '')}"

    try:
        subprocess.run(
            [gpg_bin, "--batch", "--generate-key"],
            input=BATCH,
            text=True,
            env=env,
            check=True,
            capture_output=True,
            timeout=120,
        )
        out = subprocess.run(
            [gpg_bin, "--list-keys", "--with-colons"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        shutil.rmtree(base_dir, ignore_errors=True)
        pytest.skip(f"gpg keygen failed: {e}")

    fingerprint = next(
        (l.split(":")[9] for l in out.splitlines() if l.startswith("fpr:")),
        None,
    )
    assert fingerprint, "could not extract fingerprint"
    yield {
        "base_dir": base_dir,
        "fingerprint": fingerprint,
        "gpg_bin": gpg_bin,
    }
    shutil.rmtree(base_dir, ignore_errors=True)


@pytest.fixture
def gpg_keyring(_base_gpg_keyring):
    """Isolated ephemeral GNUPGHOME per test."""
    gpg_bin = _base_gpg_keyring["gpg_bin"]
    home_dir = pathlib.Path(tempfile.gettempdir()) / f"gpg_{uuid.uuid4().hex[:8]}"
    shutil.copytree(_base_gpg_keyring["base_dir"], home_dir)
    gpg_home_str = _to_gpg_path(home_dir, gpg_bin)

    env = os.environ.copy()
    env["GNUPGHOME"] = gpg_home_str
    gpg_dir = str(pathlib.Path(gpg_bin).parent)
    if gpg_dir not in env.get("PATH", ""):
        env["PATH"] = f"{gpg_dir}{os.pathsep}{env.get('PATH', '')}"

    yield {
        "gpg_home": gpg_home_str,
        "home_dir": home_dir,
        "fingerprint": _base_gpg_keyring["fingerprint"],
        "gpg_bin": gpg_bin,
        "env": env,
    }
    shutil.rmtree(home_dir, ignore_errors=True)


@pytest.fixture
def gpg_signer(gpg_keyring):
    return GPGSigner(
        key_id=gpg_keyring["fingerprint"],
        gpg_home=gpg_keyring["gpg_home"],
        gpg_bin=gpg_keyring["gpg_bin"],
        strict=True,
    )
