# core/gpg_signer.py
"""GPG signing and verification (subprocess-based, no extra dependencies).

Design goals:
  - Zero pip dependencies (uses system `gpg` binary)
  - Strict mode: fail hard if gpg unavailable (production default)
  - Non-strict: fall back to unsigned, log warning (dev default)
  - Supports detached signatures (.asc) and signed git tags
"""
from __future__ import annotations
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Optional


class GPGError(RuntimeError):
    pass


def _to_gpg_path(p: str | pathlib.Path, gpg_bin: Optional[str] = None) -> str:
    """Convert Windows path to MSYS2 POSIX path when using Git-for-Windows gpg.exe."""
    s = str(p)
    if os.name == "nt" and gpg_bin and "usr" in gpg_bin.lower():
        if s.startswith("/"):
            return s
        try:
            resolved = pathlib.Path(s).resolve()
            temp_root = pathlib.Path(tempfile.gettempdir()).resolve()
            try:
                rel = resolved.relative_to(temp_root)
                return "/tmp/" + str(rel).replace("\\", "/")
            except ValueError:
                pass
            posix = str(resolved).replace("\\", "/")
            if len(posix) >= 2 and posix[1] == ":":
                return f"/{posix[0].lower()}{posix[2:]}"
        except Exception:
            pass
        s = s.replace("\\", "/")
        if len(s) >= 2 and s[1] == ":":
            return f"/{s[0].lower()}{s[2:]}"
    return s


class GPGSigner:
    def __init__(
        self,
        key_id: Optional[str] = None,
        gpg_home: Optional[str] = None,
        passphrase: Optional[str] = None,
        strict: bool = True,
        gpg_bin: Optional[str] = None,
    ):
        self.key_id = key_id or os.environ.get("ANCHOR_GPG_KEY")
        self.gpg_home = gpg_home or os.environ.get("GNUPGHOME")
        self.passphrase = passphrase or os.environ.get("ANCHOR_GPG_PASSPHRASE")
        self.strict = strict
        self.gpg_bin = gpg_bin if gpg_bin is not None else _find_gpg()

    # ── availability ───────────────────────────────────────
    def is_available(self) -> bool:
        return self.gpg_bin is not None

    def require(self) -> None:
        """Raise if gpg not available in strict mode (no-op in non-strict mode)."""
        if not self.is_available() and self.strict:
            raise GPGError(
                "gpg binary not found. Install: "
                "Windows->GPG4Win / Git for Windows, macOS->brew install gnupg, "
                "Linux->apt install gnupg"
            )

    def key_fingerprint(self) -> Optional[str]:
        """Return full fingerprint of signing key, or None."""
        if not self.is_available():
            return None
        cmd = ["--with-colons", "--fingerprint"]
        if self.key_id:
            cmd.append(self.key_id)
        try:
            out = self._run(cmd)
        except GPGError:
            return None
        for line in out.splitlines():
            if line.startswith("fpr:"):
                parts = line.split(":")
                if len(parts) > 9 and parts[9]:
                    return parts[9]
        return None

    # ── detached signature ─────────────────────────────────
    def sign_file(self, path: pathlib.Path | str) -> Optional[pathlib.Path]:
        """Create detached ASCII-armored signature at <path>.asc.

        Returns path to .asc, or None if gpg unavailable and non-strict.
        """
        if not self.is_available():
            if self.strict:
                raise GPGError("gpg not available (strict mode)")
            return None
        path = pathlib.Path(path).resolve()
        sig = path.with_suffix(path.suffix + ".asc")
        args = [
            "--batch",
            "--yes",
            "--armor",
            "--detach-sign",
            "--output",
            _to_gpg_path(sig, self.gpg_bin),
        ]
        if self.key_id:
            args += ["--local-user", self.key_id]
        if self.passphrase is not None:
            args += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        args.append(_to_gpg_path(path, self.gpg_bin))
        self._run(args, stdin=self.passphrase, check=True)
        return sig

    def verify_file(
        self, sig_path: pathlib.Path | str, original_path: pathlib.Path | str
    ) -> tuple[bool, str]:
        """Verify detached signature. Return (ok, human-readable detail)."""
        if not self.is_available():
            return False, "gpg not available"
        sig_p = pathlib.Path(sig_path).resolve()
        orig_p = pathlib.Path(original_path).resolve()
        try:
            out = self._run(
                [
                    "--status-fd",
                    "1",
                    "--verify",
                    _to_gpg_path(sig_p, self.gpg_bin),
                    _to_gpg_path(orig_p, self.gpg_bin),
                ]
            )
        except GPGError as e:
            return False, str(e)
        return _parse_verify_status(out)

    # ── signed git tag ─────────────────────────────────────
    def sign_git_tag(
        self,
        tag_name: str,
        message: str,
        work_dir: Optional[pathlib.Path | str] = None,
    ) -> bool:
        """Create GPG-signed git tag. Returns True on success.

        Falls back to annotated (-a) tag if gpg unavailable AND non-strict.
        """
        if not self.is_available():
            if self.strict:
                raise GPGError("gpg not available; cannot sign git tag")
            return self._fallback_annotated(tag_name, message, work_dir)

        gpg_prog = str(self.gpg_bin).replace("\\", "/")
        cmd = ["git", "-c", f"gpg.program={gpg_prog}", "tag", "-s", "-f"]
        if self.key_id:
            cmd += ["-u", self.key_id]
        cmd += [tag_name, "-m", message]

        try:
            self._run_shell(cmd, cwd=work_dir, check=True)
            return True
        except GPGError:
            if self.strict:
                raise
            return self._fallback_annotated(tag_name, message, work_dir)

    def verify_git_tag(
        self, tag_name: str, work_dir: Optional[pathlib.Path | str] = None
    ) -> tuple[bool, str]:
        """Verify signed tag. Return (ok, detail)."""
        cmd = ["git"]
        if self.gpg_bin:
            gpg_prog = str(self.gpg_bin).replace("\\", "/")
            cmd += ["-c", f"gpg.program={gpg_prog}"]
        cmd += ["tag", "-v", tag_name]
        try:
            out = self._run_shell(cmd, cwd=work_dir)
        except GPGError as e:
            return False, str(e)
        if "Good signature" in out or "GOODSIG" in out:
            return True, "valid signed tag (Good signature)"
        if "BAD signature" in out or "BADSIG" in out:
            return False, "BAD signature on tag"
        return False, f"signature verification failed: {out[:200]}"

    # ── internals ──────────────────────────────────────────
    def _fallback_annotated(
        self, tag: str, msg: str, work_dir: Optional[pathlib.Path | str]
    ) -> bool:
        try:
            self._run_shell(
                ["git", "tag", "-a", "-f", tag, "-m", msg + " [UNSIGNED]"],
                cwd=work_dir,
                check=True,
            )
            return True
        except GPGError:
            return False

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        if self.gpg_home:
            env["GNUPGHOME"] = _to_gpg_path(self.gpg_home, self.gpg_bin)
        if self.gpg_bin:
            gpg_dir = str(pathlib.Path(self.gpg_bin).parent)
            curr_path = env.get("PATH", "")
            if gpg_dir not in curr_path:
                env["PATH"] = f"{gpg_dir}{os.pathsep}{curr_path}" if curr_path else gpg_dir
        return env

    def _run(self, args: list[str], stdin: Optional[str] = None, check: bool = False) -> str:
        env = self._build_env()
        try:
            p = subprocess.run(
                [str(self.gpg_bin)] + args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                input=stdin,
                env=env,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            raise GPGError(f"gpg timeout: {args[:3]}")
        if check and p.returncode != 0:
            raise GPGError(f"gpg failed ({p.returncode}): {(p.stderr or p.stdout)[:300]}")
        return (p.stdout or "") + "\n" + (p.stderr or "")

    def _run_shell(
        self,
        args: list[str],
        cwd: Optional[pathlib.Path | str] = None,
        check: bool = False,
    ) -> str:
        env = self._build_env()
        try:
            p = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(cwd) if cwd else None,
                env=env,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            raise GPGError(f"cmd timeout: {args[:3]}")
        if check and p.returncode != 0:
            raise GPGError(f"cmd failed ({p.returncode}): {(p.stderr or p.stdout)[:300]}")
        return (p.stdout or "") + "\n" + (p.stderr or "")


# ── helpers ────────────────────────────────────────────────
def _find_gpg() -> Optional[str]:
    if not os.environ.get("PATH"):
        return None
    for name in ("gpg", "gpg2", "gpg.exe", "gpg2.exe"):
        path = shutil.which(name)
        if path:
            return path
    if os.name == "nt":
        candidates = [
            r"C:\Program Files\Git\usr\bin\gpg.exe",
            r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
            r"C:\Program Files\GnuPG\bin\gpg.exe",
        ]
        for c in candidates:
            if pathlib.Path(c).exists():
                return c
    return None


def _parse_verify_status(output: str) -> tuple[bool, str]:
    for line in output.splitlines():
        if "[GNUPG:] GOODSIG" in line:
            return True, line.strip()
        if "[GNUPG:] BADSIG" in line:
            return False, "BAD signature"
        if "[GNUPG:] NO_PUBKEY" in line:
            return False, "public key not found (cannot verify)"
        if "[GNUPG:] ERRSIG" in line:
            return False, f"error verifying: {line.strip()}"
    if "Good signature" in output:
        return True, "Good signature"
    if "BAD signature" in output:
        return False, "BAD signature"
    return False, "no signature status in gpg output"
