# core/executor.py (v1.4.2 — allowlist + path confinement + SSRF guard)
"""Executor with strict allowlist, path confinement, and SSRF guard.

v1.4.2 fixes:
  FIND-05: Strict CLI allowlist (no deny-list bypass via .exe/.cmd)
  FIND-06: Path traversal blocked via _resolve_within()
  FIND-07: SSRF guard (metadata IP always blocked; loopback/private gated)
"""
from __future__ import annotations
import importlib.util
import ipaddress
import pathlib
import socket
import subprocess
import time
import urllib.parse
from collections import defaultdict, deque
from typing import Any

MAX_TIMEOUT_SEC = 900
MAX_OUTPUT_CHARS = 2 * 1024 * 1024  # 2 MB cap

# ── CLI allowlist (FIND-05) ────────────────────────────────
# Only these binaries may be executed, under strict conditions.
_ALLOWED_CLI_BINS = {"python", "python3", "py", "node", "uv"}
_INTERPRETER_BINS = {"python", "python3", "py", "node"}

# Denied outright — even if later someone mistakenly adds to allowlist.
_DENIED_BINS = {
    "cmd", "powershell", "pwsh",
    "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh",
    "rm", "del", "rmdir", "erase", "format", "dd", "mkfs", "shutdown", "reboot",
    "curl", "wget", "nc", "ncat",
    "ssh", "scp", "sftp", "rsync",
    "npx", "uvx",              # supply-chain risk
    "perl", "ruby", "php",     # not needed for current skill set
    "regedit", "reg", "reg.exe",
    "sc", "net", "netsh",
}

# ── SSRF guard (FIND-07) ───────────────────────────────────
_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure metadata
    ipaddress.ip_address("169.254.170.2"),    # AWS ECS task
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
    ipaddress.ip_address("fd00:ec2::254"),    # AWS IPv6
}
_BLOCKED_NETS_LOCAL = [
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    )
]


class RateLimiter:
    """Sliding-window rate limiter per domain/skill."""

    def __init__(self, max_calls: int = 60, period_sec: float = 60.0):
        self.max_calls = max_calls
        self.period_sec = period_sec
        self._calls: dict[str, deque[float]] = defaultdict(deque)

    def acquire(self, key: str) -> bool:
        now = time.monotonic()
        window = self._calls[key]
        while window and now - window[0] > self.period_sec:
            window.popleft()
        if len(window) >= self.max_calls:
            return False
        window.append(now)
        return True


# ═══════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════

def _basename_ci(path: str) -> str:
    """Lowercase basename with common executable extensions stripped."""
    b = pathlib.Path(str(path)).name.lower()
    for ext in (".exe", ".cmd", ".bat", ".com", ".ps1"):
        if b.endswith(ext):
            return b[: -len(ext)]
    return b


def _is_allowed_bin(bin_path: str) -> bool:
    if not bin_path or "\x00" in str(bin_path):
        return False
    b = _basename_ci(bin_path)
    if b in _DENIED_BINS:
        return False
    return b in _ALLOWED_CLI_BINS


def _resolve_within(skill_dir: pathlib.Path, rel: str) -> pathlib.Path:
    """Resolve `rel` under `skill_dir`; raise on escape.

    Blocks: .., absolute paths, symlink escapes, null bytes.
    """
    if not isinstance(rel, str):
        rel = str(rel)
    if "\x00" in rel:
        raise ValueError("Null byte in path")
    p_rel = pathlib.Path(rel)
    if p_rel.is_absolute() or (len(rel) >= 2 and rel[1] == ":"):
        raise ValueError(f"Path traversal blocked (absolute path): {rel!r}")
    skill_dir = skill_dir.resolve()
    candidate = (skill_dir / p_rel).resolve()
    try:
        candidate.relative_to(skill_dir)
    except ValueError:
        raise ValueError(f"Path traversal blocked: {rel!r}")
    return candidate


def _validate_http_url(url: str, allow_local: bool = False) -> str:
    """Validate scheme + destination. Metadata IPs always blocked.

    NOTE: this does NOT prevent DNS rebinding (attacker-controlled domain
    that resolves to a safe IP at validation time and a metadata IP at
    request time). Mitigations: allow_redirects=False + network egress ACL
    at the org level. Documented in THREAT_MODEL.md §FIND-07.
    """
    if not isinstance(url, str):
        raise ValueError("URL must be str")
    if "\x00" in url:
        raise ValueError("Null byte in URL")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Scheme not allowed: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve host {host!r}: {e}")
    for _, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip in _METADATA_IPS:                 # always blocked
            raise ValueError(f"Cloud metadata IP blocked: {ip}")
        if not allow_local and any(ip in net for net in _BLOCKED_NETS_LOCAL):
            raise ValueError(f"Blocked destination IP: {ip}")
    return url


# ═══════════════════════════════════════════════════════════
# Executor
# ═══════════════════════════════════════════════════════════

class Executor:
    def __init__(
        self,
        sandbox: str | pathlib.Path = "sandbox",
        max_timeout: int = MAX_TIMEOUT_SEC,
        rate_limit_per_min: int = 60,
    ):
        self.sandbox = pathlib.Path(sandbox)
        self.sandbox.mkdir(parents=True, exist_ok=True)
        self.max_timeout = min(max_timeout, MAX_TIMEOUT_SEC)
        self.rate_limiter = RateLimiter(max_calls=rate_limit_per_min, period_sec=60.0)

    def _rate_key(self, skill: Any, args: dict[str, Any]) -> str:
        rt = getattr(skill, "runtime", None) or {}
        if rt.get("type") == "http" and "url" in rt:
            return urllib.parse.urlparse(rt["url"]).netloc or getattr(skill, "name", "skill")
        return getattr(skill, "name", "skill")

    def run(self, skill: Any, args: dict[str, Any]) -> dict[str, Any]:
        key = self._rate_key(skill, args)
        if not self.rate_limiter.acquire(key):
            return {"ok": False, "error": f"Rate limit exceeded for '{key}'"}

        rt = getattr(skill, "runtime", None) or {}
        t = rt.get("type", "python")
        if t == "cli":
            bin_path = rt.get("bin", "")
            if not _is_allowed_bin(bin_path):
                raise PermissionError(f"CLI binary not allowed: {bin_path!r}")

        try:
            if t == "python":
                return self._run_python(skill, args)
            if t == "cli":
                return self._run_cli(skill, args)
            if t == "http":
                return self._run_http(skill, args)
            return {"ok": False, "error": f"unsupported runtime: {t}"}
        except (ValueError, PermissionError) as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # ── python skill ──────────────────────────────────
    def _run_python(self, skill: Any, args: dict[str, Any]) -> dict[str, Any]:
        rt = skill.runtime
        skill_dir = (getattr(skill, "dir", None) or pathlib.Path(".")).resolve()
        entry = _resolve_within(skill_dir, rt["entry"])
        if not entry.is_file():
            raise ValueError(f"entry not found: {rt['entry']}")

        spec = importlib.util.spec_from_file_location(
            getattr(skill, "name", "skill").replace("-", "_"), entry
        )
        if spec is None or spec.loader is None:
            raise ValueError(f"Failed to load spec for {entry}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        res = mod.run(**args)
        return res if isinstance(res, dict) else {"ok": True, "result": res}

    # ── cli skill ─────────────────────────────────────
    def _run_cli(self, skill: Any, args: dict[str, Any]) -> dict[str, Any]:
        rt = skill.runtime
        bin_path = rt["bin"]
        if not _is_allowed_bin(bin_path):
            raise PermissionError(f"CLI binary not allowed: {bin_path!r}")

        skill_dir = (getattr(skill, "dir", None) or pathlib.Path(".")).resolve()
        if not pathlib.Path(bin_path).is_absolute() and ("/" in str(bin_path) or "\\" in str(bin_path)):
            bin_path = str(_resolve_within(skill_dir, bin_path))

        safe_defaults = {"query": "", "area": "", "limit": 50, **args}
        fmt_args: list[str] = []
        for a in rt.get("args", []):
            s = a.format(**safe_defaults) if isinstance(a, str) and "{" in a else str(a)
            if "\x00" in s:
                raise ValueError("Null byte in CLI arg")
            fmt_args.append(s)

        # interpreter safety: first non-flag arg must resolve within skill_dir
        if _basename_ci(bin_path) in _INTERPRETER_BINS:
            non_flags = [a for a in fmt_args if not a.startswith("-")]
            if not non_flags:
                raise ValueError("interpreter requires a script argument")
            _resolve_within(skill_dir, non_flags[0])  # raises on escape
        elif _basename_ci(bin_path) == "uv":
            # uv is only allowed as `uv run <script>` (not uvx, not --from)
            if not fmt_args or fmt_args[0] != "run":
                raise PermissionError("uv allowed only as `uv run <script>`")
            if any(a.startswith("--from") or a.startswith("--with") for a in fmt_args):
                raise PermissionError("uv --from/--with not allowed")
            non_flags = [a for a in fmt_args[1:] if not a.startswith("-")]
            if not non_flags:
                raise ValueError("uv run requires a script argument")
            _resolve_within(skill_dir, non_flags[0])

        cmd = [str(bin_path)] + fmt_args
        timeout = min(int(rt.get("timeout", 300)), self.max_timeout)
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=skill_dir,
            encoding="utf-8",
            errors="replace",
        )
        stdout_capped = (p.stdout or "")[:MAX_OUTPUT_CHARS][-8000:]
        stderr_capped = (p.stderr or "")[:MAX_OUTPUT_CHARS][-2000:]
        return {
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "stdout": stdout_capped,
            "stderr": stderr_capped,
        }

    # ── http skill ────────────────────────────────────
    def _run_http(self, skill: Any, args: dict[str, Any]) -> dict[str, Any]:
        rt = skill.runtime
        allow_local = bool(rt.get("allow_local", False))
        url = _validate_http_url(rt["url"], allow_local=allow_local)
        import requests
        timeout = min(int(rt.get("timeout", 120)), self.max_timeout)
        r = requests.post(
            url,
            json=args,
            headers=rt.get("headers", {}),
            timeout=timeout,
            allow_redirects=False,
        )
        try:
            return r.json()
        except ValueError:
            return {
                "ok": r.ok,
                "status": r.status_code,
                "body": r.text[-4000:],
            }
