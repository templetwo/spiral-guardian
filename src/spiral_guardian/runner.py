"""Subprocess execution and capability detection.

Two rules enforced here:

1. Every call carries a timeout. A hung security check is a security failure.
2. A tool that is not installed is DETECTED, not discovered by crash. Callers
   ask ``tool_capability()`` first and get an ``unavailable`` block they can
   return verbatim.

sudo is always invoked with ``-n`` (non-interactive). v1.0.0 called bare
``sudo``, which on a machine without the NOPASSWD sudoers entry installed
blocks forever on a password prompt that no MCP client can answer.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .config import DEFAULT_SUBPROCESS_TIMEOUT
from .result import available, unavailable

# Wrapper scripts reachable via sudo. Only entries that actually exist as
# scripts in this repo are listed; see config/guardian.sudoers, which was
# trimmed to match in v1.1.0.
SUDO_WRAPPERS = {"yara-scan", "quarantine"}

WRAPPER_INSTALL_DIR = "/usr/local/bin"


def run(
    cmd: list[str],
    timeout: float = DEFAULT_SUBPROCESS_TIMEOUT,
    input_text: str | None = None,
    env: dict | None = None,
) -> dict:
    """Run a command with a hard timeout. Never raises.

    Returns a dict with ``ok`` set only when the process ran AND exited 0.
    ``ok`` is deliberately not inferred from exit code alone at call sites —
    exit 0 from a missing interpreter is a documented trap in this house.
    """
    result = {
        "cmd": list(cmd),
        "ok": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "error": None,
    }
    executable = shutil.which(cmd[0]) if cmd else None
    if executable is None and not (cmd and Path(cmd[0]).is_file()):
        result["error"] = f"executable not found: {cmd[0] if cmd else '(empty)'}"
        return result
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, never shell=True
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            env={**os.environ, **(env or {})} if env else None,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        result["error"] = f"timeout after {timeout}s"
        return result
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    result["exit_code"] = proc.returncode
    result["stdout"] = (proc.stdout or "").strip()
    result["stderr"] = (proc.stderr or "").strip()
    result["ok"] = proc.returncode == 0
    return result


def resolve_tool(name: str) -> str | None:
    """Absolute path of `name` on PATH, or None. Symlinks NOT resolved here."""
    return shutil.which(name)


def real_path(path: str | None) -> str | None:
    """Fully resolve a path through symlinks. None-safe.

    Load-bearing for drift detection: /usr/local/bin/ollama is a symlink into
    /Applications/Ollama.app, so a naive string comparison of a plist's
    declared binary against the running process's executable reports a
    mismatch that does not exist.
    """
    if not path:
        return None
    try:
        return str(Path(path).resolve())
    except OSError:
        return path


def tool_capability(name: str, purpose: str = "") -> dict:
    """Presence check for an external tool, as an available/unavailable block."""
    path = resolve_tool(name)
    if path is None:
        suffix = f" (needed for {purpose})" if purpose else ""
        return unavailable(f"{name} is not installed on this machine{suffix}", tool=name)
    return available(tool=name, path=path, real_path=real_path(path))


def sudo_wrapper_capability(script: str) -> dict:
    """Check a privilege-separated wrapper before attempting to invoke it.

    Reports unavailable for: unknown script, wrapper not installed, or sudo
    rights not granted — three distinct reasons, never collapsed into one.
    """
    if script not in SUDO_WRAPPERS:
        return unavailable(
            f"wrapper {script!r} is not in the allowlist {sorted(SUDO_WRAPPERS)}",
            script=script,
        )
    path = f"{WRAPPER_INSTALL_DIR}/guardian-{script}.sh"
    if not Path(path).is_file():
        return unavailable(
            f"wrapper not installed at {path} (repo ships the source in scripts/; "
            "installation is a privileged step and is NOT performed by this tool)",
            script=script,
            expected_path=path,
        )
    probe = run(["sudo", "-n", "-l", path], timeout=5.0)
    if not probe["ok"]:
        return unavailable(
            f"sudo rights for {path} are not granted non-interactively "
            "(install config/guardian.sudoers to enable)",
            script=script,
            expected_path=path,
        )
    return available(script=script, path=path)


def run_wrapper(script: str, *args: object, timeout: float = 300.0) -> dict:
    """Execute a privilege-separated wrapper, or report why it could not run."""
    capability = sudo_wrapper_capability(script)
    if not capability.get("available"):
        return capability
    cmd = ["sudo", "-n", capability["path"], *[str(a) for a in args]]
    outcome = run(cmd, timeout=timeout)
    return available(script=script, **outcome)
