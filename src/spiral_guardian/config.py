"""Configuration and state paths.

NO IMPORT-TIME SIDE EFFECTS. v1.0.0 ran ``mkdir`` over ``/var/guardian/*`` at
module import, which raised PermissionError for an unprivileged user and meant
the server had never once started. Everything here is a function evaluated at
call time, so the environment can be changed (and monkeypatched in tests)
without reimporting, and directories are created lazily at first write.
"""

from __future__ import annotations

import os
from pathlib import Path

# Default state root. Replaces the v1.0.0 hardcoded /var/guardian, which
# required root. Nothing is created here — see ensure_dir().
DEFAULT_GUARDIAN_HOME = "~/.sovereign/guardian"

# Subdirectories under GUARDIAN_HOME, created on demand.
SUBDIRS = ("quarantine", "quarantine-metadata", "reports", "sbom", "baselines", "logs")


def guardian_home() -> Path:
    """Return the Guardian state root (not created)."""
    return Path(os.getenv("GUARDIAN_HOME", DEFAULT_GUARDIAN_HOME)).expanduser()


def guardian_dir(name: str) -> Path:
    """Return a subdirectory path under GUARDIAN_HOME (not created)."""
    if name not in SUBDIRS:
        raise ValueError(f"unknown guardian subdir {name!r}; known: {SUBDIRS}")
    return guardian_home() / name


def ensure_dir(name: str) -> Path:
    """Create and return a subdirectory under GUARDIAN_HOME.

    Lazy: called at first write, never at import.
    """
    path = guardian_dir(name)
    path.mkdir(parents=True, exist_ok=True)
    return path


# === Wazuh =================================================================
# NOT DEPLOYED on any Temple device as of 2026-08-10. These settings exist so
# the integration path stays wired; every Wazuh-backed capability gates on
# wazuh_credentials_present() and reports unavailable when it is False.


def wazuh_api_url() -> str:
    return os.getenv("WAZUH_API_URL", "https://wazuh-vm.tailnet.ts.net:55000")


def wazuh_user() -> str:
    return os.getenv("WAZUH_USER", "")


def wazuh_password() -> str:
    """Wazuh password. NO empty-string default that pretends to be a credential.

    v1.0.0 defaulted this to "" and then attempted authentication with it,
    which produced an auth error indistinguishable from a network failure.
    """
    return os.getenv("WAZUH_PASS", "")


def wazuh_credentials_present() -> bool:
    return bool(wazuh_user() and wazuh_password())


def tls_verify() -> bool:
    """TLS certificate verification for outbound HTTPS. Defaults to ON.

    v1.0.0 hardcoded ``verify=False`` on every httpx client. Verification can
    still be disabled for a self-signed lab Wazuh via GUARDIAN_INSECURE_TLS=1,
    but the choice is explicit, logged, and surfaced in the tool response.
    """
    return os.getenv("GUARDIAN_INSECURE_TLS", "").lower() not in ("1", "true", "yes")


# === Timeouts ==============================================================
# Every subprocess and HTTP call carries one. An unbounded call in a security
# tool is an availability bug.

DEFAULT_SUBPROCESS_TIMEOUT = 30.0
DEFAULT_HTTP_TIMEOUT = 15.0
PROBE_TIMEOUT = 1.0
