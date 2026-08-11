"""Shared fixtures.

The autouse fixture is load-bearing: it redirects GUARDIAN_HOME into a pytest
tmp_path for EVERY test, so running the suite can never write into the real
~/.sovereign/guardian. A security tool's test suite writing to the production
state directory is the same class of mistake as a regression suite asserting
against a live store.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_guardian_home(tmp_path, monkeypatch):
    """Point GUARDIAN_HOME at a temporary directory for every test."""
    home = tmp_path / "guardian-home"
    monkeypatch.setenv("GUARDIAN_HOME", str(home))
    return home


@pytest.fixture(autouse=True)
def no_wazuh_credentials(monkeypatch):
    """Guarantee tests never inherit real Wazuh credentials from the shell."""
    monkeypatch.delenv("WAZUH_USER", raising=False)
    monkeypatch.delenv("WAZUH_PASS", raising=False)
    monkeypatch.delenv("GUARDIAN_INSECURE_TLS", raising=False)


@pytest.fixture
def plist_item():
    """Factory for a synthetic launch-item observation."""

    def _make(**overrides):
        item = {
            "path": "/tmp/synthetic/com.example.service.plist",
            "sha256": "0" * 64,
            "label": "com.example.service",
            "program_arguments": ["/usr/local/bin/example", "serve"],
            "declared_binary": "/usr/local/bin/example",
            "declared_binary_real": "/usr/local/bin/example",
            "declared_binary_exists": True,
            "environment_variables": {},
            "loaded": True,
            "launchd_state": {"pid": 999, "running": True, "last_exit_status": 0},
        }
        item.update(overrides)
        return item

    return _make


@pytest.fixture
def port_entry():
    """Factory for a synthetic listening-port observation."""

    def _make(port=11434, bind_scope="localhost", addresses=None, command="example"):
        return {
            "port": port,
            "bind_scope": bind_scope,
            "bind_scopes": [bind_scope],
            "addresses": addresses or [f"127.0.0.1:{port}"],
            "processes": [{"pid": 999, "command": command}],
            "seen_by": ["lsof", "netstat"],
            "owner_known": True,
        }

    return _make
