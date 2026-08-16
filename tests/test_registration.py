"""Server construction, tool registration, and the no-side-effects rule."""

from __future__ import annotations

import asyncio
import importlib
import os

from spiral_guardian import config

EXPECTED_TOOLS = {
    "spiral_guardian_status",
    "spiral_guardian_alerts",
    "spiral_guardian_drift",
    "spiral_guardian_baseline",
    "spiral_guardian_audit",
    "spiral_guardian_mcp_audit",
    "spiral_guardian_scan",
    "spiral_guardian_report",
    "spiral_guardian_quarantine",
}


def _tool_names():
    from spiral_guardian.server import guardian

    return {tool.name for tool in asyncio.run(guardian.list_tools())}


def test_all_nine_tools_are_registered():
    assert _tool_names() == EXPECTED_TOOLS


def test_every_tool_has_a_description():
    from spiral_guardian.server import guardian

    for tool in asyncio.run(guardian.list_tools()):
        assert tool.description, f"{tool.name} has no description"
        assert len(tool.description) > 40, f"{tool.name} description is too thin"


def test_every_tool_has_an_input_schema():
    from spiral_guardian.server import guardian

    for tool in asyncio.run(guardian.list_tools()):
        assert tool.input_schema is not None


def test_quarantine_is_annotated_destructive():
    from spiral_guardian.server import guardian

    tools = {tool.name: tool for tool in asyncio.run(guardian.list_tools())}
    assert tools["spiral_guardian_quarantine"].annotations.destructive_hint is True
    assert tools["spiral_guardian_quarantine"].annotations.read_only_hint is False
    assert tools["spiral_guardian_drift"].annotations.read_only_hint is True


def test_import_creates_no_directories(tmp_path, monkeypatch):
    """v1.0.0 ran mkdir over /var/guardian at import and could not start."""
    home = tmp_path / "never-created"
    monkeypatch.setenv("GUARDIAN_HOME", str(home))
    for module in ("spiral_guardian.server", "spiral_guardian.tools", "spiral_guardian.config"):
        importlib.reload(importlib.import_module(module))
    assert not home.exists(), "importing the package created state directories"


def test_guardian_home_is_read_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_HOME", str(tmp_path / "custom"))
    assert config.guardian_home() == tmp_path / "custom"


def test_guardian_home_defaults_under_sovereign(monkeypatch):
    monkeypatch.delenv("GUARDIAN_HOME", raising=False)
    assert config.guardian_home() == (
        __import__("pathlib").Path("~/.sovereign/guardian").expanduser()
    )


def test_ensure_dir_creates_lazily_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_HOME", str(tmp_path / "lazy"))
    assert not (tmp_path / "lazy").exists()
    created = config.ensure_dir("reports")
    assert created.is_dir()
    assert config.ensure_dir("reports") == created


def test_unknown_subdir_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        config.guardian_dir("../../etc")


def test_no_var_guardian_path_literal_remains_in_python_sources():
    """The hardcoded root that made v1.0.0 unstartable must be gone.

    Matches the QUOTED form only: a path used by code is a string literal.
    Prose mentions of /var/guardian in comments explaining why it was removed
    are documentation, not a defect — an earlier version of this test failed
    on its own changelog note.
    """
    import pathlib

    source_root = pathlib.Path(__file__).resolve().parent.parent / "src"
    offenders = [
        path.name for path in source_root.rglob("*.py")
        if '"/var/guardian' in path.read_text() or "'/var/guardian" in path.read_text()
    ]
    assert offenders == []


def test_backward_compatible_shim_still_imports():
    module = importlib.import_module("spiral_guardian_mcp")
    assert hasattr(module, "guardian")
    assert hasattr(module, "mount_guardian")


def test_mount_helper_refuses_an_incompatible_host():
    import pytest

    from spiral_guardian_mcp import mount_guardian

    with pytest.raises(TypeError):
        mount_guardian(object())


def test_spoke_agent_registers_its_tools():
    from spiral_guardian.agent import agent

    names = {tool.name for tool in asyncio.run(agent.list_tools())}
    assert names == {"local_status", "local_scan"}


def test_environment_is_not_mutated_by_import():
    assert os.getenv("GUARDIAN_HOME") is not None  # set by the autouse fixture
