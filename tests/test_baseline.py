"""Baseline capture and diffing.

The distinction under test throughout: ``changed`` versus
``not_collected_this_run``. Collapsing them would mean an instrument that went
missing gets reported as a security change that never happened — the same
fail-open shape in a new costume.
"""

from __future__ import annotations

import asyncio
import json

from spiral_guardian import tools
from spiral_guardian.evaluate import diff_baseline, diff_fingerprints, fingerprint_component
from spiral_guardian.result import available, unavailable


def _baseline(components):
    return {"version": 1, "timestamp": "2026-08-10T00:00:00Z", "components": components}


def _ports(entries):
    return available(ports=entries, count=len(entries), cross_check={}, lan_address={})


def test_diff_fingerprints_detects_all_three_change_kinds():
    difference = diff_fingerprints(
        {"a": "1", "b": "2", "c": "3"}, {"a": "1", "b": "CHANGED", "d": "4"}
    )
    assert [entry["key"] for entry in difference["added"]] == ["d"]
    assert [entry["key"] for entry in difference["removed"]] == ["c"]
    assert difference["changed"][0]["key"] == "b"
    assert difference["changed"][0]["from"] == "2"
    assert difference["changed"][0]["to"] == "CHANGED"
    assert difference["change_count"] == 3


def test_identical_state_reports_unchanged():
    entries = [{"port": 8100, "bind_scope": "localhost", "processes": [{"command": "python"}]}]
    result = diff_baseline(
        _baseline({"listening_ports": _ports(entries)}),
        _baseline({"listening_ports": _ports(entries)}),
    )
    assert result["components"]["listening_ports"]["status"] == "unchanged"
    assert result["total_changes"] == 0
    assert result["comparable"] is True


def test_bind_scope_change_is_detected():
    """POSITIVE CONTROL: a port going localhost -> wildcard must be caught."""
    before = [{"port": 11434, "bind_scope": "localhost", "processes": [{"command": "ollama"}]}]
    after = [{"port": 11434, "bind_scope": "wildcard", "processes": [{"command": "ollama"}]}]
    result = diff_baseline(_baseline({"listening_ports": _ports(before)}),
                           _baseline({"listening_ports": _ports(after)}))
    assert result["components"]["listening_ports"]["status"] == "changed"
    assert "listening_ports" in result["changed_components"]


def test_uncollected_component_is_not_reported_as_changed():
    """The key distinction. A missing instrument is a coverage gap."""
    before = _baseline({"listening_ports": _ports([{"port": 1, "bind_scope": "localhost", "processes": []}])})
    after = _baseline({"listening_ports": unavailable("lsof is not installed")})
    result = diff_baseline(before, after)
    component = result["components"]["listening_ports"]
    assert component["status"] == "not_collected_this_run"
    assert "lsof" in component["reason"]
    assert result["changed_components"] == []
    assert result["comparable"] is False
    assert "INCOMPLETE" in result["summary"]


def test_new_component_reports_no_prior_baseline():
    result = diff_baseline(_baseline({}), _baseline({"firewall": available(enabled=True, stealth_enabled=True)}))
    assert result["components"]["firewall"]["status"] == "no_prior_baseline"


def test_plist_hash_change_is_detected():
    """A LaunchAgent being modified must show up as a change."""
    def items(digest):
        return available(items=[{"path": "/tmp/a.plist", "sha256": digest}], count=1)

    result = diff_baseline(_baseline({"launch_items": items("a" * 64)}),
                           _baseline({"launch_items": items("b" * 64)}))
    assert result["components"]["launch_items"]["status"] == "changed"


def test_unreadable_plist_is_fingerprinted_as_unreadable_not_absent():
    block = available(items=[{"path": "/tmp/x.plist", "sha256": None, "parse_error": "boom"}], count=1)
    fingerprint = fingerprint_component("launch_items", block)
    assert "UNREADABLE" in fingerprint["plist:/tmp/x.plist"]


def test_firewall_toggle_is_detected():
    result = diff_baseline(
        _baseline({"firewall": available(enabled=True, stealth_enabled=True)}),
        _baseline({"firewall": available(enabled=False, stealth_enabled=True)}),
    )
    assert result["components"]["firewall"]["status"] == "changed"


def test_tcc_grant_addition_is_detected():
    def tcc(clients):
        return available(grants={"Screen Recording": [
            {"client": name, "granted": True} for name in clients
        ]})

    result = diff_baseline(_baseline({"tcc_user": tcc(["com.a"])}),
                           _baseline({"tcc_user": tcc(["com.a", "com.evil"])}))
    assert result["components"]["tcc_user"]["status"] == "changed"


def test_fingerprint_of_unavailable_component_is_none():
    assert fingerprint_component("firewall", unavailable("nope")) is None


# === live capture ==========================================================


def test_baseline_captures_real_state_and_persists_it(isolated_guardian_home):
    result = asyncio.run(tools.baseline_impl(device="pytest"))
    assert result["components_captured"], "no component captured any real data"
    saved = isolated_guardian_home / "baselines" / "baseline_pytest.json"
    assert saved.is_file()
    stored = json.loads(saved.read_text())
    # v1.0.0 wrote {"captured": true} and captured nothing.
    ports = stored["components"]["listening_ports"]
    assert ports["available"] is True
    assert isinstance(ports["ports"], list)
    assert ports["count"] > 0
    assert "captured" not in ports


def test_first_run_says_nothing_was_compared():
    result = asyncio.run(tools.baseline_impl(device="pytest-fresh"))
    assert result["comparison"] is None
    assert "Nothing was compared" in result["comparison_note"]


def test_second_run_compares_against_the_stored_baseline():
    asyncio.run(tools.baseline_impl(device="pytest-twice"))
    second = asyncio.run(tools.baseline_impl(device="pytest-twice"))
    assert second["comparison"] is not None
    assert "components" in second["comparison"]
    assert second["compared_against"]["timestamp"]


def test_unknown_component_is_an_error_not_a_silent_skip():
    result = asyncio.run(tools.baseline_impl(components=["not_a_component"], device="pytest-bad"))
    assert "not_a_component" in result["coverage"]["errors"]
