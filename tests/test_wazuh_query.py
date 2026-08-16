"""time_window and query construction.

Wazuh is not deployed, so the live path can never prove that ``time_window``
is honored. Extracting the query builder makes it provable as a unit — which
is the point: v1.0.0 accepted the parameter and never used it, and no
end-to-end test on this machine could ever have caught that.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from spiral_guardian.wazuh import build_alert_query, parse_time_window


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30m", timedelta(minutes=30)),
        ("24h", timedelta(hours=24)),
        ("7d", timedelta(days=7)),
        ("2w", timedelta(weeks=2)),
        ("90s", timedelta(seconds=90)),
    ],
)
def test_parse_time_window_valid(text, expected):
    assert parse_time_window(text) == expected


@pytest.mark.parametrize("text", ["", "h", "abc", "24x", "-5d", "0h", None, 24])
def test_parse_time_window_rejects_garbage(text):
    assert parse_time_window(text) is None


def test_time_window_is_actually_applied_to_the_query():
    """The regression v1.0.0 shipped: time_window accepted, never used."""
    now = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
    query = build_alert_query(severity="high", time_window="24h", now=now)
    assert query["time_window_applied"] is True
    assert "timestamp>2026-08-09T12:00:00Z" in query["params"]["q"]


def test_different_windows_produce_different_queries():
    now = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
    day = build_alert_query(time_window="24h", now=now)["params"]["q"]
    week = build_alert_query(time_window="7d", now=now)["params"]["q"]
    assert day != week


def test_unparseable_window_is_reported_not_silently_dropped():
    query = build_alert_query(time_window="banana")
    assert query["time_window_applied"] is False
    assert "NO time filter was applied" in query["time_window_reason"]
    assert "timestamp>" not in query["params"]["q"]


@pytest.mark.parametrize(
    ("severity", "level"),
    [("low", 3), ("medium", 7), ("high", 10), ("critical", 12), ("unknown", 7)],
)
def test_severity_maps_to_rule_level(severity, level):
    query = build_alert_query(severity=severity)
    assert f"rule.level>={level}" in query["params"]["q"]
    assert query["severity_min_level"] == level


def test_device_filter_is_applied_only_when_specified():
    assert "agent.name" not in build_alert_query(device="all")["params"]["q"]
    assert "agent.name=mac-studio" in build_alert_query(device="mac-studio")["params"]["q"]


def test_limit_and_sort_are_carried_through():
    params = build_alert_query(limit=42)["params"]
    assert params["limit"] == 42
    assert params["sort"] == "-timestamp"
