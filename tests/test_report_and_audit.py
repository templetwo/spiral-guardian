"""Report branching and the two audit types v1.0.0 advertised but never ran."""

from __future__ import annotations

import asyncio

import pytest

from spiral_guardian import tools

REPORT_TYPES = ("summary", "detailed", "compliance", "incident")


@pytest.fixture(scope="module")
def reports():
    """Generate all four report types once; they are the expensive path."""
    return {name: asyncio.run(tools.report_impl(report_type=name)) for name in REPORT_TYPES}


def test_all_four_report_types_produce_different_content(reports):
    """v1.0.0 accepted four report types and branched on none of them."""
    bodies = {name: report["content"] for name, report in reports.items()}
    assert len(set(bodies.values())) == 4, "report_type does not change the output"


def test_report_types_have_different_sections(reports):
    sections = {name: tuple(report["sections"]) for name, report in reports.items()}
    assert len(set(sections.values())) == 4


def test_detailed_report_includes_drift_and_ports(reports):
    content = reports["detailed"]["content"]
    assert "Configuration drift" in content
    assert "Listening ports" in content


def test_compliance_report_is_a_control_table(reports):
    content = reports["compliance"]["content"]
    assert "| Control | State | Evidence |" in content
    assert "System Integrity Protection" in content
    assert "not a certified benchmark run" in content


def test_incident_report_states_that_no_alert_source_was_reached(reports):
    content = reports["incident"]["content"]
    assert "Critical alerts" in content
    assert "not evidence that no incident occurred" in content


def test_summary_report_is_the_shortest(reports):
    lengths = {name: len(report["content"]) for name, report in reports.items()}
    assert lengths["summary"] < lengths["detailed"]


def test_every_report_carries_a_coverage_statement(reports):
    for name, report in reports.items():
        assert "Coverage:" in report["content"], f"{name} report lacks coverage"
        assert report["coverage"]["complete"] is False  # Wazuh is absent


def test_unknown_report_type_is_rejected():
    result = asyncio.run(tools.report_impl(report_type="nonsense"))
    assert "unknown report_type" in result["error"]


def test_json_output_format_is_supported():
    result = asyncio.run(tools.report_impl(report_type="summary", output_format="json"))
    import json

    assert json.loads(result["content"])


def test_report_is_persisted(isolated_guardian_home):
    asyncio.run(tools.report_impl(report_type="summary"))
    saved = list((isolated_guardian_home / "reports").glob("report_summary_*.md"))
    assert saved, "report was not written to GUARDIAN_HOME"


# === audit network / permissions ==========================================


def test_audit_network_enumerates_ports_and_cross_checks():
    """v1.0.0 advertised this type and silently returned empty findings."""
    result = asyncio.run(tools.audit_impl(audit_type="network"))
    network = result["network"]
    assert network["count"] > 0
    assert "findings" in network
    assert "seen_by_netstat_only" in network["cross_check"]


def test_audit_network_reports_ports_it_could_not_attribute():
    result = asyncio.run(tools.audit_impl(audit_type="network"))
    ports = result["network"]["ports"]
    unowned = [entry for entry in ports if not entry.get("owner_known")]
    for entry in unowned:
        assert "owner_note" in entry
    if unowned:
        assert "port_ownership" in result["coverage"]["unavailable"]


def test_audit_permissions_returns_tcc_and_file_modes():
    """The other type v1.0.0 advertised and never implemented."""
    result = asyncio.run(tools.audit_impl(audit_type="permissions"))
    permissions = result["permissions"]
    assert "tcc_user" in permissions
    assert "tcc_system" in permissions
    assert permissions["file_modes"]["available"] is True
    assert "findings" in permissions


def test_audit_permissions_tcc_reports_availability_either_way():
    result = asyncio.run(tools.audit_impl(audit_type="permissions"))
    for key in ("tcc_user", "tcc_system"):
        block = result["permissions"][key]
        assert "available" in block
        if not block["available"]:
            assert block["reason"], f"{key} unavailable without a reason"


def test_audit_permissions_explains_tcc_readability():
    result = asyncio.run(tools.audit_impl(audit_type="permissions"))
    assert "Full Disk Access" in result["permissions"]["tcc_note"]


def test_secrets_audit_runs_gitleaks_and_redacts_values(tmp_path):
    """gitleaks IS installed here, so this exercises a real scanner."""
    target = tmp_path / "repo"
    target.mkdir()
    (target / "config.py").write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    )
    result = asyncio.run(tools.audit_impl(audit_type="secrets", target_path=str(target)))
    secrets = result["secrets"]
    assert secrets["available"] is True
    assert "gitleaks" in result["coverage"]["checked"]
    for leak in secrets["leaks"]:
        assert leak["secret_value"] == "REDACTED — not emitted by design"
