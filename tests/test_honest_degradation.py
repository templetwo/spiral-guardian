"""Every tool must degrade honestly when its backing instrument is absent.

The rule under test: a missing tool produces ``available: false`` plus a
reason. Not a crash, not an empty result that reads as clean, not a fabricated
finding. None of Wazuh, YARA, ClamAV, nmap, trivy or restic is installed on
this machine, so these are live degradation paths rather than mocks.
"""

from __future__ import annotations

import asyncio

import pytest

from spiral_guardian import config, tools, wazuh as wazuh_module
from spiral_guardian.result import Coverage, is_available
from spiral_guardian.runner import run, sudo_wrapper_capability, tool_capability


def test_absent_tool_reports_unavailable_with_reason():
    result = tool_capability("definitely-not-a-real-binary-xyz", "testing")
    assert result["available"] is False
    assert "not installed" in result["reason"]


def test_present_tool_reports_available_with_path():
    result = tool_capability("ls")
    assert result["available"] is True
    assert result["path"].endswith("/ls")


def test_run_with_missing_executable_returns_error_not_exception():
    result = run(["definitely-not-a-real-binary-xyz"])
    assert result["ok"] is False
    assert "not found" in result["error"]


def test_run_enforces_timeout():
    result = run(["sleep", "5"], timeout=0.3)
    assert result["timed_out"] is True
    assert result["ok"] is False


def test_run_reports_nonzero_exit_as_not_ok():
    result = run(["false"])
    assert result["ok"] is False
    assert result["exit_code"] != 0


# === Wazuh: gated BEFORE any network I/O ==================================


def test_wazuh_capability_unavailable_without_credentials():
    gate = wazuh_module.capability()
    assert gate["available"] is False
    assert "not_deployed" == gate["integration_status"]
    assert "No request was attempted" in gate["reason"]


def test_wazuh_get_makes_no_network_call_without_credentials(monkeypatch):
    """Proves the credential gate short-circuits BEFORE httpx is constructed."""
    import httpx

    def explode(*args, **kwargs):
        raise AssertionError("network call attempted without credentials")

    monkeypatch.setattr(httpx, "AsyncClient", explode)
    result = asyncio.run(wazuh_module.WazuhClient().get("/agents"))
    assert result["available"] is False


def test_tls_verification_defaults_to_on(monkeypatch):
    monkeypatch.delenv("GUARDIAN_INSECURE_TLS", raising=False)
    assert config.tls_verify() is True


def test_tls_verification_can_be_disabled_only_explicitly(monkeypatch):
    monkeypatch.setenv("GUARDIAN_INSECURE_TLS", "1")
    assert config.tls_verify() is False


def test_no_empty_string_credential_default(monkeypatch):
    """An empty password must never count as a credential."""
    monkeypatch.setenv("WAZUH_USER", "wazuh-wui")
    monkeypatch.setenv("WAZUH_PASS", "")
    assert config.wazuh_credentials_present() is False


# === per-tool degradation =================================================


def test_alerts_degrades_without_fabricating_a_clean_result():
    result = asyncio.run(tools.alerts_impl(severity="high", time_window="24h"))
    assert result["alerts"] == []
    assert result["total"] is None, "total must be None, not 0, when no source was reached"
    assert "not evidence that no alerts exist" in result["alerts_note"]
    assert result["coverage"]["complete"] is False
    assert result["source"]["available"] is False


def test_status_scores_only_from_collected_signals():
    result = asyncio.run(tools.status_impl())
    assert result["health_score"] is not None
    signals = {entry["signal"] for entry in result["health_score_basis"]}
    assert signals, "a score was emitted with no basis"
    assert "not a whole-infrastructure score" in result["health_score_note"]
    # Wazuh is absent on this machine, so coverage must say so.
    assert result["coverage"]["complete"] is False


def test_scan_reports_each_absent_scanner_separately():
    result = asyncio.run(
        tools.scan_impl(scan_type="full", target_path="~", include_clamav=True)
    )
    assert result["yara"]["available"] is False
    assert result["clamav"]["available"] is False
    assert result["vulnerabilities"]["available"] is False
    assert result["network"]["available"] is False
    assert "not a clean result" in result["findings_note"].lower()
    for name in ("yara", "clamav", "wazuh_vulnerability", "nmap"):
        assert name in result["coverage"]["unavailable"]


def test_scan_network_fallback_states_its_reduced_scope():
    result = asyncio.run(tools.scan_impl(scan_type="network"))
    assert result["network"]["available"] is False
    assert "no other host on the network was contacted" in result["network"]["fallback_scope"]


def test_supply_chain_audit_degrades_when_trivy_absent():
    result = asyncio.run(tools.audit_impl(audit_type="supply_chain", target_path="~"))
    assert result["supply_chain"]["available"] is False
    assert "trivy" in result["coverage"]["unavailable"]


def test_unknown_audit_type_is_rejected_not_silently_empty():
    result = asyncio.run(tools.audit_impl(audit_type="nonsense"))
    assert "unknown audit_type" in result["error"]
    assert result["coverage"]["complete"] is False


def test_quarantine_wrapper_absent_is_reported_not_hung():
    capability = sudo_wrapper_capability("quarantine")
    assert capability["available"] is False
    assert "not installed" in capability["reason"]
    result = asyncio.run(tools.quarantine_impl("list"))
    assert result["result"]["available"] is False


def test_quarantine_rejects_a_non_sha256_hash():
    result = asyncio.run(tools.quarantine_impl("isolate", "not-a-hash"))
    assert "SHA256" in result["error"]


def test_quarantine_requires_a_hash_for_destructive_actions():
    result = asyncio.run(tools.quarantine_impl("isolate", ""))
    assert "required" in result["error"]


def test_unknown_wrapper_is_refused():
    assert sudo_wrapper_capability("rm-rf-everything")["available"] is False


# === coverage semantics ===================================================


def test_coverage_is_incomplete_when_anything_is_unavailable():
    coverage = Coverage()
    coverage.check("a")
    assert coverage.complete is True
    coverage.skip("b", "absent")
    assert coverage.complete is False
    assert "COVERAGE INCOMPLETE" in coverage.statement()


def test_coverage_statement_names_what_was_missing():
    coverage = Coverage()
    coverage.skip("yara", "not installed")
    assert "yara: not installed" in coverage.statement()


def test_is_available_rejects_non_dicts_and_false_blocks():
    assert is_available({"available": True}) is True
    assert is_available({"available": False, "reason": "x"}) is False
    assert is_available(None) is False
    assert is_available("available") is False


@pytest.mark.parametrize(
    "tool_name",
    ["status_impl", "alerts_impl", "drift_impl", "mcp_audit_impl", "baseline_impl"],
)
def test_no_tool_raises_on_this_machine(tool_name):
    """Whatever is missing, the tool returns a payload rather than raising."""
    result = asyncio.run(getattr(tools, tool_name)())
    assert isinstance(result, dict)
    assert "coverage" in result
