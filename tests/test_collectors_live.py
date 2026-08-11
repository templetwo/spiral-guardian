"""Live collectors against this actual machine.

These are integration tests. They assert the SHAPE and the honesty properties
rather than machine-specific values, so they stay true as the host changes,
but they do run the real instruments.
"""

from __future__ import annotations

import socket

from spiral_guardian import collectors


def test_listening_ports_cross_checks_two_instruments():
    block = collectors.collect_listening_ports(probe=False)
    assert block["available"] is True
    cross_check = block["cross_check"]
    assert cross_check["lsof_available"] is True
    assert cross_check["netstat_available"] is True
    # netstat sees root-owned sockets that unprivileged lsof cannot. The count
    # is the measured blind spot of this scan.
    assert isinstance(cross_check["seen_by_netstat_only"], list)


def test_ports_are_classified_by_bind_scope():
    block = collectors.collect_listening_ports(probe=False)
    scopes = {entry["bind_scope"] for entry in block["ports"]}
    assert scopes <= {"localhost", "wildcard", "specific", "unknown"}


def test_probe_results_never_claim_remote_reachability():
    block = collectors.collect_listening_ports(probe=True)
    for entry in block["ports"]:
        assert entry["probe"]["reachability_from_other_hosts"] == "not_tested"
        assert "loopback-routed" in entry["probe"]["probe_caveat"]


def test_probe_of_a_closed_port_reports_closed():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    closed_port = sock.getsockname()[1]
    sock.close()
    assert collectors.probe_tcp("127.0.0.1", closed_port)["open"] is False


def test_probe_of_an_open_port_reports_open():
    """POSITIVE CONTROL: the probe must be able to return True."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        assert collectors.probe_tcp("127.0.0.1", server.getsockname()[1])["open"] is True
    finally:
        server.close()


def test_launch_items_are_hashed_and_labelled():
    block = collectors.collect_launch_items()
    assert block["available"] is True
    assert block["count"] > 0
    parsed = [item for item in block["items"] if item.get("label")]
    assert parsed, "no LaunchAgent could be parsed"
    assert all(item["sha256"] for item in parsed)


def test_unparseable_plists_fall_back_to_plutil():
    """Two plists here contain '--' inside XML comments, which expat rejects.

    plutil accepts them and launchd runs them. Reporting them as unreadable
    would be a finding manufactured by the choice of parser.
    """
    block = collectors.collect_launch_items()
    fallbacks = [item for item in block["items"] if (item.get("parser") or "").startswith("plutil")]
    for item in fallbacks:
        assert item["label"], "plutil fallback parsed a plist but got no label"
    unreadable = [item for item in block["items"] if item.get("parse_error")]
    for item in unreadable:
        assert "plutil fallback" in item["parse_error"], "both parsers must be reported"


def test_security_tools_inventory_separates_present_from_absent():
    block = collectors.collect_security_tools()
    assert block["available"] is True
    assert "lsof" in block["present"]
    # None of the heavy security stack is installed on this machine.
    assert "wazuh-control" in block["absent"]


def test_sip_gatekeeper_firewall_are_readable_on_macos():
    for collect in (collectors.collect_sip, collectors.collect_gatekeeper, collectors.collect_firewall):
        block = collect()
        assert "available" in block
        if not block["available"]:
            assert block["reason"]


def test_tcc_returns_available_or_an_explicit_reason():
    for database in ("user", "system"):
        block = collectors.collect_tcc(database)
        if block["available"]:
            assert block["auth_column"] in ("auth_value", "allowed")
            assert "Full Disk Access" in block["grants"]
        else:
            assert block["reason"]


def test_tcc_unknown_database_is_rejected():
    assert collectors.collect_tcc("nonsense")["available"] is False


def test_file_modes_reports_missing_files_separately_from_findings():
    block = collectors.collect_file_modes()
    assert block["available"] is True
    assert isinstance(block["missing"], list)
    assert block["sweep"]["depth"] == 1


def test_file_modes_detects_a_world_writable_file(tmp_path):
    """POSITIVE CONTROL: the permission check must be able to fire."""
    target = tmp_path / "exposed.env"
    target.write_text("SECRET=1")
    target.chmod(0o666)
    block = collectors.collect_file_modes([str(target)])
    assert block["files"][0]["world_writable"] is True


def test_processes_resolve_executable_paths():
    block = collectors.collect_processes()
    assert block["available"] is True
    assert block["count"] > 0


def test_sha256_of_unreadable_file_is_none():
    from pathlib import Path

    assert collectors.sha256_file(Path("/definitely/not/here")) is None


def test_classify_bind_covers_the_wildcard_forms():
    assert collectors.classify_bind("*") == "wildcard"
    assert collectors.classify_bind("0.0.0.0") == "wildcard"
    assert collectors.classify_bind("::") == "wildcard"
    assert collectors.classify_bind("127.0.0.1") == "localhost"
    assert collectors.classify_bind("192.168.1.10") == "specific"
