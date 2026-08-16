"""Tool implementations.

These are plain async functions, deliberately NOT decorated. server.py wraps
each one in a thin ``@guardian.tool()`` registration. Two reasons:

  * tools call each other (report needs status and alerts). v1.0.0 had
    ``spiral_guardian_audit`` await ``spiral_guardian_mcp_audit`` directly —
    a decorated object, which is not reliably callable as a bare function.
  * pytest can exercise the logic without any MCP plumbing.

Blocking collectors are run through ``asyncio.to_thread`` so a slow subprocess
never stalls the server's event loop.
"""

from __future__ import annotations

import asyncio
import json
import platform
import time
from pathlib import Path

from . import collectors, config
from .evaluate import (
    SUSPICIOUS_PATTERNS,
    diff_baseline,
    evaluate_drift,
    evaluate_mcp_servers,
    evaluate_port_exposure,
)
from .result import Coverage, envelope, is_available, now_iso, unavailable
from .runner import run, run_wrapper, tool_capability
from .wazuh import build_alert_query, capability as wazuh_capability, wazuh

BASELINE_COMPONENTS = (
    "listening_ports",
    "launch_items",
    "security_tools",
    "system_integrity_protection",
    "gatekeeper",
    "firewall",
    "tcc_user",
    "tcc_system",
    "file_modes",
    "mcp_servers",
)

_COLLECTOR_MAP = {
    "listening_ports": lambda: collectors.collect_listening_ports(probe=False),
    "launch_items": collectors.collect_launch_items,
    "security_tools": collectors.collect_security_tools,
    "system_integrity_protection": collectors.collect_sip,
    "gatekeeper": collectors.collect_gatekeeper,
    "firewall": collectors.collect_firewall,
    "tcc_user": lambda: collectors.collect_tcc("user"),
    "tcc_system": lambda: collectors.collect_tcc("system"),
    "file_modes": collectors.collect_file_modes,
    "mcp_servers": collectors.collect_mcp_servers,
}


def _write_json(directory: str, filename: str, payload: dict) -> dict:
    """Persist JSON under GUARDIAN_HOME, creating the directory lazily."""
    try:
        target = config.ensure_dir(directory) / filename
        target.write_text(json.dumps(payload, indent=2, default=str))
        return {"saved_to": str(target)}
    except OSError as exc:
        return {"save_failed": f"{type(exc).__name__}: {exc}"}


# === status ================================================================


async def status_impl(include_scan_progress: bool = False) -> dict:
    """Local security posture, scored only from signals actually collected."""
    coverage = Coverage()

    sip = coverage.record("sip", await asyncio.to_thread(collectors.collect_sip))
    gatekeeper = coverage.record(
        "gatekeeper", await asyncio.to_thread(collectors.collect_gatekeeper)
    )
    firewall = coverage.record("firewall", await asyncio.to_thread(collectors.collect_firewall))
    ports = coverage.record(
        "listening_ports",
        await asyncio.to_thread(collectors.collect_listening_ports, False),
    )

    wazuh_gate = wazuh_capability()
    devices: dict = {}
    if not wazuh_gate.get("available"):
        coverage.skip("wazuh_agents", wazuh_gate["reason"])
        coverage.skip("wazuh_alerts", wazuh_gate["reason"])
        agents_block = wazuh_gate
        alerts_block = wazuh_gate
    else:
        agents_block = await wazuh.get("/agents", params={"limit": 10})
        coverage.record("wazuh_agents", agents_block)
        if is_available(agents_block):
            for agent in agents_block["data"].get("data", {}).get("affected_items", []):
                devices[agent.get("name", "unknown")] = {
                    "status": agent.get("status", "unknown"),
                    "last_keep_alive": agent.get("lastKeepAlive", "unknown"),
                    "os": agent.get("os", {}).get("name", "unknown"),
                }
        query = build_alert_query(severity="medium", time_window="24h", limit=100)
        alerts_block = await wazuh.get("/alerts", params=query["params"])
        coverage.record("wazuh_alerts", alerts_block)

    # Score only from signals that were actually collected. A score computed
    # over nothing would be the purest form of the failure this release is
    # about: 100/100 meaning "I checked nothing".
    score = 100
    basis: list[dict] = []
    if is_available(sip):
        if not sip["enabled"]:
            score -= 25
            basis.append({"signal": "sip", "penalty": 25, "note": "System Integrity Protection disabled"})
        else:
            basis.append({"signal": "sip", "penalty": 0, "note": "enabled"})
    if is_available(gatekeeper):
        if not gatekeeper["assessments_enabled"]:
            score -= 15
            basis.append({"signal": "gatekeeper", "penalty": 15, "note": "assessments disabled"})
        else:
            basis.append({"signal": "gatekeeper", "penalty": 0, "note": "enabled"})
    if is_available(firewall):
        if not firewall["enabled"]:
            score -= 15
            basis.append({"signal": "firewall", "penalty": 15, "note": "firewall off"})
        else:
            basis.append({"signal": "firewall", "penalty": 0, "note": "enabled"})
    wildcard_count = 0
    if is_available(ports):
        wildcard_count = len(evaluate_port_exposure(ports["ports"]))
        penalty = min(20, wildcard_count * 4)
        score -= penalty
        basis.append({
            "signal": "wildcard_binds",
            "penalty": penalty,
            "note": f"{wildcard_count} wildcard-bound listening port(s)",
        })

    scored = bool(basis)
    payload = {
        "health_score": max(0, score) if scored else None,
        "health_score_basis": basis,
        "health_score_note": (
            "computed ONLY from the signals in health_score_basis; it is not a "
            "whole-infrastructure score and does not account for capabilities "
            "listed as unavailable in coverage"
            if scored else
            "no signal could be collected; refusing to emit a score"
        ),
        "risk_level": (
            "unknown" if not scored else
            "high" if score < 60 else "medium" if score < 85 else "low"
        ),
        "host": platform.node(),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "system_integrity_protection": sip,
        "gatekeeper": gatekeeper,
        "firewall": firewall,
        "listening_ports_summary": (
            {
                "total": ports["count"],
                "wildcard": wildcard_count,
                "invisible_to_lsof": ports["cross_check"]["seen_by_netstat_only"],
            }
            if is_available(ports) else ports
        ),
        "devices": devices,
        "wazuh": wazuh_gate if not wazuh_gate.get("available") else {
            "agents": agents_block, "alerts": alerts_block
        },
    }
    if include_scan_progress:
        payload["scan_progress"] = unavailable(
            "no scan scheduler is implemented in v1.1.0; scans are synchronous"
        )
    return envelope("spiral_guardian_status", coverage, **payload)


# === alerts ================================================================


async def alerts_impl(
    severity: str = "high",
    time_window: str = "24h",
    device: str = "all",
    limit: int = 25,
) -> dict:
    """Retrieve alerts. time_window is HONORED and its application reported."""
    coverage = Coverage()
    query = build_alert_query(severity, time_window, device, limit)

    gate = wazuh_capability()
    if not gate.get("available"):
        coverage.skip("wazuh_alerts", gate["reason"])
        return envelope(
            "spiral_guardian_alerts",
            coverage,
            alerts=[],
            total=None,
            alerts_note=(
                "an empty alert list here means NO ALERT SOURCE WAS REACHED — "
                "it is not evidence that no alerts exist"
            ),
            query=query,
            source=gate,
        )

    if not query["time_window_applied"]:
        coverage.error("time_window", query["time_window_reason"])

    response = await wazuh.get("/alerts", params=query["params"])
    coverage.record("wazuh_alerts", response)
    if not is_available(response):
        return envelope(
            "spiral_guardian_alerts", coverage,
            alerts=[], total=None, query=query, source=response,
        )

    data = response["data"].get("data", {})
    formatted = [
        {
            "id": alert.get("id"),
            "timestamp": alert.get("timestamp"),
            "level": alert.get("rule", {}).get("level"),
            "description": alert.get("rule", {}).get("description"),
            "agent": alert.get("agent", {}).get("name"),
            "mitre": alert.get("rule", {}).get("mitre", {}),
        }
        for alert in data.get("affected_items", [])
    ]
    total = data.get("total_affected_items", 0)
    return envelope(
        "spiral_guardian_alerts", coverage,
        alerts=formatted,
        returned=len(formatted),
        total=total,
        truncated=total > len(formatted),
        query=query,
    )


# === drift =================================================================


async def drift_impl(check_ports: bool = True, probe: bool = True) -> dict:
    """Detect configuration that no longer governs the running system.

    The class of bug this exists for: a plist, flag, or env var that reads as
    enforcement while nothing consumes it. Encoded from the house's SOP #12
    ("the fix is usually already written and not connected") and its live
    specimen on this machine.
    """
    coverage = Coverage()
    launch_block = coverage.record(
        "launch_items", await asyncio.to_thread(collectors.collect_launch_items)
    )
    ports_block = coverage.record(
        "listening_ports",
        await asyncio.to_thread(collectors.collect_listening_ports, probe and check_ports),
    )
    process_block = coverage.record(
        "processes", await asyncio.to_thread(collectors.collect_processes)
    )

    if not is_available(launch_block) or not is_available(ports_block):
        return envelope(
            "spiral_guardian_drift", coverage,
            findings=[],
            findings_note=(
                "NO drift evaluation was performed — a required observation "
                "was unavailable. An empty findings list here means nothing "
                "was checked."
            ),
            launch_items=launch_block if not is_available(launch_block) else None,
            listening_ports=ports_block if not is_available(ports_block) else None,
        )

    findings = evaluate_drift(
        launch_block["items"],
        ports_block["ports"],
        process_block.get("processes", {}) if is_available(process_block) else {},
    )
    exposure = evaluate_port_exposure(ports_block["ports"]) if check_ports else []

    unreadable = [
        item["path"] for item in launch_block["items"] if item.get("parse_error")
    ]
    if unreadable:
        coverage.error("launch_item_parse", f"{len(unreadable)} plist(s) unreadable: {unreadable}")

    by_class: dict[str, int] = {}
    for finding in findings:
        by_class[finding["class"]] = by_class.get(finding["class"], 0) + 1

    return envelope(
        "spiral_guardian_drift", coverage,
        findings=findings,
        finding_count=len(findings),
        findings_by_class=by_class,
        port_exposure=exposure,
        scope={
            "launch_items_examined": launch_block["count"],
            "dirs_scanned": launch_block["dirs_scanned"],
            "dirs_unreadable": launch_block["dirs_unreadable"],
            "ports_examined": ports_block["count"],
            "ports_invisible_to_lsof": ports_block["cross_check"]["seen_by_netstat_only"],
            "processes_examined": (
                process_block.get("count", 0) if is_available(process_block) else 0
            ),
        },
        method={
            "binary_comparison": (
                "declared and running binaries are compared AFTER full symlink "
                "resolution; /usr/local/bin/X symlinked into an .app bundle is "
                "NOT reported as a mismatch"
            ),
            "bind_truth": (
                "bind scope is taken from lsof and netstat, cross-checked, and "
                "where probed, confirmed by TCP connect. Reachability from "
                "other hosts is never inferred."
            ),
        },
    )


# === audit =================================================================


async def _audit_network(coverage: Coverage) -> dict:
    ports_block = coverage.record(
        "listening_ports", await asyncio.to_thread(collectors.collect_listening_ports, True)
    )
    if not is_available(ports_block):
        return {"network": ports_block}
    findings = evaluate_port_exposure(ports_block["ports"])
    unowned = [entry["port"] for entry in ports_block["ports"] if not entry.get("owner_known")]
    if unowned:
        coverage.skip(
            "port_ownership",
            f"{len(unowned)} port(s) have no owning process visible to this "
            f"unprivileged user: {unowned}",
        )
    return {
        "network": {
            "ports": ports_block["ports"],
            "count": ports_block["count"],
            "cross_check": ports_block["cross_check"],
            "findings": findings,
            "wildcard_count": len(findings),
        }
    }


async def _audit_permissions(coverage: Coverage) -> dict:
    user_tcc = coverage.record("tcc_user", await asyncio.to_thread(collectors.collect_tcc, "user"))
    system_tcc = coverage.record(
        "tcc_system", await asyncio.to_thread(collectors.collect_tcc, "system")
    )
    modes = coverage.record("file_modes", await asyncio.to_thread(collectors.collect_file_modes))

    findings = []
    if is_available(modes):
        for entry in modes["files"]:
            if entry.get("world_writable"):
                findings.append({
                    "class": "world_writable_sensitive_file",
                    "severity": "critical",
                    "path": entry["path"], "mode": entry["mode"],
                })
            elif entry.get("world_readable") and "/.ssh/" in entry["path"] and "pub" not in entry["path"]:
                findings.append({
                    "class": "world_readable_private_key",
                    "severity": "high",
                    "path": entry["path"], "mode": entry["mode"],
                })
            elif entry.get("group_readable") and entry["path"].endswith(".env"):
                findings.append({
                    "class": "group_readable_secret_file",
                    "severity": "medium",
                    "path": entry["path"], "mode": entry["mode"],
                })
        for entry in modes["world_writable"]:
            findings.append({
                "class": "world_writable_config_entry",
                "severity": "high",
                "path": entry["path"], "mode": entry["mode"],
            })
    return {
        "permissions": {
            "tcc_user": user_tcc,
            "tcc_system": system_tcc,
            "tcc_note": (
                "TCC readability is a property of the CALLING process's Full "
                "Disk Access grant, not of the system. Full Disk Access grants "
                "live in the SYSTEM database; when it reads unavailable, that "
                "is a coverage gap, not an absence of grants."
            ),
            "file_modes": modes,
            "findings": findings,
            "finding_count": len(findings),
        }
    }


async def audit_impl(
    audit_type: str = "supply_chain",
    target_path: str = "~/sovereign-stack",
) -> dict:
    """Run a targeted security audit.

    All six advertised types are implemented. v1.0.0 documented six and
    branched four: ``network`` and ``permissions`` fell through and returned an
    empty findings list that read as a clean result.
    """
    coverage = Coverage()
    known = ("supply_chain", "secrets", "compliance", "network", "permissions", "mcp")
    resolved_target = str(Path(target_path).expanduser())
    payload: dict = {"audit_type": audit_type, "target": resolved_target}

    if audit_type not in known:
        coverage.error("audit_type", f"unknown audit_type {audit_type!r}")
        return envelope(
            "spiral_guardian_audit", coverage,
            **payload,
            error=f"unknown audit_type {audit_type!r}; known types: {list(known)}",
        )

    if audit_type == "supply_chain":
        gate = tool_capability("trivy", "filesystem vulnerability scanning")
        if not gate["available"]:
            coverage.skip("trivy", gate["reason"])
            payload["supply_chain"] = gate
        else:
            outcome = await asyncio.to_thread(
                run,
                ["trivy", "fs", "--format", "json", "--severity", "HIGH,CRITICAL", resolved_target],
                600.0,
            )
            coverage.check("trivy")
            try:
                payload["supply_chain"] = {"available": True, "trivy": json.loads(outcome["stdout"])}
            except json.JSONDecodeError:
                payload["supply_chain"] = {
                    "available": True, "parse_error": "trivy output was not JSON",
                    "raw": outcome["stdout"][:2000], "stderr": outcome["stderr"][:1000],
                }

    elif audit_type == "secrets":
        gate = tool_capability("gitleaks", "secret detection")
        if not gate["available"]:
            coverage.skip("gitleaks", gate["reason"])
            payload["secrets"] = gate
        else:
            report_path = config.ensure_dir("reports") / f"gitleaks_{int(time.time())}.json"
            outcome = await asyncio.to_thread(
                run,
                ["gitleaks", "detect", "--source", resolved_target, "--no-git",
                 "--report-format", "json", "--report-path", str(report_path)],
                600.0,
            )
            coverage.check("gitleaks")
            leaks, parse_error = [], None
            if report_path.exists():
                try:
                    leaks = json.loads(report_path.read_text() or "[]")
                except json.JSONDecodeError as exc:
                    parse_error = str(exc)
                finally:
                    report_path.unlink(missing_ok=True)
            else:
                parse_error = "gitleaks produced no report file"
            payload["secrets"] = {
                "available": True,
                "leak_count": len(leaks) if isinstance(leaks, list) else None,
                # Detected secrets are reported by location and rule only.
                # Emitting the matched value would copy the secret into the
                # chronicle, the MCP transcript, and the report file.
                "leaks": [
                    {
                        "rule": leak.get("RuleID"),
                        "file": leak.get("File"),
                        "line": leak.get("StartLine"),
                        "entropy": leak.get("Entropy"),
                        "secret_value": "REDACTED — not emitted by design",
                    }
                    for leak in (leaks if isinstance(leaks, list) else [])
                ],
                "parse_error": parse_error,
                "exit_code": outcome["exit_code"],
            }

    elif audit_type == "compliance":
        gate = wazuh_capability()
        coverage.skip("wazuh_sca", gate["reason"]) if not gate["available"] else None
        if gate["available"]:
            response = await wazuh.get("/sca", params={"limit": 50})
            coverage.record("wazuh_sca", response)
            payload["compliance"] = response
        else:
            payload["compliance"] = gate
        posture = {
            "system_integrity_protection": coverage.record(
                "sip", await asyncio.to_thread(collectors.collect_sip)
            ),
            "gatekeeper": coverage.record(
                "gatekeeper", await asyncio.to_thread(collectors.collect_gatekeeper)
            ),
            "firewall": coverage.record(
                "firewall", await asyncio.to_thread(collectors.collect_firewall)
            ),
        }
        payload["local_posture"] = posture

    elif audit_type == "network":
        payload.update(await _audit_network(coverage))

    elif audit_type == "permissions":
        payload.update(await _audit_permissions(coverage))

    elif audit_type == "mcp":
        payload["mcp"] = await mcp_audit_impl()

    return envelope("spiral_guardian_audit", coverage, **payload)


# === mcp audit =============================================================


async def mcp_audit_impl(
    scan_tool_descriptions: bool = True,
    check_transport_security: bool = True,
) -> dict:
    """Audit MCP servers configured on this machine.

    v1.0.0 defined a nine-pattern list, returned ``{"patterns": 9}``, and
    scanned nothing. v1.1.0 enumerates real configuration and applies the same
    nine patterns to it.
    """
    coverage = Coverage()
    servers_block = coverage.record(
        "mcp_server_enumeration", await asyncio.to_thread(collectors.collect_mcp_servers)
    )
    if not is_available(servers_block):
        return envelope("spiral_guardian_mcp_audit", coverage, servers=[], findings=[])

    servers = servers_block["servers"]
    findings = evaluate_mcp_servers(servers) if scan_tool_descriptions else []
    if not scan_tool_descriptions:
        coverage.skip("pattern_scan", "scan_tool_descriptions=False was requested")
    # The honest limit: descriptions live inside running servers.
    coverage.skip(
        "tool_description_scan", servers_block["limits"]["tool_descriptions_reason"]
    )

    transports: dict[str, int] = {}
    for server in servers:
        transport = str(server.get("transport", "unknown"))
        transports[transport] = transports.get(transport, 0) + 1
    if check_transport_security:
        coverage.check("transport_review")
    else:
        coverage.skip("transport_review", "check_transport_security=False was requested")

    return envelope(
        "spiral_guardian_mcp_audit", coverage,
        servers=[
            {key: server[key] for key in ("name", "source", "scope", "transport", "command", "args", "url", "env_keys")}
            for server in servers
        ],
        server_count=len(servers),
        findings=findings,
        finding_count=len(findings),
        transports=transports,
        patterns_applied=[pattern for pattern, _ in SUSPICIOUS_PATTERNS],
        pattern_count=len(SUSPICIOUS_PATTERNS),
        scanned_surface="server configuration only (name, command, args, url, env)",
        sources_read=servers_block["sources_read"],
        sources_failed=servers_block["sources_failed"],
        limits=servers_block["limits"],
    )


# === baseline ==============================================================


def _baseline_path(device: str) -> Path:
    return config.guardian_dir("baselines") / f"baseline_{device}.json"


async def baseline_impl(
    components: list[str] | None = None,
    device: str = "local",
    compare: bool = True,
) -> dict:
    """Capture a real security baseline, and diff it against the stored one.

    v1.0.0 wrote ``{"captured": True}`` per component and captured nothing.
    """
    coverage = Coverage()
    requested = list(components) if components else list(BASELINE_COMPONENTS)
    unknown = [name for name in requested if name not in _COLLECTOR_MAP]
    for name in unknown:
        coverage.error(name, f"unknown baseline component {name!r}")
    requested = [name for name in requested if name in _COLLECTOR_MAP]

    collected: dict[str, dict] = {}
    for name in requested:
        block = await asyncio.to_thread(_COLLECTOR_MAP[name])
        collected[name] = coverage.record(name, block)

    baseline = {
        "version": 1,
        "timestamp": now_iso(),
        "device": device,
        "host": platform.node(),
        "requested_components": requested,
        "unknown_components": unknown,
        "components": collected,
    }

    result: dict = {
        "device": device,
        "components_captured": [
            name for name, block in collected.items() if is_available(block)
        ],
        "components_unavailable": {
            name: block.get("reason")
            for name, block in collected.items() if not is_available(block)
        },
    }

    stored_path = _baseline_path(device)
    prior = None
    if compare and stored_path.is_file():
        try:
            prior = json.loads(stored_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            coverage.error("prior_baseline", f"stored baseline unreadable: {exc}")

    if prior is not None:
        result["comparison"] = diff_baseline(prior, baseline)
        result["compared_against"] = {
            "path": str(stored_path), "timestamp": prior.get("timestamp"),
        }
    elif compare:
        result["comparison"] = None
        result["comparison_note"] = (
            f"no stored baseline at {stored_path}; this run establishes the "
            "first one. Nothing was compared."
        )

    result.update(_write_json("baselines", f"baseline_{device}.json", baseline))
    result.update({
        "history": _write_json(
            "baselines", f"baseline_{device}_{int(time.time())}.json", baseline
        ).get("saved_to")
    })
    result["fingerprint_note"] = (
        "diffs compare stable fingerprints (bind scope, plist hashes, tool "
        "paths, TCC grants, file modes); PIDs, timestamps and probe results "
        "are excluded so a restart is not reported as a posture change"
    )
    return envelope("spiral_guardian_baseline", coverage, **result)


# === scan ==================================================================


async def scan_impl(
    scan_type: str = "quick",
    target_path: str = "~/temple-vault",
    target_device: str = "local",
    include_yara: bool = True,
    include_clamav: bool = False,
) -> dict:
    """Trigger a security scan with whatever scanners actually exist."""
    coverage = Coverage()
    started = time.time()
    resolved_target = str(Path(target_path).expanduser())
    scan_id = f"scan_{int(started)}"
    results: dict = {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "target": resolved_target,
        "target_device": target_device,
        "target_exists": Path(resolved_target).exists(),
    }

    if target_device != "local":
        coverage.skip(
            "remote_scan",
            f"remote scanning of {target_device!r} is not implemented in v1.1.0; "
            "only the local host was scanned",
        )

    if not results["target_exists"]:
        coverage.error("target", f"{resolved_target} does not exist")

    if scan_type in ("quick", "full", "malware"):
        if include_yara:
            yara = tool_capability("yr", "YARA-X scanning")
            if not yara["available"]:
                fallback = tool_capability("yara", "YARA scanning")
                yara = fallback if fallback["available"] else yara
            if not yara["available"]:
                coverage.skip("yara", yara["reason"])
                results["yara"] = yara
            else:
                results["yara"] = run_wrapper(
                    "yara-scan", resolved_target,
                    timeout=7200.0 if scan_type == "full" else 600.0,
                )
                coverage.record("yara", results["yara"])
        else:
            coverage.skip("yara", "include_yara=False was requested")

        if include_clamav:
            clamav = tool_capability("clamscan", "ClamAV malware scanning")
            coverage.record("clamav", clamav)
            results["clamav"] = clamav if not clamav["available"] else await asyncio.to_thread(
                run, ["clamscan", "-r", "--no-summary", resolved_target], 14400.0
            )
        else:
            coverage.skip("clamav", "include_clamav=False was requested")

    if scan_type in ("full", "vulnerability"):
        gate = wazuh_capability()
        if gate["available"]:
            response = await wazuh.get("/vulnerability", params={"limit": 50})
            coverage.record("wazuh_vulnerability", response)
            results["vulnerabilities"] = response
        else:
            coverage.skip("wazuh_vulnerability", gate["reason"])
            results["vulnerabilities"] = gate

    if scan_type in ("full", "network"):
        nmap = tool_capability("nmap", "network scanning")
        if not nmap["available"]:
            coverage.skip("nmap", nmap["reason"])
            # Degrade to the local instrument that DOES exist, and say so.
            local_ports = await asyncio.to_thread(collectors.collect_listening_ports, True)
            coverage.record("local_port_enumeration", local_ports)
            results["network"] = {
                **nmap,
                "fallback": "local listening-port enumeration only",
                "fallback_scope": "this host; no other host on the network was contacted",
                "local_ports": local_ports,
            }
        else:
            coverage.check("nmap")
            results["network"] = await asyncio.to_thread(
                run, ["nmap", "-sT", "-Pn", "127.0.0.1"], 600.0
            )

    results["duration_seconds"] = round(time.time() - started, 2)
    results["findings_note"] = (
        "an empty or absent finding set from a scanner reported unavailable is "
        "NOT a clean result"
    )
    envelope_result = envelope("spiral_guardian_scan", coverage, **results)
    envelope_result.update(_write_json("reports", f"{scan_id}.json", envelope_result))
    return envelope_result


# === quarantine ============================================================


async def quarantine_impl(action: str = "list", file_hash: str = "") -> dict:
    """Isolate, release, or list quarantined files."""
    coverage = Coverage()
    valid_actions = ("list", "isolate", "release", "delete")
    if action not in valid_actions:
        coverage.error("action", f"unknown action {action!r}")
        return envelope(
            "spiral_guardian_quarantine", coverage,
            error=f"unknown action {action!r}; valid: {list(valid_actions)}",
        )
    if action in ("isolate", "release", "delete"):
        if not file_hash:
            coverage.error("file_hash", "file_hash is required for this action")
            return envelope(
                "spiral_guardian_quarantine", coverage,
                error=f"file_hash required for action {action!r}",
            )
        normalized = file_hash.lower()
        if len(normalized) != 64 or not all(c in "0123456789abcdef" for c in normalized):
            coverage.error("file_hash", "not a SHA256 hex digest")
            return envelope(
                "spiral_guardian_quarantine", coverage,
                error="file_hash must be a 64-character SHA256 hex digest",
            )
        file_hash = normalized

    outcome = await asyncio.to_thread(run_wrapper, "quarantine", action, file_hash)
    coverage.record("quarantine_wrapper", outcome)
    return envelope("spiral_guardian_quarantine", coverage, action=action, result=outcome)


# === report ================================================================


def _markdown_report(report_type: str, sections: list[dict], payload: dict) -> str:
    lines = [
        f"# Spiral Guardian — {report_type.title()} Report",
        "",
        f"**Generated:** {payload['generated_at']}  ",
        f"**Host:** {payload['host']}  ",
        f"**Period:** {payload['time_period']}  ",
        f"**Coverage:** {payload['coverage_statement']}",
        "",
    ]
    for section in sections:
        lines.append(f"## {section['title']}")
        lines.append("")
        for line in section["lines"]:
            lines.append(line)
        lines.append("")
    return "\n".join(lines)


async def report_impl(
    report_type: str = "summary",
    time_period: str = "7d",
    output_format: str = "markdown",
) -> dict:
    """Generate a security report. report_type genuinely changes the content.

    v1.0.0 accepted four report types, branched on none of them, and produced
    an identical document for all four.
    """
    coverage = Coverage()
    known_types = ("summary", "detailed", "compliance", "incident")
    if report_type not in known_types:
        coverage.error("report_type", f"unknown report_type {report_type!r}")
        return envelope(
            "spiral_guardian_report", coverage,
            error=f"unknown report_type {report_type!r}; known: {list(known_types)}",
        )

    status = await status_impl()
    alerts = await alerts_impl(severity="low", time_window=time_period, limit=100)
    for name, reason in status["coverage"]["unavailable"].items():
        coverage.skip(name, reason)
    for name in status["coverage"]["checked"]:
        coverage.check(name)

    sections: list[dict] = []

    if report_type == "summary":
        sections.append({
            "title": "Posture",
            "lines": [
                f"- Health score: {status['health_score']}/100 (risk: {status['risk_level']})",
                f"- SIP: {status['system_integrity_protection'].get('raw', 'unavailable')}",
                f"- Alerts in {time_period}: {alerts['total'] if alerts['total'] is not None else 'NO SOURCE REACHED'}",
            ],
        })

    elif report_type == "detailed":
        sections.append({
            "title": "Posture",
            "lines": [f"- Health score: {status['health_score']}/100"] + [
                f"- {entry['signal']}: {entry['note']} (penalty {entry['penalty']})"
                for entry in status["health_score_basis"]
            ],
        })
        drift = await drift_impl(probe=False)
        coverage.check("drift")
        sections.append({
            "title": f"Configuration drift ({drift['finding_count']} finding(s))",
            "lines": [
                f"- **{finding['severity'].upper()}** `{finding['class']}` {finding['label']}: {finding['detail']}"
                for finding in drift["findings"]
            ] or ["- none detected within the scanned scope"],
        })
        ports = status.get("listening_ports_summary", {})
        sections.append({
            "title": "Listening ports",
            "lines": [
                f"- total: {ports.get('total')}",
                f"- wildcard-bound: {ports.get('wildcard')}",
                f"- invisible to unprivileged lsof: {ports.get('invisible_to_lsof')}",
            ],
        })

    elif report_type == "compliance":
        controls = [
            ("System Integrity Protection", status["system_integrity_protection"], "enabled"),
            ("Gatekeeper assessments", status["gatekeeper"], "assessments_enabled"),
            ("Application firewall", status["firewall"], "enabled"),
            ("Firewall stealth mode", status["firewall"], "stealth_enabled"),
        ]
        lines = ["| Control | State | Evidence |", "| --- | --- | --- |"]
        for title, block, key in controls:
            if is_available(block):
                state = "PASS" if block.get(key) else "FAIL"
                evidence = block.get("raw") or block.get("global_state_raw") or "collected"
            else:
                state = "NOT ASSESSED"
                evidence = block.get("reason", "unavailable")
            lines.append(f"| {title} | {state} | {str(evidence)[:80]} |")
        sections.append({"title": "Local control assessment", "lines": lines})
        sections.append({
            "title": "Configuration-assessment backend",
            "lines": [
                "- Wazuh SCA: " + (
                    "available" if status["wazuh"].get("available") else
                    status["wazuh"].get("reason", "unavailable")
                ),
                "- No CIS/SCA benchmark was evaluated; controls above are direct "
                "macOS state reads, not a certified benchmark run.",
            ],
        })

    elif report_type == "incident":
        critical = [
            alert for alert in alerts["alerts"]
            if isinstance(alert.get("level"), int) and alert["level"] >= 12
        ]
        quarantine = await quarantine_impl("list")
        coverage.check("quarantine_listing") if is_available(
            quarantine["result"]
        ) else coverage.skip("quarantine_listing", quarantine["result"].get("reason", "?"))
        sections.append({
            "title": "Critical alerts",
            "lines": [
                f"- [{alert['timestamp']}] level {alert['level']} {alert['description']} ({alert['agent']})"
                for alert in sorted(critical, key=lambda a: str(a.get("timestamp")))
            ] or [
                "- none returned. NOTE: " + (
                    "no alert source was reachable, so this is not evidence that "
                    "no incident occurred"
                    if alerts["total"] is None else "the alert source returned no critical alerts"
                )
            ],
        })
        sections.append({
            "title": "Quarantine",
            "lines": [
                "- " + (
                    "wrapper unavailable: " + quarantine["result"].get("reason", "?")
                    if not is_available(quarantine["result"])
                    else str(quarantine["result"].get("stdout", ""))[:500]
                )
            ],
        })

    payload = {
        "report_type": report_type,
        "time_period": time_period,
        "generated_at": now_iso(),
        "host": platform.node(),
        "output_format": output_format,
        "health_score": status["health_score"],
        "risk_level": status["risk_level"],
        "alert_count": alerts["total"],
        "sections": [section["title"] for section in sections],
        "coverage_statement": coverage.statement(),
    }
    if output_format == "markdown":
        payload["content"] = _markdown_report(report_type, sections, payload)
    else:
        payload["content"] = json.dumps(
            {"payload": payload, "sections": sections}, indent=2, default=str
        )
    payload["section_detail"] = sections

    result = envelope("spiral_guardian_report", coverage, **payload)
    extension = "md" if output_format == "markdown" else "json"
    saved = _write_json("reports", f"report_{report_type}_{int(time.time())}.{extension}", result)
    try:
        if "saved_to" in saved:
            Path(saved["saved_to"]).write_text(payload["content"])
    except OSError as exc:
        saved = {"save_failed": str(exc)}
    result.update(saved)
    return result
