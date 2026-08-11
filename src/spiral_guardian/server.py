"""MCP tool surface for Spiral Guardian.

Thin registration layer only: every tool body delegates to an undecorated
implementation in tools.py. Keeping the surface thin is what allows the
implementations to call one another and to be tested without MCP plumbing.

Import of this module has NO side effects beyond constructing the server
object — no directories are created, no subprocesses run, no network touched.
"""

from __future__ import annotations

import argparse
import logging

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from . import __version__, config, tools

logger = logging.getLogger(__name__)

guardian = MCPServer(
    "Spiral Guardian",
    version=__version__,
    description=(
        "Defensive security agent for Temple of Two infrastructure. Reports "
        "honestly about the instruments it actually has: when a backing tool "
        "is absent, the affected capability returns available=false with a "
        "reason, and every response carries a coverage statement naming what "
        "was checked and what could not be."
    ),
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)


@guardian.tool(annotations=READ_ONLY)
async def spiral_guardian_status(include_scan_progress: bool = False) -> dict:
    """Local security posture: SIP, Gatekeeper, firewall, listening ports.

    Returns a health score computed ONLY from signals actually collected, with
    the scoring basis itemized. If nothing could be collected, no score is
    emitted rather than a misleading 100.

    Args:
        include_scan_progress: include scan scheduler state (not implemented).
    """
    return await tools.status_impl(include_scan_progress=include_scan_progress)


@guardian.tool(annotations=READ_ONLY)
async def spiral_guardian_alerts(
    severity: str = "high",
    time_window: str = "24h",
    device: str = "all",
    limit: int = 25,
) -> dict:
    """Retrieve security alerts from the monitoring stack.

    NOTE: the alert backend (Wazuh) is NOT DEPLOYED on this infrastructure. In
    that state this tool returns available=false with a reason and an explicit
    statement that an empty alert list is not evidence of no alerts.

    Args:
        severity: "low", "medium", "high", or "critical".
        time_window: e.g. "30m", "24h", "7d", "2w". Applied to the query.
        device: agent name, or "all".
        limit: maximum alerts to return.
    """
    return await tools.alerts_impl(
        severity=severity, time_window=time_window, device=device, limit=limit
    )


@guardian.tool(annotations=READ_ONLY)
async def spiral_guardian_drift(check_ports: bool = True, probe: bool = True) -> dict:
    """Detect configuration that no longer governs the running system.

    Finds five classes of config-with-no-reader drift: a plist configuring a
    service launchd is not running; a declared binary that does not exist; a
    running process that is not the declared binary (compared after symlink
    resolution); a declared localhost bind whose real listener is wildcard; and
    a declared port with no listener.

    Args:
        check_ports: include listening-port classification and exposure review.
        probe: confirm port state by TCP connect (localhost-originated only).
    """
    return await tools.drift_impl(check_ports=check_ports, probe=probe)


@guardian.tool(annotations=READ_ONLY)
async def spiral_guardian_baseline(
    components: list[str] | None = None,
    device: str = "local",
    compare: bool = True,
) -> dict:
    """Capture a security baseline and diff it against the stored one.

    Captures real state: listening ports, LaunchAgents/LaunchDaemons with
    hashes, PATH security-tool inventory, SIP, Gatekeeper, firewall, TCC
    grants, and sensitive file modes. Diff statuses distinguish "changed" from
    "not collected this run" so a missing instrument is never reported as a
    posture change.

    Args:
        components: subset to capture; defaults to all known components.
        device: baseline namespace, default "local".
        compare: diff against the stored baseline for this device.
    """
    return await tools.baseline_impl(
        components=components, device=device, compare=compare
    )


@guardian.tool(annotations=READ_ONLY)
async def spiral_guardian_audit(
    audit_type: str = "supply_chain",
    target_path: str = "~/sovereign-stack",
) -> dict:
    """Run a targeted security audit.

    Args:
        audit_type: "supply_chain" (trivy), "secrets" (gitleaks), "compliance"
            (local macOS controls + Wazuh SCA), "network" (listening ports,
            ownership, wildcard binds), "permissions" (TCC grants, file modes),
            or "mcp" (configured MCP servers).
        target_path: path to audit for the filesystem-scanning types.
    """
    return await tools.audit_impl(audit_type=audit_type, target_path=target_path)


@guardian.tool(annotations=READ_ONLY)
async def spiral_guardian_mcp_audit(
    scan_tool_descriptions: bool = True,
    check_transport_security: bool = True,
) -> dict:
    """Audit MCP servers configured on this machine.

    Enumerates servers from ~/.claude.json (global and per-project), .mcp.json
    files within depth 3 of home, and plugin-bundled configs, then applies a
    nine-pattern suspicious-content list to the configuration. Reading a
    server's TOOL DESCRIPTIONS would require launching it; this audit starts
    nothing and says so.

    Args:
        scan_tool_descriptions: apply the pattern list to enumerated config.
        check_transport_security: summarize transports in use.
    """
    return await tools.mcp_audit_impl(
        scan_tool_descriptions=scan_tool_descriptions,
        check_transport_security=check_transport_security,
    )


@guardian.tool(annotations=READ_ONLY)
async def spiral_guardian_scan(
    scan_type: str = "quick",
    target_path: str = "~/temple-vault",
    target_device: str = "local",
    include_yara: bool = True,
    include_clamav: bool = False,
) -> dict:
    """Trigger a security scan using whichever scanners are installed.

    YARA, ClamAV and nmap are NOT installed on this machine; each reports
    available=false with a reason rather than failing or faking a clean scan.

    Args:
        scan_type: "quick", "full", "malware", "vulnerability", or "network".
        target_path: path to scan.
        target_device: only "local" is implemented.
        include_yara: attempt a YARA scan.
        include_clamav: attempt a ClamAV scan.
    """
    return await tools.scan_impl(
        scan_type=scan_type,
        target_path=target_path,
        target_device=target_device,
        include_yara=include_yara,
        include_clamav=include_clamav,
    )


@guardian.tool(annotations=READ_ONLY)
async def spiral_guardian_report(
    report_type: str = "summary",
    time_period: str = "7d",
    output_format: str = "markdown",
) -> dict:
    """Generate a security report. Each report_type produces different content.

    Args:
        report_type: "summary" (posture headline), "detailed" (posture, drift
            findings, port picture), "compliance" (control-by-control table),
            or "incident" (critical alerts timeline plus quarantine state).
        time_period: reporting window, e.g. "24h", "7d".
        output_format: "markdown" or "json".
    """
    return await tools.report_impl(
        report_type=report_type, time_period=time_period, output_format=output_format
    )


@guardian.tool(
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False
    )
)
async def spiral_guardian_quarantine(action: str = "list", file_hash: str = "") -> dict:
    """Isolate, release, or list quarantined files. DESTRUCTIVE except "list".

    Operates on SHA256 digests only, never on raw paths. Requires the
    privileged wrapper to be installed; when it is not, reports why instead of
    hanging on a sudo password prompt.

    Args:
        action: "list", "isolate", "release", or "delete".
        file_hash: 64-character SHA256 hex digest (required except for "list").
    """
    return await tools.quarantine_impl(action=action, file_hash=file_hash)


def main() -> None:
    parser = argparse.ArgumentParser(description="Spiral Guardian MCP server")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=("stdio", "sse", "streamable-http"),
        help="MCP transport (default: stdio)",
    )
    parser.add_argument("--log-level", default="WARNING")
    arguments = parser.parse_args()
    logging.basicConfig(level=arguments.log_level.upper())
    if not config.tls_verify():
        logger.warning(
            "GUARDIAN_INSECURE_TLS is set: outbound TLS certificate "
            "verification is DISABLED for this process."
        )
    guardian.run(transport=arguments.transport)


if __name__ == "__main__":
    main()
