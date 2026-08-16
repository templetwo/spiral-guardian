"""Lightweight spoke agent for remote devices (MacBook Pro, Jetson).

STATUS: local-only and UNAUTHENTICATED. v1.0.0 bound this to port 8001 over
streamable HTTP with no authentication of any kind, which is a remote code
execution surface for anything that can reach the port. v1.1.0 defaults to
stdio (no listening socket at all); binding a network port requires an
explicit --transport plus an explicit bind host, and the agent refuses to bind
a non-loopback address without GUARDIAN_AGENT_ALLOW_REMOTE=1 so it cannot be
put on the network by accident.

The hub-to-spoke orchestration path is NOT DEPLOYED. This agent is the local
half only.
"""

from __future__ import annotations

import argparse
import logging
import os
import platform

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from . import __version__, collectors
from .result import Coverage, envelope, is_available
from .runner import tool_capability

logger = logging.getLogger(__name__)

agent = MCPServer(
    "Guardian Agent",
    version=__version__,
    description=(
        "Lightweight spoke agent for Spiral Guardian. Reports local security "
        "state honestly, including which scanners are absent."
    ),
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)


@agent.tool(annotations=READ_ONLY)
async def local_status() -> dict:
    """This device's security state: SIP, Gatekeeper, firewall, ports, tools."""
    coverage = Coverage()
    sip = coverage.record("sip", collectors.collect_sip())
    gatekeeper = coverage.record("gatekeeper", collectors.collect_gatekeeper())
    firewall = coverage.record("firewall", collectors.collect_firewall())
    ports = coverage.record("listening_ports", collectors.collect_listening_ports(probe=False))
    return envelope(
        "local_status", coverage,
        device=platform.node(),
        platform=platform.system(),
        architecture=platform.machine(),
        system_integrity_protection=sip,
        gatekeeper=gatekeeper,
        firewall=firewall,
        listening_port_count=ports["count"] if is_available(ports) else None,
        listening_ports=ports,
    )


@agent.tool(annotations=READ_ONLY)
async def local_scan(scan_type: str = "quick", target_path: str = "~") -> dict:
    """Run a local scan with whichever scanners exist on this device."""
    coverage = Coverage()
    results = {"device": platform.node(), "scan_type": scan_type, "target": target_path}
    yara = tool_capability("yr", "YARA-X scanning")
    if not yara["available"]:
        fallback = tool_capability("yara", "YARA scanning")
        yara = fallback if fallback["available"] else yara
    coverage.record("yara", yara)
    results["yara"] = yara
    if yara["available"]:
        results["yara"] = {
            **yara,
            "note": (
                "a scanner binary is present but no rule set is configured on "
                "this device; no scan was performed"
            ),
        }
    return envelope("local_scan", coverage, **results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Spiral Guardian spoke agent")
    parser.add_argument("--transport", default="stdio", choices=("stdio", "streamable-http"))
    parser.add_argument("--host", default="127.0.0.1", help="bind host for HTTP transports")
    parser.add_argument("--port", type=int, default=8001)
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)

    if arguments.transport == "stdio":
        agent.run(transport="stdio")
        return

    loopback = arguments.host in ("127.0.0.1", "::1", "localhost")
    if not loopback and os.getenv("GUARDIAN_AGENT_ALLOW_REMOTE") != "1":
        raise SystemExit(
            f"refusing to bind {arguments.host}: this agent has NO "
            "authentication, so a non-loopback bind exposes local scanning to "
            "the network. Set GUARDIAN_AGENT_ALLOW_REMOTE=1 to override, and "
            "put an authenticating proxy in front of it."
        )
    logger.warning(
        "Guardian agent is starting on %s:%s with NO AUTHENTICATION.",
        arguments.host, arguments.port,
    )
    agent.run(transport="streamable-http", host=arguments.host, port=arguments.port)


if __name__ == "__main__":
    main()
