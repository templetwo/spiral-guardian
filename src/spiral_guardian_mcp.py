"""Backward-compatible entry point for the v1.0.0 module path.

v1.0.0 shipped a single 393-line module at this path. v1.1.0 splits it into
the ``spiral_guardian`` package (config / result / runner / collectors /
evaluate / wazuh / tools / server) so that judgment is separable from
observation and therefore testable.

This shim exists so any existing reference to ``src/spiral_guardian_mcp.py``
keeps working. It re-exports the server object and the mount helper. Unlike
v1.0.0, importing it creates no directories and touches nothing.
"""

from __future__ import annotations

from spiral_guardian import __version__
from spiral_guardian.server import guardian, main

__all__ = ["guardian", "main", "mount_guardian", "__version__"]


def mount_guardian(host) -> None:
    """Mount Spiral Guardian's tools into a host MCP server.

    v1.0.0 called ``host.mount(guardian, namespace="guardian")``. The MCP 2.x
    server object has no ``mount``; composition is done by re-registering the
    tool callables on the host. If the host does expose ``mount``, that path is
    preferred. Raises rather than silently mounting nothing.
    """
    if hasattr(host, "mount"):
        host.mount(guardian, namespace="guardian")
        return
    if not hasattr(host, "add_tool"):
        raise TypeError(
            f"host {type(host).__name__} exposes neither mount() nor add_tool(); "
            "cannot compose Spiral Guardian into it"
        )
    from spiral_guardian import tools as _tools

    for name, implementation in (
        ("spiral_guardian_status", _tools.status_impl),
        ("spiral_guardian_alerts", _tools.alerts_impl),
        ("spiral_guardian_drift", _tools.drift_impl),
        ("spiral_guardian_baseline", _tools.baseline_impl),
        ("spiral_guardian_audit", _tools.audit_impl),
        ("spiral_guardian_mcp_audit", _tools.mcp_audit_impl),
        ("spiral_guardian_scan", _tools.scan_impl),
        ("spiral_guardian_report", _tools.report_impl),
        ("spiral_guardian_quarantine", _tools.quarantine_impl),
    ):
        host.add_tool(implementation, name=name)


if __name__ == "__main__":
    main()
