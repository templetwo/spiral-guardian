#!/usr/bin/env python3
"""
Spiral Guardian Lightweight Agent
Runs on spoke devices (MacBook Pro, Jetson Orin Nano).
Exposes a minimal MCP interface for remote scanning from the hub.
"""

import asyncio
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

agent = FastMCP(
    "Guardian Agent",
    description="Lightweight spoke agent for Spiral Guardian. "
    "Provides local scanning and status for remote orchestration.",
)


async def _run(cmd: list[str], timeout: int = 300) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {"exit_code": proc.returncode, "stdout": stdout.decode().strip(), "stderr": stderr.decode().strip()}
    except asyncio.TimeoutError:
        proc.kill()
        return {"error": f"Timeout after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


@agent.tool()
async def local_scan(scan_type: str = "quick", target_path: str = "/") -> dict:
    """Run a local security scan on this device."""
    results = {"device": platform.node(), "scan_type": scan_type, "timestamp": datetime.now(timezone.utc).isoformat()}

    if scan_type in ("quick", "malware"):
        results["yara"] = await _run(["yr", "scan", str(Path.home() / "guardian/yara-rules/rules/malware/"), target_path])

    return results


@agent.tool()
async def local_status() -> dict:
    """Return this device's security status."""
    return {
        "device": platform.node(),
        "platform": platform.system(),
        "architecture": platform.machine(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "wazuh_agent": (await _run(["pgrep", "-x", "wazuh-agentd"])).get("exit_code") == 0,
    }


if __name__ == "__main__":
    agent.run(transport="streamable-http", port=8001)
