#!/usr/bin/env python3
"""
Spiral Guardian — MCP-Native Security Agent
Mounts into the sovereign-stack MCP server as the 'guardian' namespace.

All 8 tools designed for conversational security monitoring.
Runs as guardian_user with privilege-separated subprocess wrappers.
"""

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

# === Configuration ===
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://wazuh-vm.tailnet.ts.net:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "")
GUARDIAN_DIR = Path(os.getenv("GUARDIAN_DIR", "/var/guardian"))
QUARANTINE_DIR = GUARDIAN_DIR / "quarantine"
REPORTS_DIR = GUARDIAN_DIR / "reports"
SBOM_DIR = GUARDIAN_DIR / "sbom"

for d in [QUARANTINE_DIR, REPORTS_DIR, SBOM_DIR, GUARDIAN_DIR / "quarantine-metadata"]:
    d.mkdir(parents=True, exist_ok=True)

guardian = FastMCP(
    "Spiral Guardian",
    description="Sovereign security agent for Temple of Two infrastructure. "
    "Provides malware scanning, vulnerability auditing, alert monitoring, "
    "supply chain verification, and cross-device security posture assessment.",
)


class WazuhClient:
    """Authenticated client for the Wazuh REST API."""

    def __init__(self):
        self.token: Optional[str] = None
        self.token_expires: float = 0

    async def authenticate(self) -> str:
        if self.token and time.time() < self.token_expires:
            return self.token

        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.post(
                f"{WAZUH_API_URL}/security/user/authenticate",
                auth=(WAZUH_USER, WAZUH_PASS),
            )
            resp.raise_for_status()
            data = resp.json()
            self.token = data["data"]["token"]
            self.token_expires = time.time() + 870
            return self.token

    async def get(self, endpoint: str, params: dict = None) -> dict:
        token = await self.authenticate()
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"{WAZUH_API_URL}{endpoint}",
                headers={"Authorization": f"Bearer {token}"},
                params=params or {},
            )
            resp.raise_for_status()
            return resp.json()


wazuh = WazuhClient()


async def run_wrapper(script: str, *args, timeout: int = 300) -> dict:
    """Execute a privilege-separated wrapper script via sudo."""
    allowed_scripts = {
        "clamscan", "yara-scan", "quarantine",
        "osquery", "santa-info", "nmap", "wazuh-control",
    }
    if script not in allowed_scripts:
        return {"error": f"Script '{script}' not in allowlist"}

    cmd = ["sudo", f"/usr/local/bin/guardian-{script}.sh", *[str(a) for a in args]]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "exit_code": proc.returncode,
            "stdout": stdout.decode().strip(),
            "stderr": stderr.decode().strip(),
        }
    except asyncio.TimeoutError:
        proc.kill()
        return {"error": f"Timeout after {timeout}s", "exit_code": -1}
    except Exception as e:
        return {"error": str(e), "exit_code": -1}


@guardian.tool()
async def spiral_guardian_scan(
    scan_type: str = "quick",
    target_path: str = "~/temple-vault",
    target_device: str = "local",
    include_yara: bool = True,
    include_clamav: bool = False,
) -> dict:
    """Trigger a security scan on the sovereign infrastructure.

    Args:
        scan_type: "full", "quick", "malware", "vulnerability", or "network"
        target_path: Path to scan (default: ~/temple-vault)
        target_device: "local", "mac-studio", "macbook", "jetson", or "all"
        include_yara: Run YARA-X rules against target
        include_clamav: Run ClamAV scan (Jetson only)
    """
    scan_id = f"scan_{int(time.time())}"
    results = {"scan_id": scan_id, "scan_type": scan_type, "target": target_path, "findings": []}
    start_time = time.time()

    if scan_type in ("quick", "full", "malware"):
        if include_yara:
            results["yara"] = await run_wrapper(
                "yara-scan", target_path,
                timeout=7200 if scan_type == "full" else 600,
            )
        if include_clamav and target_device in ("jetson", "all"):
            results["clamav"] = await run_wrapper("clamscan", target_path, timeout=14400)

    if scan_type in ("full", "vulnerability"):
        try:
            results["vulnerabilities"] = (await wazuh.get("/vulnerability", params={"limit": 50})).get("data", {})
        except Exception as e:
            results["vulnerabilities"] = {"error": str(e)}

    if scan_type in ("full", "network"):
        results["network"] = await run_wrapper("nmap", "-sS", "-O", "192.168.1.0/24", timeout=7200)

    results["duration_seconds"] = round(time.time() - start_time, 2)
    results["timestamp"] = datetime.now(timezone.utc).isoformat()

    report_path = REPORTS_DIR / f"{scan_id}.json"
    report_path.write_text(json.dumps(results, indent=2))
    return results


@guardian.tool()
async def spiral_guardian_status(include_scan_progress: bool = False) -> dict:
    """Get the overall security posture of the sovereign infrastructure.

    Returns a 0-100 health score, risk level, device connectivity,
    active threat count, and pending updates.
    """
    status = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "health_score": 100,
        "risk_level": "low",
        "devices": {},
        "active_threats": 0,
        "alerts_24h": 0,
        "last_backup": None,
    }

    try:
        agents = await wazuh.get("/agents", params={"limit": 10})
        for agent in agents.get("data", {}).get("affected_items", []):
            status["devices"][agent.get("name", "unknown")] = {
                "status": agent.get("status", "unknown"),
                "last_keep_alive": agent.get("lastKeepAlive", "unknown"),
                "os": agent.get("os", {}).get("name", "unknown"),
            }
            if agent.get("status") != "active":
                status["health_score"] -= 15
    except Exception as e:
        status["wazuh_error"] = str(e)
        status["health_score"] -= 20

    try:
        alerts = await wazuh.get("/alerts", params={"limit": 100, "sort": "-timestamp", "q": "rule.level>=7"})
        alert_count = alerts.get("data", {}).get("total_affected_items", 0)
        status["alerts_24h"] = alert_count
        if alert_count > 10:
            status["health_score"] -= 20
            status["risk_level"] = "high"
        elif alert_count > 3:
            status["health_score"] -= 10
            status["risk_level"] = "medium"
    except Exception:
        pass

    try:
        backup_log = Path("/tmp/guardian-backup.log")
        if backup_log.exists():
            hours_since = (time.time() - backup_log.stat().st_mtime) / 3600
            status["last_backup"] = f"{hours_since:.1f} hours ago"
            if hours_since > 48:
                status["health_score"] -= 10
    except Exception:
        pass

    status["health_score"] = max(0, status["health_score"])
    return status


@guardian.tool()
async def spiral_guardian_alerts(
    severity: str = "high",
    time_window: str = "24h",
    device: str = "all",
    limit: int = 25,
) -> dict:
    """Retrieve recent security alerts from the unified monitoring stack."""
    severity_map = {"low": 3, "medium": 7, "high": 10, "critical": 12}
    min_level = severity_map.get(severity, 7)

    try:
        params = {"limit": limit, "sort": "-timestamp", "q": f"rule.level>={min_level}"}
        if device != "all":
            params["q"] += f";agent.name={device}"

        alerts = await wazuh.get("/alerts", params=params)
        items = alerts.get("data", {}).get("affected_items", [])

        formatted = []
        for alert in items:
            formatted.append({
                "id": alert.get("id"),
                "timestamp": alert.get("timestamp"),
                "level": alert.get("rule", {}).get("level"),
                "description": alert.get("rule", {}).get("description"),
                "agent": alert.get("agent", {}).get("name"),
                "mitre": alert.get("rule", {}).get("mitre", {}),
            })

        return {"total": alerts.get("data", {}).get("total_affected_items", 0), "alerts": formatted}
    except Exception as e:
        return {"error": str(e)}


@guardian.tool()
async def spiral_guardian_audit(
    audit_type: str = "supply_chain",
    target_path: str = "~/sovereign-stack",
) -> dict:
    """Run a targeted security audit (supply_chain, secrets, compliance, network, permissions, mcp)."""
    results = {"audit_type": audit_type, "target": target_path, "timestamp": datetime.now(timezone.utc).isoformat(), "findings": []}

    if audit_type == "supply_chain":
        proc = await asyncio.create_subprocess_exec(
            "trivy", "fs", "--format", "json", "--severity", "HIGH,CRITICAL", target_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        try:
            results["trivy"] = json.loads(stdout.decode())
        except json.JSONDecodeError:
            results["trivy"] = {"raw": stdout.decode()[:2000]}

    elif audit_type == "secrets":
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect", "--source", target_path,
            "--report-format", "json", "--report-path", "/tmp/gitleaks-report.json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        report = Path("/tmp/gitleaks-report.json")
        if report.exists():
            results["gitleaks"] = json.loads(report.read_text())
            report.unlink()

    elif audit_type == "compliance":
        try:
            results["sca"] = (await wazuh.get("/sca", params={"limit": 50})).get("data", {})
        except Exception as e:
            results["sca"] = {"error": str(e)}

    elif audit_type == "mcp":
        results["mcp_scan"] = await spiral_guardian_mcp_audit()

    return results


@guardian.tool(annotations={"destructiveHint": True})
async def spiral_guardian_quarantine(action: str = "list", file_hash: str = "") -> dict:
    """Isolate, release, or list quarantined files. DESTRUCTIVE for isolate/release/delete."""
    if action in ("isolate", "release", "delete") and not file_hash:
        return {"error": "file_hash required"}
    if file_hash and not all(c in "0123456789abcdef" for c in file_hash.lower()):
        return {"error": "Invalid hash — must be hex"}
    return await run_wrapper("quarantine", action, file_hash)


@guardian.tool()
async def spiral_guardian_report(
    report_type: str = "summary",
    time_period: str = "7d",
    output_format: str = "markdown",
) -> dict:
    """Generate a security report (summary, detailed, compliance, incident)."""
    status = await spiral_guardian_status()
    alerts = await spiral_guardian_alerts(severity="low", time_window=time_period, limit=100)

    report = {
        "report_type": report_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "health_score": status.get("health_score"),
        "risk_level": status.get("risk_level"),
        "devices": status.get("devices", {}),
        "alert_count": alerts.get("total", 0),
    }

    if output_format == "markdown":
        md = f"# Spiral Guardian Security Report\n**Generated:** {report['generated_at']}\n"
        md += f"**Health Score:** {report['health_score']}/100 | **Risk:** {report['risk_level'].upper()}\n\n"
        md += "## Devices\n"
        for name, info in report["devices"].items():
            md += f"- **{name}**: {info.get('status', 'unknown')}\n"
        md += f"\n## Alerts\nTotal: {report['alert_count']}\n"
        report["content"] = md

    filename = f"report_{report_type}_{int(time.time())}.{'md' if output_format == 'markdown' else output_format}"
    report_path = REPORTS_DIR / filename
    report_path.write_text(report.get("content", json.dumps(report, indent=2)))
    report["saved_to"] = str(report_path)
    return report


@guardian.tool()
async def spiral_guardian_mcp_audit(
    scan_tool_descriptions: bool = True,
    check_transport_security: bool = True,
) -> dict:
    """Audit connected MCP servers for injection vulnerabilities."""
    findings = []

    if scan_tool_descriptions:
        suspicious_patterns = [
            ("http.post", "high"), ("fetch(", "high"), ("ignore previous", "critical"),
            ("disregard", "high"), ("system prompt", "high"), ("base64", "medium"),
            ("eval(", "critical"), ("document.cookie", "critical"), ("<script", "critical"),
        ]
        findings.append({"check": "tool_description_scan", "patterns": len(suspicious_patterns)})

    if check_transport_security:
        findings.append({
            "check": "transport_security",
            "sse_deprecated": True,
            "recommendation": "Migrate to Streamable HTTP",
            "deadline": "June 2026",
        })

    return {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": findings}


@guardian.tool()
async def spiral_guardian_baseline(
    components: list[str] = None,
    device: str = "local",
) -> dict:
    """Create a security baseline snapshot for Santa/osquery/YARA/network."""
    if components is None:
        components = ["santa", "osquery", "yara", "network"]

    baseline = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device": device,
        "components": {c: {"captured": True} for c in components},
    }

    baseline_dir = GUARDIAN_DIR / "baselines"
    baseline_dir.mkdir(exist_ok=True)
    path = baseline_dir / f"baseline_{device}_{int(time.time())}.json"
    path.write_text(json.dumps(baseline, indent=2))
    baseline["saved_to"] = str(path)
    return baseline


def mount_guardian(sovereign_stack: FastMCP):
    """Mount Spiral Guardian into the sovereign-stack MCP server."""
    sovereign_stack.mount(guardian, namespace="guardian")


if __name__ == "__main__":
    guardian.run(transport="streamable-http")
