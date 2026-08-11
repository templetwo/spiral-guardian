"""Pure evaluation functions: observation in, findings out.

Nothing here touches the system. Every function is deterministic given its
arguments, which is what makes the positive controls possible — a synthetic
observation can be fed in to prove a check CAN fire. A gate that has never
been shown to fail is not a gate (house experimental law #2).
"""

from __future__ import annotations

import json
import re
from typing import Any

from .result import is_available

# === MCP suspicious patterns ==============================================
# The nine patterns declared (and never applied) by v1.0.0's stub. In v1.1.0
# they are matched against real enumerated configuration.
SUSPICIOUS_PATTERNS: tuple[tuple[str, str], ...] = (
    ("http.post", "high"),
    ("fetch(", "high"),
    ("ignore previous", "critical"),
    ("disregard", "high"),
    ("system prompt", "high"),
    ("base64", "medium"),
    ("eval(", "critical"),
    ("document.cookie", "critical"),
    ("<script", "critical"),
)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Environment variable names that declare where a service BINDS.
# ORIGINS is deliberately excluded: it is a CORS allowlist, not a bind address,
# and treating it as one would manufacture findings.
_BIND_KEY = re.compile(r"(HOST|ADDR|ADDRESS|BIND|LISTEN|PORT)$")
_EXCLUDED_KEY = re.compile(r"(ORIGIN|ORIGINS|PROTO|SCHEME)$")


def _classify_declared_host(host: str) -> str:
    from .collectors import classify_bind

    return classify_bind(host)


# Executables that report THEMSELVES as the running binary while actually
# executing a script named on their command line.
_INTERPRETERS = (
    "python", "node", "ruby", "perl", "bash", "sh", "zsh", "java", "deno", "bun", "osascript",
)


def compare_binary(
    declared: str | None,
    declared_real: str | None,
    actual_real: str | None,
    argv: str | None,
) -> tuple[str, str]:
    """Compare a plist's declared binary against what is actually running.

    Returns ``(verdict, explanation)``. Verdicts other than ``mismatch`` are
    NOT findings.

    Two ways a naive comparison manufactures false drift, both observed live
    on this machine:

    * symlinks — /usr/local/bin/ollama points into /Applications/Ollama.app,
      so the strings differ while the binary is identical.
    * interpreters — a launchd job declaring a venv console script runs as
      .../Python with the script as argv[1]. ``ps -o comm=`` reports the
      interpreter, so every Python daemon looks like a mismatch. Before this
      was fixed, this check reported the sovereign-bridge and sovereign-sse
      daemons as HIGH-severity binary drift. They were fine.
    """
    if not declared_real or not actual_real:
        return "unknown", "declared or actual binary path unavailable"
    if declared_real == actual_real:
        return "match", "identical after symlink resolution"
    candidates = [path for path in (declared, declared_real) if path]
    if argv and any(path in argv for path in candidates):
        return (
            "match_via_argv",
            "the declared binary appears in the running command line; the "
            "executable reported by ps is its interpreter",
        )
    actual_name = actual_real.rsplit("/", 1)[-1].lower()
    if declared_real.rsplit("/", 1)[-1] == actual_real.rsplit("/", 1)[-1]:
        return "match_basename", "same executable name via a different path"
    if any(interpreter in actual_name for interpreter in _INTERPRETERS):
        return (
            "inconclusive_interpreter",
            f"the running executable is an interpreter ({actual_real}) and the "
            "declared binary was not found in its command line; this cannot be "
            "resolved to a match or a mismatch from process metadata alone",
        )
    return "mismatch", "the running executable is not the declared binary"


def extract_declared_endpoints(env: dict) -> list[dict]:
    """Parse bind endpoints out of a plist's EnvironmentVariables.

    Recognizes ``HOST=127.0.0.1:11434``, ``HOST=0.0.0.0``, ``PORT=8080``.
    """
    endpoints = []
    for key, value in (env or {}).items():
        if not isinstance(value, str) or not value:
            continue
        if _EXCLUDED_KEY.search(key) or not _BIND_KEY.search(key):
            continue
        host, port = None, None
        text = value.strip()
        if text.isdigit():
            port = int(text)
        elif ":" in text:
            candidate_host, _, candidate_port = text.rpartition(":")
            if candidate_port.isdigit():
                host, port = candidate_host, int(candidate_port)
            else:
                host = text
        else:
            host = text
        endpoints.append({
            "env_key": key,
            "env_value": value,
            "declared_host": host,
            "declared_port": port,
            "declared_scope": _classify_declared_host(host) if host else None,
        })
    return endpoints


def evaluate_drift(
    launch_items: list[dict],
    ports: list[dict],
    processes: dict[int, dict] | None = None,
) -> list[dict]:
    """Detect config-with-no-reader drift between declared and actual state.

    Five distinct classes, deliberately not collapsed:

    * ``declared_not_loaded``   — a plist configures a service that launchd is
      not running. Its settings govern nothing. (SOP #12: a config that assumes
      a merge / a valve connected to nothing.)
    * ``declared_binary_missing`` — the plist names a binary that is not there.
    * ``binary_mismatch``      — the running process is not the binary the
      plist declares, compared AFTER symlink resolution.
    * ``bind_mismatch``        — the plist declares a bind address, and the
      actual listener on that port binds more broadly.
    * ``declared_port_absent`` — the declared port has no listener at all.
    """
    processes = processes or {}
    ports_by_number = {entry["port"]: entry for entry in ports}
    findings: list[dict] = []

    for item in launch_items:
        label = item.get("label")
        if not label:
            continue
        env = item.get("environment_variables") or {}
        endpoints = extract_declared_endpoints(env)
        declares_service_config = bool(env)

        base = {
            "label": label,
            "plist": item.get("path"),
            "plist_sha256": item.get("sha256"),
        }

        if declares_service_config and not item.get("loaded"):
            findings.append({
                **base,
                "class": "declared_not_loaded",
                "severity": "medium",
                "detail": (
                    f"{item.get('path')} sets environment ({sorted(env)}) for "
                    f"{label}, but the label is not loaded in launchd. Nothing "
                    "reads this configuration; any setting it appears to "
                    "enforce is not enforced."
                ),
                "declared_environment": env,
                "evidence": {"loaded": False, "launchctl_state": item.get("launchd_state")},
            })

        if item.get("declared_binary") and not item.get("declared_binary_exists"):
            findings.append({
                **base,
                "class": "declared_binary_missing",
                "severity": "high" if item.get("loaded") else "low",
                "detail": (
                    f"{label} declares binary {item.get('declared_binary')} "
                    "which does not exist on disk."
                ),
                "declared_binary": item.get("declared_binary"),
                "evidence": {"loaded": item.get("loaded")},
            })

        state = item.get("launchd_state") or {}
        running_pid = state.get("pid")
        if running_pid and running_pid in processes:
            process = processes[running_pid]
            declared_real = item.get("declared_binary_real")
            actual_real = process.get("executable_real")
            verdict, explanation = compare_binary(
                item.get("declared_binary"), declared_real, actual_real, process.get("args")
            )
            if verdict in ("mismatch", "inconclusive_interpreter"):
                findings.append({
                    **base,
                    "class": (
                        "binary_mismatch" if verdict == "mismatch"
                        else "binary_comparison_inconclusive"
                    ),
                    "severity": "high" if verdict == "mismatch" else "info",
                    "detail": (
                        f"{label} is running pid {running_pid} executing "
                        f"{actual_real}, but the plist declares {declared_real}. "
                        f"{explanation}."
                    ),
                    "verdict": verdict,
                    "declared_binary_real": declared_real,
                    "actual_binary_real": actual_real,
                    "actual_argv": process.get("args"),
                    "evidence": {"pid": running_pid},
                })

        for endpoint in endpoints:
            port = endpoint.get("declared_port")
            if port is None:
                continue
            listener = ports_by_number.get(port)
            if listener is None:
                findings.append({
                    **base,
                    "class": "declared_port_absent",
                    "severity": "info",
                    "detail": (
                        f"{label} declares {endpoint['env_key']}="
                        f"{endpoint['env_value']} but nothing is listening on "
                        f"port {port}."
                    ),
                    **endpoint,
                })
                continue
            actual_scope = listener.get("bind_scope")
            declared_scope = endpoint.get("declared_scope")
            if declared_scope == "localhost" and actual_scope == "wildcard":
                owners = [
                    process.get("command")
                    for process in listener.get("processes", [])
                    if process.get("command")
                ]
                findings.append({
                    **base,
                    "class": "bind_mismatch",
                    "severity": "high",
                    "detail": (
                        f"{label} declares {endpoint['env_key']}="
                        f"{endpoint['env_value']} (localhost only), but the "
                        f"actual listener on port {port} binds WILDCARD "
                        f"({', '.join(listener.get('addresses', [])) or 'unknown'}). "
                        "The declared restriction is not in effect."
                    ),
                    **endpoint,
                    "actual_scope": actual_scope,
                    "actual_addresses": listener.get("addresses", []),
                    "actual_processes": owners,
                    "evidence": {
                        "listener": {
                            key: listener.get(key)
                            for key in ("port", "bind_scope", "addresses", "seen_by")
                        }
                    },
                })

    findings.sort(key=lambda finding: -SEVERITY_ORDER.get(finding["severity"], 0))
    return findings


def evaluate_port_exposure(ports: list[dict]) -> list[dict]:
    """Flag wildcard binds. Says nothing about off-host reachability."""
    findings = []
    for entry in ports:
        if entry.get("bind_scope") != "wildcard":
            continue
        owners = [
            process.get("command")
            for process in entry.get("processes", [])
            if process.get("command")
        ]
        findings.append({
            "class": "wildcard_bind",
            "severity": "medium",
            "port": entry["port"],
            "addresses": entry.get("addresses", []),
            "processes": owners or None,
            "owner_known": entry.get("owner_known", False),
            "detail": (
                f"port {entry['port']} binds on all interfaces"
                + (f" (owner: {', '.join(owners)})" if owners else
                   " (owning process not visible to this unprivileged user)")
            ),
            "reachability_from_other_hosts": "not_tested",
            "caveat": (
                "a wildcard bind is not proof of network exposure; the host "
                "firewall may still refuse connections from other machines"
            ),
        })
    return findings


def evaluate_mcp_servers(servers: list[dict]) -> list[dict]:
    """Apply the suspicious-pattern list to enumerated MCP configuration."""
    findings = []
    for server in servers:
        haystack = json.dumps({
            "name": server.get("name"),
            "command": server.get("command"),
            "args": server.get("args"),
            "url": server.get("url"),
            "env": server.get("env"),
        }).lower()
        for pattern, severity in SUSPICIOUS_PATTERNS:
            if pattern.lower() in haystack:
                findings.append({
                    "class": "suspicious_pattern",
                    "severity": severity,
                    "pattern": pattern,
                    "server": server.get("name"),
                    "source": server.get("source"),
                    "scanned_surface": "configuration (name, command, args, url, env)",
                    "detail": (
                        f"pattern {pattern!r} appears in the configuration of "
                        f"MCP server {server.get('name')!r}"
                    ),
                })
        url = server.get("url") or ""
        if url.startswith("http://") and "127.0.0.1" not in url and "localhost" not in url:
            findings.append({
                "class": "cleartext_transport",
                "severity": "high",
                "server": server.get("name"),
                "source": server.get("source"),
                "detail": f"MCP server {server.get('name')!r} uses cleartext HTTP to a non-local host: {url}",
            })
        if str(server.get("transport", "")).lower() == "sse":
            findings.append({
                "class": "deprecated_transport",
                "severity": "low",
                "server": server.get("name"),
                "source": server.get("source"),
                "detail": (
                    f"MCP server {server.get('name')!r} uses the deprecated SSE "
                    "transport; Streamable HTTP is the replacement"
                ),
            })
    findings.sort(key=lambda finding: -SEVERITY_ORDER.get(finding["severity"], 0))
    return findings


# === baseline fingerprints and diffing ====================================


def fingerprint_component(name: str, block: Any) -> dict[str, str] | None:
    """Reduce a collected component to a stable, comparable fingerprint.

    Volatile fields (timestamps, PIDs, probe results) are excluded so that a
    diff reports posture changes rather than noise. Returns None when the
    component was not collected — which the differ treats as
    "not collected", never as "changed".
    """
    if not is_available(block):
        return None
    if name == "listening_ports":
        return {
            f"port:{entry['port']}": "|".join([
                entry.get("bind_scope", "?"),
                ",".join(sorted(
                    process.get("command") or "?" for process in entry.get("processes", [])
                )) or "unknown-owner",
            ])
            for entry in block.get("ports", [])
        }
    if name == "launch_items":
        return {
            f"plist:{item['path']}": (item.get("sha256") or f"UNREADABLE:{item.get('parse_error')}")
            for item in block.get("items", [])
        }
    if name == "security_tools":
        return {
            f"tool:{tool}": info.get("real_path") or info.get("path") or "?"
            for tool, info in block.get("present", {}).items()
        }
    if name == "system_integrity_protection":
        return {"sip": str(block.get("enabled"))}
    if name == "gatekeeper":
        return {"gatekeeper": str(block.get("assessments_enabled"))}
    if name == "firewall":
        return {
            "firewall_enabled": str(block.get("enabled")),
            "stealth_mode": str(block.get("stealth_enabled")),
        }
    if name in ("tcc_user", "tcc_system"):
        fingerprint = {}
        for service, entries in block.get("grants", {}).items():
            granted = sorted(entry["client"] for entry in entries if entry.get("granted"))
            fingerprint[f"tcc:{service}"] = ",".join(granted)
        return fingerprint
    if name == "file_modes":
        fingerprint = {
            f"mode:{entry['path']}": entry.get("mode", "?")
            for entry in block.get("files", []) if "mode" in entry
        }
        for entry in block.get("world_writable", []):
            fingerprint[f"world_writable:{entry['path']}"] = entry.get("mode", "?")
        return fingerprint
    if name == "mcp_servers":
        return {
            f"mcp:{server['source']}::{server['name']}": "|".join([
                str(server.get("transport")),
                str(server.get("command")),
                " ".join(str(argument) for argument in server.get("args", [])),
                str(server.get("url")),
            ])
            for server in block.get("servers", [])
        }
    return None


def diff_fingerprints(old: dict[str, str], new: dict[str, str]) -> dict:
    """Set/value diff between two fingerprints."""
    old_keys, new_keys = set(old), set(new)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = sorted(
        key for key in old_keys & new_keys if old[key] != new[key]
    )
    return {
        "added": [{"key": key, "value": new[key]} for key in added],
        "removed": [{"key": key, "value": old[key]} for key in removed],
        "changed": [
            {"key": key, "from": old[key], "to": new[key]} for key in changed
        ],
        "change_count": len(added) + len(removed) + len(changed),
    }


def diff_baseline(old_baseline: dict, new_baseline: dict) -> dict:
    """Compare two baselines component by component.

    Four per-component statuses, kept distinct on purpose. Collapsing
    ``not_collected_this_run`` into ``changed`` would be the same fail-open
    shape this release exists to remove: an instrument that went missing would
    be reported as a security change that did not happen.
    """
    old_components = old_baseline.get("components", {})
    new_components = new_baseline.get("components", {})
    results: dict[str, dict] = {}

    for name in sorted(set(old_components) | set(new_components)):
        old_block = old_components.get(name)
        new_block = new_components.get(name)
        old_fingerprint = fingerprint_component(name, old_block) if old_block else None
        new_fingerprint = fingerprint_component(name, new_block) if new_block else None

        if new_fingerprint is None:
            reason = (
                new_block.get("reason", "component absent from this run")
                if isinstance(new_block, dict) else "component absent from this run"
            )
            results[name] = {
                "status": "not_collected_this_run",
                "reason": reason,
                "note": "this is a coverage gap, NOT an observed change",
            }
            continue
        if old_fingerprint is None:
            results[name] = {
                "status": "no_prior_baseline",
                "reason": (
                    old_block.get("reason", "not present in stored baseline")
                    if isinstance(old_block, dict) else "not present in stored baseline"
                ),
                "note": "nothing to compare against; recorded for next run",
            }
            continue
        difference = diff_fingerprints(old_fingerprint, new_fingerprint)
        results[name] = {
            "status": "changed" if difference["change_count"] else "unchanged",
            **difference,
        }

    changed = [name for name, result in results.items() if result["status"] == "changed"]
    uncollected = [
        name for name, result in results.items()
        if result["status"] == "not_collected_this_run"
    ]
    return {
        "components": results,
        "changed_components": changed,
        "uncollected_components": uncollected,
        "total_changes": sum(
            result.get("change_count", 0) for result in results.values()
        ),
        "comparable": not uncollected,
        "summary": (
            f"{len(changed)} component(s) changed, "
            f"{len(uncollected)} component(s) could not be collected this run"
            + ("" if not uncollected else " — the diff is INCOMPLETE")
        ),
    }
