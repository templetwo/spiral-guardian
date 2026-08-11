"""macOS-native, read-only collectors.

Every function here observes and returns; none of them changes system state,
none requires sudo, and none raises on a missing instrument — absence is
returned as an ``unavailable`` block so it can be reported rather than crash.

Collectors are deliberately split from judgment (see evaluate.py). A collector
returns raw observation; an evaluator turns observation into findings. That
split is what makes the positive-control tests possible: a synthetic
observation can be fed to an evaluator to prove the check CAN fire.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import socket
import sqlite3
import stat
from pathlib import Path

from .config import PROBE_TIMEOUT
from .result import available, unavailable
from .runner import real_path, resolve_tool, run

# Security tools Guardian knows how to use. Presence is a fact worth
# baselining: a tool disappearing from PATH is a posture change.
KNOWN_SECURITY_TOOLS = (
    "gitleaks", "trivy", "restic", "yara", "yr", "clamscan", "freshclam",
    "nmap", "osqueryi", "santactl", "suricata", "falco", "wazuh-control",
    "sqlite3", "lsof", "netstat", "csrutil", "spctl", "codesign",
)

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

LAUNCH_DIRS = (
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
)

# TCC services worth surfacing. Screen Recording and Accessibility live in the
# user database; Full Disk Access lives in the SYSTEM database, which is
# normally unreadable — reported as unavailable rather than as an empty list.
TCC_SERVICES = {
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceListenEvent": "Input Monitoring",
}

TCC_DBS = {
    "user": "~/Library/Application Support/com.apple.TCC/TCC.db",
    "system": "/Library/Application Support/com.apple.TCC/TCC.db",
}


# === helpers ===============================================================


def sha256_file(path: Path) -> str | None:
    """SHA256 of a file, or None if unreadable. Never raises."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _split_host_port(name: str) -> tuple[str, int | None]:
    """Split an lsof address like '127.0.0.1:8100', '*:11434', '[::1]:631'."""
    name = name.strip()
    if name.startswith("["):
        host, _, port = name.rpartition("]:")
        return host.lstrip("["), int(port) if port.isdigit() else None
    host, _, port = name.rpartition(":")
    return host, int(port) if port.isdigit() else None


def classify_bind(host: str) -> str:
    """Classify a bind address as localhost-only or wildcard.

    Wildcard means the socket accepts connections on every interface. It does
    NOT by itself mean reachable from the LAN — a host firewall may still
    block. Reachability from another host is not testable from this host and
    is never claimed.
    """
    if host in ("*", "0.0.0.0", "::", "[::]", ""):
        return "wildcard"
    if host in ("127.0.0.1", "::1", "localhost") or host.startswith("127."):
        return "localhost"
    return "specific"


# === listening ports =======================================================


def collect_lsof_listeners() -> dict:
    """Listening TCP sockets visible to lsof as the CURRENT user.

    Unprivileged lsof cannot see sockets owned by other users (root daemons,
    launchd-held sockets). That blind spot is measured, not assumed — see
    collect_listening_ports(), which cross-checks against netstat.
    """
    if resolve_tool("lsof") is None:
        return unavailable("lsof is not installed")
    # -F gives machine-readable field output; column parsing of lsof is fragile.
    outcome = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcnPt"], timeout=20.0)
    if outcome["timed_out"]:
        return unavailable("lsof timed out")
    if outcome["error"]:
        return unavailable(f"lsof failed: {outcome['error']}")
    # lsof exits non-zero when it finds nothing; that is not an error.
    listeners: list[dict] = []
    pid = command = ip_version = None
    for line in outcome["stdout"].splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            pid = int(value) if value.isdigit() else None
        elif tag == "c":
            command = value
        elif tag == "t":
            ip_version = value
        elif tag == "n":
            host, port = _split_host_port(value)
            if port is None:
                continue
            listeners.append({
                "pid": pid,
                "command": command,
                "ip_version": ip_version,
                "address": value,
                "host": host,
                "port": port,
                "bind_scope": classify_bind(host),
            })
    return available(
        listeners=listeners,
        count=len(listeners),
        scope="sockets owned by uid %d only; other users' sockets are invisible"
        % os.getuid(),
    )


def collect_netstat_listeners() -> dict:
    """Listening TCP sockets per netstat. Sees system sockets lsof cannot."""
    if resolve_tool("netstat") is None:
        return unavailable("netstat is not installed")
    outcome = run(["netstat", "-an", "-p", "tcp"], timeout=20.0)
    if not outcome["ok"]:
        return unavailable(f"netstat failed: {outcome['error'] or outcome['stderr']}")
    listeners = []
    for line in outcome["stdout"].splitlines():
        if "LISTEN" not in line:
            continue
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]  # e.g. 127.0.0.1.8100  or  *.11434  or  ::1.631
        host, _, port = local.rpartition(".")
        if not port.isdigit():
            continue
        listeners.append({
            "proto": fields[0],
            "address": local,
            "host": host,
            "port": int(port),
            "bind_scope": classify_bind(host),
        })
    return available(listeners=listeners, count=len(listeners))


def probe_tcp(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> dict:
    """Connect probe (nc -z semantics) against a local address.

    Port truth is behavioral: a socket held open by launchd on behalf of an
    on-demand job does not appear in unprivileged lsof, but it accepts
    connections. Only a connect attempt settles it.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((host, port))
        return {"host": host, "port": port, "open": code == 0, "errno": code}
    except OSError as exc:
        return {"host": host, "port": port, "open": False, "error": str(exc)}
    finally:
        sock.close()


def primary_lan_address() -> dict:
    """This host's primary LAN IPv4 address, via ipconfig (no packets sent)."""
    for interface in ("en0", "en1"):
        outcome = run(["ipconfig", "getifaddr", interface], timeout=5.0)
        if outcome["ok"] and outcome["stdout"]:
            return available(address=outcome["stdout"], interface=interface)
    return unavailable("no IPv4 address on en0/en1")


def collect_listening_ports(probe: bool = True) -> dict:
    """Full listening-port picture: lsof, netstat cross-check, connect probes.

    The cross-check is the point. Ports netstat sees and lsof does not are
    exactly the ones an unprivileged scan would silently miss, and that count
    is reported rather than absorbed.
    """
    lsof_block = collect_lsof_listeners()
    netstat_block = collect_netstat_listeners()
    lan = primary_lan_address()

    if not lsof_block.get("available") and not netstat_block.get("available"):
        return unavailable(
            "no port enumeration instrument available "
            f"(lsof: {lsof_block.get('reason')}; netstat: {netstat_block.get('reason')})"
        )

    lsof_listeners = lsof_block.get("listeners", []) if lsof_block.get("available") else []
    netstat_listeners = (
        netstat_block.get("listeners", []) if netstat_block.get("available") else []
    )

    by_port: dict[int, dict] = {}
    for entry in lsof_listeners:
        record = by_port.setdefault(entry["port"], {
            "port": entry["port"], "seen_by": [], "bind_scopes": [],
            "processes": [], "addresses": [],
        })
        if "lsof" not in record["seen_by"]:
            record["seen_by"].append("lsof")
        if entry["bind_scope"] not in record["bind_scopes"]:
            record["bind_scopes"].append(entry["bind_scope"])
        if entry["address"] not in record["addresses"]:
            record["addresses"].append(entry["address"])
        proc = {"pid": entry["pid"], "command": entry["command"]}
        if proc not in record["processes"]:
            record["processes"].append(proc)
    for entry in netstat_listeners:
        record = by_port.setdefault(entry["port"], {
            "port": entry["port"], "seen_by": [], "bind_scopes": [],
            "processes": [], "addresses": [],
        })
        if "netstat" not in record["seen_by"]:
            record["seen_by"].append("netstat")
        if entry["bind_scope"] not in record["bind_scopes"]:
            record["bind_scopes"].append(entry["bind_scope"])
        if entry["address"] not in record["addresses"]:
            record["addresses"].append(entry["address"])

    for record in by_port.values():
        record["bind_scope"] = (
            "wildcard" if "wildcard" in record["bind_scopes"] else
            (record["bind_scopes"][0] if record["bind_scopes"] else "unknown")
        )
        record["owner_known"] = bool(record["processes"])
        if not record["owner_known"]:
            record["owner_note"] = (
                "no owning process visible to this unprivileged user; "
                "likely a root-owned or launchd-held socket"
            )

    if probe:
        lan_address = lan.get("address") if lan.get("available") else None
        for record in by_port.values():
            record["probe"] = {
                "localhost_127_0_0_1": probe_tcp("127.0.0.1", record["port"]),
                "lan_from_this_host": (
                    probe_tcp(lan_address, record["port"]) if lan_address
                    else {"skipped": "no LAN address"}
                ),
                # Stated explicitly so no reader infers exposure from a probe
                # that never left this machine.
                "reachability_from_other_hosts": "not_tested",
                "probe_caveat": (
                    "probes originate on this host and are loopback-routed; "
                    "they cannot establish whether a host firewall permits "
                    "connections from other machines"
                ),
            }

    lsof_ports = {entry["port"] for entry in lsof_listeners}
    netstat_ports = {entry["port"] for entry in netstat_listeners}
    return available(
        ports=[by_port[port] for port in sorted(by_port)],
        count=len(by_port),
        cross_check={
            "lsof_available": lsof_block.get("available", False),
            "netstat_available": netstat_block.get("available", False),
            "lsof_port_count": len(lsof_ports),
            "netstat_port_count": len(netstat_ports),
            "seen_by_netstat_only": sorted(netstat_ports - lsof_ports),
            "seen_by_lsof_only": sorted(lsof_ports - netstat_ports),
            "note": (
                "ports in seen_by_netstat_only are invisible to unprivileged "
                "lsof — they are the measure of this scan's blind spot, not an "
                "anomaly in themselves"
            ),
        },
        lan_address=lan,
        probed=probe,
    )


# === launch items ==========================================================


def _parse_plist(path: Path) -> tuple[dict | None, str | None, str | None]:
    """Parse a plist, with a plutil fallback. Returns (data, error, parser).

    plistlib uses expat, which enforces the XML spec strictly. Apple's own
    parser does not. Two plists on this machine contain "--dry-run" and
    "--survey-only" INSIDE XML comment blocks, where a double hyphen is
    illegal XML: expat rejects the whole file, `plutil -lint` says OK, and
    launchd runs them happily.

    Reporting those as unreadable would have been a false finding produced by
    the choice of parser. When the strict parser fails, the system parser is
    tried and the parser actually used is recorded.
    """
    try:
        with path.open("rb") as handle:
            return plistlib.load(handle), None, "plistlib"
    except Exception as strict_error:  # plistlib raises a wide family
        outcome = run(["plutil", "-convert", "json", "-o", "-", str(path)], timeout=10.0)
        if outcome["ok"] and outcome["stdout"]:
            try:
                return (
                    json.loads(outcome["stdout"]),
                    None,
                    f"plutil (plistlib rejected it: {type(strict_error).__name__}: {strict_error})",
                )
            except json.JSONDecodeError:
                pass
        return (
            None,
            f"plistlib: {type(strict_error).__name__}: {strict_error}; "
            f"plutil fallback: {outcome['error'] or outcome['stderr'] or 'produced no JSON'}",
            None,
        )


def collect_launchctl_loaded() -> dict:
    """Labels currently loaded in this user's launchd domain."""
    if resolve_tool("launchctl") is None:
        return unavailable("launchctl is not installed")
    outcome = run(["launchctl", "list"], timeout=15.0)
    if not outcome["ok"]:
        return unavailable(f"launchctl list failed: {outcome['error'] or outcome['stderr']}")
    loaded = {}
    for line in outcome["stdout"].splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        pid_field, status_field, label = fields[0], fields[1], fields[2]
        loaded[label] = {
            "pid": int(pid_field) if pid_field.isdigit() else None,
            "last_exit_status": int(status_field) if status_field.lstrip("-").isdigit() else None,
            "running": pid_field.isdigit(),
        }
    return available(loaded=loaded, count=len(loaded))


def collect_launch_items() -> dict:
    """Inventory LaunchAgents/LaunchDaemons with hashes and parsed contents."""
    loaded_block = collect_launchctl_loaded()
    loaded = loaded_block.get("loaded", {}) if loaded_block.get("available") else {}

    items: list[dict] = []
    dirs_scanned: list[str] = []
    dirs_unreadable: dict[str, str] = {}

    for raw_dir in LAUNCH_DIRS:
        directory = Path(raw_dir).expanduser()
        if not directory.is_dir():
            dirs_unreadable[str(directory)] = "directory does not exist"
            continue
        try:
            entries = sorted(directory.iterdir())
        except PermissionError as exc:
            dirs_unreadable[str(directory)] = f"permission denied: {exc}"
            continue
        dirs_scanned.append(str(directory))
        for entry in entries:
            if not entry.is_file() or not entry.name.endswith(".plist"):
                continue
            parsed, parse_error, parser_used = _parse_plist(entry)
            record = {
                "path": str(entry),
                "sha256": sha256_file(entry),
                "size": entry.stat().st_size if entry.exists() else None,
                "mtime": int(entry.stat().st_mtime) if entry.exists() else None,
                "parser": parser_used,
            }
            if parsed is None:
                # A plist we could not read is an ERROR entry, never an absence.
                record["parse_error"] = parse_error
                record["label"] = None
                items.append(record)
                continue
            label = parsed.get("Label")
            program_arguments = parsed.get("ProgramArguments") or []
            program = parsed.get("Program")
            declared_binary = program or (program_arguments[0] if program_arguments else None)
            record.update({
                "label": label,
                "program_arguments": program_arguments,
                "program": program,
                "declared_binary": declared_binary,
                "declared_binary_real": real_path(declared_binary),
                "declared_binary_exists": bool(
                    declared_binary and Path(declared_binary).exists()
                ),
                "environment_variables": parsed.get("EnvironmentVariables") or {},
                "run_at_load": parsed.get("RunAtLoad"),
                "keep_alive": parsed.get("KeepAlive"),
                "disabled_in_plist": parsed.get("Disabled"),
                "loaded": label in loaded if label else False,
                "launchd_state": loaded.get(label) if label else None,
            })
            items.append(record)

    return available(
        items=items,
        count=len(items),
        dirs_scanned=dirs_scanned,
        dirs_unreadable=dirs_unreadable,
        launchctl=loaded_block if not loaded_block.get("available") else {
            "available": True, "loaded_count": loaded_block.get("count", 0)
        },
    )


def collect_processes() -> dict:
    """Running processes with fully-resolved executable paths and arguments."""
    outcome = run(["ps", "-axo", "pid=,comm="], timeout=20.0)
    if not outcome["ok"]:
        return unavailable(f"ps failed: {outcome['error'] or outcome['stderr']}")
    processes = {}
    for line in outcome["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        pid_text, _, command = line.partition(" ")
        if not pid_text.isdigit():
            continue
        processes[int(pid_text)] = {
            "pid": int(pid_text),
            "executable": command.strip(),
            "executable_real": real_path(command.strip()),
        }
    args_outcome = run(["ps", "-axo", "pid=,args="], timeout=20.0)
    if args_outcome["ok"]:
        for line in args_outcome["stdout"].splitlines():
            line = line.strip()
            pid_text, _, args = line.partition(" ")
            if pid_text.isdigit() and int(pid_text) in processes:
                processes[int(pid_text)]["args"] = args.strip()
    return available(processes=processes, count=len(processes))


# === security posture ======================================================


def collect_sip() -> dict:
    if resolve_tool("csrutil") is None:
        return unavailable("csrutil is not installed (not a macOS system?)")
    outcome = run(["csrutil", "status"], timeout=10.0)
    if not outcome["ok"] and not outcome["stdout"]:
        return unavailable(f"csrutil failed: {outcome['error'] or outcome['stderr']}")
    text = outcome["stdout"]
    return available(raw=text, enabled="enabled" in text.lower() and "disabled" not in text.lower())


def collect_gatekeeper() -> dict:
    if resolve_tool("spctl") is None:
        return unavailable("spctl is not installed")
    outcome = run(["spctl", "--status"], timeout=10.0)
    text = outcome["stdout"] or outcome["stderr"]
    if not text:
        return unavailable(f"spctl produced no output: {outcome['error']}")
    return available(raw=text, assessments_enabled="assessments enabled" in text.lower())


def collect_firewall() -> dict:
    """Application firewall global state and stealth mode."""
    if not Path(SOCKETFILTERFW).is_file():
        return unavailable(f"{SOCKETFILTERFW} not present")
    state = run([SOCKETFILTERFW, "--getglobalstate"], timeout=10.0)
    stealth = run([SOCKETFILTERFW, "--getstealthmode"], timeout=10.0)
    state_text = state["stdout"] or state["stderr"]
    stealth_text = stealth["stdout"] or stealth["stderr"]
    if not state_text and not stealth_text:
        return unavailable("socketfilterfw produced no output")
    return available(
        global_state_raw=state_text,
        stealth_mode_raw=stealth_text,
        enabled=("disabled" not in state_text.lower()) and bool(state_text),
        stealth_enabled="on" in stealth_text.lower() and "off" not in stealth_text.lower(),
    )


def collect_security_tools() -> dict:
    """Which known security tools are on PATH, with resolved paths."""
    present, absent = {}, []
    for tool in KNOWN_SECURITY_TOOLS:
        path = resolve_tool(tool)
        if path:
            present[tool] = {"path": path, "real_path": real_path(path)}
        else:
            absent.append(tool)
    return available(present=present, absent=absent, present_count=len(present))


# === TCC / permissions =====================================================


def collect_tcc(which: str = "user") -> dict:
    """Read a TCC database, honestly.

    Readability is a property of the CALLING process's Full Disk Access grant.
    The same code returns data under one client and unavailable under another;
    that is reported, never smoothed over.
    """
    raw_path = TCC_DBS.get(which)
    if raw_path is None:
        return unavailable(f"unknown TCC database {which!r}")
    path = Path(raw_path).expanduser()
    if not path.exists():
        return unavailable(f"{path} does not exist", db=which)
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        return unavailable(
            f"cannot open {path}: {exc} (the calling process likely lacks Full Disk Access)",
            db=which,
        )
    try:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(access)").fetchall()
        }
        if not columns:
            return unavailable(f"{path} has no 'access' table", db=which)
        # Schema varies across macOS releases: modern uses auth_value,
        # older used allowed. Report which column was actually found.
        auth_column = "auth_value" if "auth_value" in columns else (
            "allowed" if "allowed" in columns else None
        )
        if auth_column is None:
            return unavailable(
                f"{path} 'access' table has neither auth_value nor allowed "
                f"(columns found: {sorted(columns)})",
                db=which,
            )
        placeholders = ",".join("?" for _ in TCC_SERVICES)
        rows = connection.execute(
            f"SELECT service, client, {auth_column} FROM access "  # noqa: S608 - column name from a fixed allowlist
            f"WHERE service IN ({placeholders})",
            tuple(TCC_SERVICES),
        ).fetchall()
    except sqlite3.Error as exc:
        return unavailable(f"query against {path} failed: {exc}", db=which)
    finally:
        connection.close()

    grants: dict[str, list[dict]] = {label: [] for label in TCC_SERVICES.values()}
    for service, client, auth in rows:
        label = TCC_SERVICES.get(service, service)
        grants[label].append({
            "client": client,
            "auth_value": auth,
            "granted": auth in (2, 3),  # 2 = allowed, 3 = limited/allowed
        })
    return available(
        db=which,
        path=str(path),
        auth_column=auth_column,
        columns_found=sorted(columns),
        grants=grants,
        granted_counts={
            label: sum(1 for entry in entries if entry["granted"])
            for label, entries in grants.items()
        },
    )


def collect_file_modes(paths: list[str] | None = None) -> dict:
    """Permission modes on sensitive files, plus a world-writable sweep."""
    targets = paths or [
        "~/.ssh",
        "~/.ssh/id_ed25519",
        "~/.ssh/id_rsa",
        "~/.ssh/config",
        "~/.ssh/authorized_keys",
        "~/.config/sovereign-bridge.env",
        "~/.env",
    ]
    checked, missing = [], []
    for raw in targets:
        path = Path(raw).expanduser()
        if not path.exists():
            missing.append(str(path))
            continue
        try:
            info = path.stat()
        except OSError as exc:
            checked.append({"path": str(path), "error": str(exc)})
            continue
        mode = stat.S_IMODE(info.st_mode)
        checked.append({
            "path": str(path),
            "mode": oct(mode),
            "is_dir": path.is_dir(),
            "group_readable": bool(mode & stat.S_IRGRP),
            "world_readable": bool(mode & stat.S_IROTH),
            "world_writable": bool(mode & stat.S_IWOTH),
        })

    sweep_roots = ["~/.config", "~/.sovereign"]
    world_writable, roots_scanned, roots_absent = [], [], []
    for raw_root in sweep_roots:
        root = Path(raw_root).expanduser()
        if not root.is_dir():
            roots_absent.append(str(root))
            continue
        roots_scanned.append(str(root))
        try:
            entries = list(root.iterdir())
        except PermissionError as exc:
            roots_absent.append(f"{root} (permission denied: {exc})")
            continue
        for entry in entries:
            try:
                mode = stat.S_IMODE(entry.stat().st_mode)
            except OSError:
                continue
            if mode & stat.S_IWOTH:
                world_writable.append({"path": str(entry), "mode": oct(mode)})

    return available(
        files=checked,
        missing=missing,
        world_writable=world_writable,
        sweep={
            "roots_scanned": roots_scanned,
            "roots_absent": roots_absent,
            "depth": 1,
            "note": "top level only, not recursive",
        },
    )


# === MCP server configuration ==============================================


def _normalize_mcp_block(block: dict, source: str, scope: str) -> list[dict]:
    """Normalize a config blob into server records.

    Handles BOTH shapes seen on this machine: the standard
    ``{"mcpServers": {...}}`` wrapper and the bare ``{name: {...}}`` map used
    by ~/t2helix/.mcp.json. Guessing one shape would have silently dropped
    the other.
    """
    if not isinstance(block, dict):
        return []
    servers = block.get("mcpServers") if isinstance(block.get("mcpServers"), dict) else block
    records = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        if not any(key in spec for key in ("command", "url", "type", "args", "transport")):
            continue
        transport = spec.get("type") or spec.get("transport")
        if not transport:
            transport = "stdio" if spec.get("command") else ("http" if spec.get("url") else "unknown")
        records.append({
            "name": name,
            "source": source,
            "scope": scope,
            "transport": transport,
            # Variables are reported RAW and unresolved: ${HOME} in a config is
            # not the same fact as its expansion, and expanding it here would
            # invent a path this tool never verified.
            "command": spec.get("command"),
            "args": spec.get("args", []),
            "url": spec.get("url"),
            "env_keys": sorted(spec.get("env", {}).keys()) if isinstance(spec.get("env"), dict) else [],
            "env": spec.get("env", {}) if isinstance(spec.get("env"), dict) else {},
        })
    return records


def collect_mcp_servers() -> dict:
    """Enumerate MCP servers configured on this machine.

    Sources: ~/.claude.json (global + per-project), any .mcp.json within depth
    3 of the home directory, and plugin-bundled .mcp.json files under
    ~/.claude/plugins (which sit deeper than depth 3 and would otherwise be
    missed entirely).
    """
    servers: list[dict] = []
    sources_read: list[str] = []
    sources_failed: dict[str, str] = {}

    claude_json = Path("~/.claude.json").expanduser()
    if claude_json.is_file():
        try:
            data = json.loads(claude_json.read_text())
            sources_read.append(str(claude_json))
            servers.extend(
                _normalize_mcp_block(
                    {"mcpServers": data.get("mcpServers", {})}, str(claude_json), "global"
                )
            )
            for project_path, project in (data.get("projects") or {}).items():
                if isinstance(project, dict) and project.get("mcpServers"):
                    servers.extend(
                        _normalize_mcp_block(
                            {"mcpServers": project["mcpServers"]},
                            str(claude_json),
                            f"project:{project_path}",
                        )
                    )
        except (OSError, json.JSONDecodeError) as exc:
            sources_failed[str(claude_json)] = f"{type(exc).__name__}: {exc}"
    else:
        sources_failed[str(claude_json)] = "does not exist"

    home = Path("~").expanduser()
    candidates: list[Path] = []
    for depth in range(1, 4):
        candidates.extend(home.glob("/".join(["*"] * (depth - 1) + [".mcp.json"])))
    plugins_root = home / ".claude" / "plugins"
    if plugins_root.is_dir():
        candidates.extend(plugins_root.rglob(".mcp.json"))

    for candidate in sorted(set(candidates)):
        if not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            sources_failed[str(candidate)] = f"{type(exc).__name__}: {exc}"
            continue
        sources_read.append(str(candidate))
        scope = "plugin" if plugins_root in candidate.parents else "project-file"
        servers.extend(_normalize_mcp_block(data, str(candidate), scope))

    return available(
        servers=servers,
        count=len(servers),
        sources_read=sorted(set(sources_read)),
        sources_failed=sources_failed,
        limits={
            "tool_descriptions_scanned": False,
            "tool_descriptions_reason": (
                "reading a server's tool descriptions requires launching that "
                "server and completing an MCP handshake; this audit is "
                "read-only and starts nothing. Patterns are applied to the "
                "CONFIGURATION only (name, command, args, env, url)."
            ),
            "variables_unresolved": (
                "${HOME}, ${CLAUDE_PLUGIN_ROOT} and similar are reported as "
                "written; they are not expanded"
            ),
            "home_glob_depth": 3,
        },
    )
