# Spiral Guardian

MCP-native security agent for the Temple of Two research infrastructure. Runs read-only
against the machine it is installed on and answers security questions in natural language
from any Claude conversation.

**Version 1.1.0.** This README states what works *today*, on this hardware, verified by
running it. Anything not proven is labelled as not proven.

## The design rule everything here follows

**A surface must be incapable of reporting success on a failed operation, or completeness on
a partial one.** Every tool returns an explicit availability block. When a backing instrument
is absent, the response says so with a reason:

```json
{"available": false, "reason": "trivy is not installed on this machine (needed for filesystem vulnerability scanning)"}
```

Never a fake result, never a silent skip, never a crash. Every response carries what was
checked and what could not be.

## What works today (verified on Mac Studio, 2026-08-10)

| Tool | State | Notes |
|---|---|---|
| `spiral_guardian_drift` | **Working** | New in 1.1.0. Finds config-with-no-reader drift and bind-scope truth. |
| `spiral_guardian_baseline` | **Working** | Captures real state; second run diffs against the stored baseline. |
| `spiral_guardian_mcp_audit` | **Working** | Enumerates MCP servers actually configured on the machine. |
| `spiral_guardian_audit` | **Working** | `network`, `permissions`, `secrets` (gitleaks), `compliance`, `mcp`, `supply_chain` (trivy). |
| `spiral_guardian_quarantine` | **Working** | Hash-validated isolate/release/list. Needs the sudoers install to act. |
| `spiral_guardian_report` | **Working** | Branches on `report_type`; composes from live tool output. |
| `spiral_guardian_status` | **Degrades honestly** | Wazuh not deployed → reports unavailable with reason. |
| `spiral_guardian_alerts` | **Degrades honestly** | Same. `time_window` is now honored in the query. |
| `spiral_guardian_scan` | **Partial, honest** | YARA path real when `yr`/`yara` present; ClamAV/nmap report unavailable. |

### The drift tool, and why it exists

On 2026-04-02 a sweep found Ollama listening on `0.0.0.0:11434` and fixed it by rewriting
`~/Library/LaunchAgents/com.ollama.server.plist` to bind localhost. On 2026-08-10 — 130 days
later — the machine was still serving on `*:11434`. The plist was never wrong. The process
reading it was never running: the live listener is the GUI app, which does not read the
LaunchAgent environment.

**A fix that governs a process which is not the one running is not a fix.** `drift` hunts that
shape:

- **`bind_mismatch`** — a launch item declares a bind restriction; the actual listener on that
  port is wider. Bind scope is established *behaviorally* (connect probe), never inferred from
  a process list — unprivileged `lsof` cannot see launchd-held sockets.
- **`declared_not_loaded`** — a plist sets configuration for a label that is not loaded.
  Nothing reads it; anything it appears to enforce is not enforced.
- **`binary_mismatch`** — the running process is not the binary the plist declares.
  Symlinks and interpreter-running-declared-script resolve as *matches*; genuinely ambiguous
  cases return **inconclusive**, never a mismatch.

## Not deployed, and honest about it

Wazuh, osquery, Santa, Suricata, Falco, and ClamAV are **not installed** on any machine in
this infrastructure. The client code and config templates for Wazuh are real and tested
against a mock; the rest exist as integration paths in
`SPIRAL_GUARDIAN_IMPLEMENTATION.md` and nothing more. Tools that depend on them report
unavailable. The 4-phase plan in that document describes intent, not deployment.

## Install

```bash
python3.12 -m venv venv
./venv/bin/pip install -e '.[dev]'
./venv/bin/python -m pytest        # 143 tests
```

`GUARDIAN_HOME` (default `~/.sovereign/guardian`) holds baselines, reports, and quarantine
metadata. Directories are created lazily at first use — importing the module has no side
effects and requires no privilege. v1.0.0 created `/var/guardian/*` at import time, which is
why it could never start as the unprivileged user it was designed for.

## Privilege

`config/guardian.sudoers` allowlists exactly the wrapper scripts that exist in `scripts/`.
It is **not installed** on any machine. Until it is, quarantine and YARA report unavailable
rather than blocking on a password prompt. Installing it is a privileged system change and no
Guardian tool performs it.

## Testing

143 tests. Every tool has an import/registration test and an honest-degradation test (backing
tool absent → `available: false`, not a crash and not a fake result). The drift detector
carries negative controls proving it stays silent on clean input — a gate that cannot fail,
and a gate that always fires, are both broken.
