# Changelog

All notable changes and deviations from the implementation plan will be documented here.

## [1.1.0] - 2026-08-10

Delivery pass on the Mac Studio. v1.0.0 was a scaffold that had never been executed: it
created `/var/guardian/*` at import time and so could not start as the unprivileged user it
was designed for, declared no dependencies, and shipped two tools that returned canned
dictionaries without scanning anything.

### Added
- `spiral_guardian_drift` — finds config-with-no-reader drift: `bind_mismatch`,
  `declared_not_loaded`, `binary_mismatch`. Bind scope is established by connect probe, not
  inferred from a process list. Born from a live case: a 130-day-old "fix" to Ollama's bind
  address that governed a process which was not the one running.
- `pyproject.toml` declaring `mcp` and `httpx`; `GUARDIAN_HOME` (default
  `~/.sovereign/guardian`) replacing every `/var/guardian` path; lazy directory creation.
- 143 tests, including honest-degradation tests per tool and negative controls proving the
  drift detector stays silent on clean input.
- README stating verified capability, and what is not deployed.

### Changed
- `baseline` and `mcp_audit` were stubs; both now collect real state. `baseline` diffs against
  the stored capture on second run; `mcp_audit` enumerates the MCP servers actually configured.
- `audit` gained working `network` and `permissions` branches (previously documented and
  silently empty). `alerts` now honors `time_window`. `report` now branches on `report_type`.
- Every tool returns an explicit availability block with a reason when a backing instrument is
  absent, and a coverage statement — no silent skips, no fabricated results.
- TLS verification is on by default (v1.0.0 hardcoded `verify=False` on every client).
  Absent credentials report unavailable instead of defaulting to an empty password.
- Timeouts on all subprocess and HTTP calls.
- `config/guardian.sudoers` trimmed to the two wrapper scripts that exist. The five removed
  entries named paths that were never written — a standing grant that would activate the
  moment anything with write access created that filename.

### Fixed
- Dangling references: the `config/Caddyfile` and "Appendix B" pointers, and the six §6.x
  section bodies that read "full details in this same document."

### Not done
- Wazuh, osquery, Santa, Suricata, Falco, ClamAV remain undeployed on all machines. Their
  integration paths are prose; tools depending on them report unavailable.
- The sudoers file is not installed. Quarantine and YARA therefore report unavailable.
- The spoke agent still binds `:8001` without auth and is not deployed.

## [1.0.0] - 2026-04-02

### Added
- Initial implementation plan (SPIRAL_GUARDIAN_IMPLEMENTATION.md)
- Core MCP server with 8 tools (src/spiral_guardian_mcp.py)
- Lightweight spoke agent (src/guardian_agent.py)
- Repository structure per Appendix B
