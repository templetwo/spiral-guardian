"""Backward-compatible entry point for the v1.0.0 spoke-agent module path.

The implementation moved to ``spiral_guardian.agent`` in v1.1.0. See that
module for the security note: v1.0.0 bound an unauthenticated MCP server to
port 8001 by default; the agent now defaults to stdio and refuses a
non-loopback bind without an explicit override.
"""

from __future__ import annotations

from spiral_guardian.agent import agent, main

__all__ = ["agent", "main"]


if __name__ == "__main__":
    main()
