"""Spiral Guardian — MCP-native defensive security agent.

Design law (inherited from the house, earned the hard way):
a surface must be INCAPABLE of reporting success on a failed operation,
or completeness on a partial one. Every tool in this package returns a
`coverage` block stating what was checked and what could not be, and any
capability whose backing instrument is absent returns
``{"available": False, "reason": ...}`` — never a fabricated result,
never a silent skip, never an unhandled crash.
"""

__version__ = "1.1.0"

__all__ = ["__version__"]
