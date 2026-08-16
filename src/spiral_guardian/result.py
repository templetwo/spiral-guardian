"""Honesty primitives.

The single most important module in this package. Every result shape that can
report partial knowledge is built from these, so that no caller can mistake
"I could not look" for "I looked and found nothing".
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def unavailable(reason: str, **extra: Any) -> dict:
    """A capability that could not be exercised.

    Callers MUST branch on ``available``; there is no result payload to
    misread as an empty-but-successful answer.
    """
    return {"available": False, "reason": reason, **extra}


def available(**payload: Any) -> dict:
    """A capability that was exercised. Payload is real, collected data."""
    return {"available": True, **payload}


def is_available(block: Any) -> bool:
    return isinstance(block, dict) and block.get("available") is True


class Coverage:
    """Accumulates what was checked, what was not, and why.

    Attached to every tool response as ``coverage``. ``complete`` is True only
    when every requested capability was exercised without error, so a partial
    answer can never present itself as a whole one.
    """

    def __init__(self) -> None:
        self.checked: list[str] = []
        self.unavailable: dict[str, str] = {}
        self.errors: dict[str, str] = {}

    def check(self, name: str) -> None:
        """Record that capability `name` was successfully exercised."""
        if name not in self.checked:
            self.checked.append(name)

    def skip(self, name: str, reason: str) -> None:
        """Record that capability `name` could not be exercised, and why."""
        self.unavailable[name] = reason

    def error(self, name: str, err: str) -> None:
        """Record that capability `name` was attempted and failed."""
        self.errors[name] = err

    def record(self, name: str, block: dict) -> dict:
        """Record a capability from its own result block, and return it.

        Convenience for the common shape:
            cov.record("firewall", collect_firewall())
        """
        if is_available(block):
            self.check(name)
        else:
            self.skip(name, block.get("reason", "unknown"))
        return block

    @property
    def complete(self) -> bool:
        return not self.unavailable and not self.errors

    def statement(self) -> str:
        """One-line human-readable coverage statement."""
        total = len(self.checked) + len(self.unavailable) + len(self.errors)
        if total == 0:
            return "nothing was checked"
        parts = [f"checked {len(self.checked)} of {total} capabilities"]
        if self.unavailable:
            detail = "; ".join(f"{k}: {v}" for k, v in sorted(self.unavailable.items()))
            parts.append(f"{len(self.unavailable)} unavailable ({detail})")
        if self.errors:
            detail = "; ".join(f"{k}: {v}" for k, v in sorted(self.errors.items()))
            parts.append(f"{len(self.errors)} errored ({detail})")
        if self.complete:
            parts.append("coverage complete")
        else:
            parts.append("COVERAGE INCOMPLETE — absent findings are not evidence of absence")
        return "; ".join(parts)

    def as_dict(self) -> dict:
        return {
            "checked": list(self.checked),
            "unavailable": dict(self.unavailable),
            "errors": dict(self.errors),
            "complete": self.complete,
            "statement": self.statement(),
        }


def envelope(tool: str, coverage: Coverage, **payload: Any) -> dict:
    """Standard tool response envelope."""
    return {
        "tool": tool,
        "timestamp": now_iso(),
        **payload,
        "coverage": coverage.as_dict(),
    }
