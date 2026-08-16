"""Wazuh REST client.

STATUS: NOT DEPLOYED. No Wazuh manager exists on any Temple device as of
2026-08-10. This module is kept wired so the integration path survives, but
every entry point gates on credentials BEFORE any network call, so an absent
Wazuh degrades to an honest ``unavailable`` instead of a DNS hang against
wazuh-vm.tailnet.ts.net.

Two v1.0.0 defects fixed here:
  * ``httpx.AsyncClient(verify=False)`` on every call — TLS verification now
    defaults ON, and disabling it is explicit, warned, and surfaced.
  * ``WAZUH_PASS`` defaulting to ``""`` and then being used as a credential,
    producing an auth error indistinguishable from a network failure.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from . import config
from .result import available, unavailable

logger = logging.getLogger(__name__)

_TIME_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_time_window(window: str) -> timedelta | None:
    """Parse '24h', '7d', '30m', '90s', '2w' into a timedelta. None if invalid.

    Pure and unit-tested. v1.0.0 accepted ``time_window`` and never used it —
    the parameter was decorative and every query silently returned all time.
    """
    if not isinstance(window, str):
        return None
    text = window.strip().lower()
    if len(text) < 2:
        return None
    quantity, unit = text[:-1], text[-1]
    if unit not in _TIME_UNITS or not quantity.isdigit():
        return None
    value = int(quantity)
    if value <= 0:
        return None
    return timedelta(**{_TIME_UNITS[unit]: value})


def build_alert_query(
    severity: str = "high",
    time_window: str = "24h",
    device: str = "all",
    limit: int = 25,
    now: datetime | None = None,
) -> dict:
    """Build the Wazuh /alerts query parameters.

    Extracted as a pure function precisely because the live path is
    untestable on this machine: no Wazuh exists, so "time_window is honored"
    could otherwise only ever be an assertion. Here it is a unit test.
    """
    severity_map = {"low": 3, "medium": 7, "high": 10, "critical": 12}
    minimum_level = severity_map.get(severity, 7)
    clauses = [f"rule.level>={minimum_level}"]

    delta = parse_time_window(time_window)
    window_applied = delta is not None
    if window_applied:
        reference = now or datetime.now(timezone.utc)
        since = (reference - delta).strftime("%Y-%m-%dT%H:%M:%SZ")
        clauses.append(f"timestamp>{since}")
    if device and device != "all":
        clauses.append(f"agent.name={device}")

    return {
        "params": {
            "limit": limit,
            "sort": "-timestamp",
            "q": ";".join(clauses),
        },
        "time_window_applied": window_applied,
        "time_window_reason": (
            None if window_applied
            else f"could not parse time_window={time_window!r}; NO time filter was applied"
        ),
        "severity_min_level": minimum_level,
    }


def capability() -> dict:
    """Is Wazuh usable at all? Checked before any network I/O."""
    if not config.wazuh_credentials_present():
        missing = []
        if not config.wazuh_user():
            missing.append("WAZUH_USER")
        if not config.wazuh_password():
            missing.append("WAZUH_PASS")
        return unavailable(
            "Wazuh is NOT DEPLOYED on this infrastructure and no credentials "
            f"are configured (missing: {', '.join(missing)}). No request was "
            "attempted.",
            integration_status="not_deployed",
            api_url=config.wazuh_api_url(),
        )
    return available(api_url=config.wazuh_api_url(), tls_verify=config.tls_verify())


class WazuhClient:
    """Authenticated Wazuh API client. Returns result blocks, never raises."""

    def __init__(self) -> None:
        self._token: str | None = None
        self._token_expires: float = 0.0

    def _client_kwargs(self) -> dict:
        verify = config.tls_verify()
        if not verify:
            logger.warning(
                "TLS VERIFICATION DISABLED for %s via GUARDIAN_INSECURE_TLS. "
                "This permits machine-in-the-middle interception of Wazuh "
                "credentials and alert data.",
                config.wazuh_api_url(),
            )
        return {"verify": verify, "timeout": config.DEFAULT_HTTP_TIMEOUT}

    async def _authenticate(self) -> dict:
        import httpx

        if self._token and time.time() < self._token_expires:
            return available(token=self._token, cached=True)
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
                response = await client.post(
                    f"{config.wazuh_api_url()}/security/user/authenticate",
                    auth=(config.wazuh_user(), config.wazuh_password()),
                )
                response.raise_for_status()
                self._token = response.json()["data"]["token"]
                self._token_expires = time.time() + 870
                return available(token=self._token, cached=False)
        except Exception as exc:
            return unavailable(f"Wazuh authentication failed: {type(exc).__name__}: {exc}")

    async def get(self, endpoint: str, params: dict | None = None) -> dict:
        import httpx

        gate = capability()
        if not gate.get("available"):
            return gate
        auth = await self._authenticate()
        if not auth.get("available"):
            return auth
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
                response = await client.get(
                    f"{config.wazuh_api_url()}{endpoint}",
                    headers={"Authorization": f"Bearer {auth['token']}"},
                    params=params or {},
                )
                response.raise_for_status()
                return available(data=response.json(), endpoint=endpoint)
        except Exception as exc:
            return unavailable(
                f"Wazuh request to {endpoint} failed: {type(exc).__name__}: {exc}"
            )


wazuh = WazuhClient()
