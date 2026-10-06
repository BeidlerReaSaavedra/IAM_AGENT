"""Connector registry: builds and owns all five platform connectors.

``ConnectorHub`` is the single object the workflows, the MCP server, the REST
API and the CLI depend on. It resolves ``live`` vs ``mock`` per platform from
settings, keeps one shared :class:`MockStore` so simulated platforms stay
coherent, and exposes uniform health probing.
"""

from __future__ import annotations

import asyncio
from typing import Any

from iam_agent.config import Settings, get_settings
from iam_agent.connectors.action1 import Action1Connector, build_action1_connector
from iam_agent.connectors.ad_local import ADConnector, build_ad_connector
from iam_agent.connectors.base import BaseConnector, HealthStatus
from iam_agent.connectors.entra import EntraConnector, build_entra_connector
from iam_agent.connectors.m365 import M365Connector, build_m365_connector
from iam_agent.connectors.mock.store import MockStore, get_mock_store
from iam_agent.connectors.scalefusion import ScalefusionConnector, build_scalefusion_connector
from iam_agent.core.audit import AuditLog

PLATFORMS = ("entra", "m365", "active_directory", "action1", "scalefusion")


class ConnectorHub:
    """Owns the connector instances for one settings snapshot."""

    def __init__(self, settings: Settings, audit: AuditLog | None = None) -> None:
        self.settings = settings
        self.audit = audit
        self.store: MockStore | None = get_mock_store() if self._any_mock() else None

        self.entra: EntraConnector = build_entra_connector(settings.entra, audit, self.store)
        self.m365: M365Connector = build_m365_connector(settings.m365, audit, self.store)
        self.active_directory: ADConnector = build_ad_connector(
            settings.active_directory, audit, self.store
        )
        self.action1: Action1Connector = build_action1_connector(settings.action1, audit, self.store)
        self.scalefusion: ScalefusionConnector = build_scalefusion_connector(
            settings.scalefusion, audit, self.store
        )

    def _any_mock(self) -> bool:
        backends = self.settings.platform_backends()
        return any(b == "mock" for b in backends.values())

    # ---- access ---------------------------------------------------------- #

    def all(self) -> dict[str, BaseConnector]:
        return {
            "entra": self.entra,
            "m365": self.m365,
            "active_directory": self.active_directory,
            "action1": self.action1,
            "scalefusion": self.scalefusion,
        }

    def get(self, platform: str) -> BaseConnector:
        connectors = self.all()
        if platform not in connectors:
            raise KeyError(f"unknown platform '{platform}'. Known: {sorted(connectors)}")
        return connectors[platform]

    def enabled_platforms(self) -> list[str]:
        """Every platform this hub can talk to.

        All five connectors are always constructed - a platform without
        credentials falls back to the simulator - so this is simply ``PLATFORMS``.
        Reachability is not the interesting question; :meth:`live_platforms`
        answers the one operators actually care about.
        """
        return list(PLATFORMS)

    def live_platforms(self) -> list[str]:
        """Platforms backed by real credentials rather than the simulator."""
        backends = self.settings.platform_backends()
        return [p for p in PLATFORMS if backends[p] == "live"]

    def simulated_platforms(self) -> list[str]:
        """Platforms currently answered by the mock backend.

        Surfaced loudly on purpose: pointing a production lifecycle agent at a
        simulator should never be something an operator has to guess.
        """
        backends = self.settings.platform_backends()
        return [p for p in PLATFORMS if backends[p] == "mock"]

    # ---- health ---------------------------------------------------------- #

    async def health(self) -> dict[str, HealthStatus]:
        """Probe every connector concurrently."""
        results = await asyncio.gather(
            *(c.health() for c in self.all().values()), return_exceptions=True
        )
        out: dict[str, HealthStatus] = {}
        for name, result in zip(self.all().keys(), results):
            if isinstance(result, BaseException):
                out[name] = HealthStatus(name, False, "unknown", f"{type(result).__name__}: {result}")
            else:
                out[name] = result
        return out

    async def health_report(self) -> dict[str, Any]:
        statuses = await self.health()
        return {
            "healthy": all(s.healthy for s in statuses.values()),
            "mode": self.settings.effective_mode(),
            "connectors": {name: s.to_dict() for name, s in statuses.items()},
        }

    # ---- lifecycle ------------------------------------------------------- #

    async def aclose(self) -> None:
        await asyncio.gather(*(c.aclose() for c in self.all().values()), return_exceptions=True)

    async def __aenter__(self) -> "ConnectorHub":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()


_hub: ConnectorHub | None = None


def get_hub(settings: Settings | None = None, audit: AuditLog | None = None) -> ConnectorHub:
    """Process-wide hub. Pass explicit settings to force a rebuild."""
    global _hub
    if settings is not None or _hub is None:
        _hub = ConnectorHub(settings or get_settings(), audit)
    return _hub


def reset_hub() -> None:
    """Drop the cached hub (used by tests after changing settings)."""
    global _hub
    _hub = None


__all__ = [
    "ConnectorHub",
    "get_hub",
    "reset_hub",
    "PLATFORMS",
    "Action1Connector",
    "ADConnector",
    "EntraConnector",
    "M365Connector",
    "ScalefusionConnector",
]
