"""Action1 RMM connector - desktop, laptop and server endpoint management.

Action1 covers the Windows/macOS/Linux fleet: inventory, patch status,
vulnerabilities, endpoint groups and automations.

Authentication is OAuth2 **client credentials** against ``{base}/oauth2/token``:

.. code-block:: text

    POST https://app.eu.action1.com/api/3.0/oauth2/token
    Content-Type: application/x-www-form-urlencoded

    client_id=<API key>&client_secret=<secret>

The returned JWT lives exactly **3600 seconds** and is cached/refreshed here.
Credentials are created in the console under *Configuration → Users & API
Credentials*; the API role attached to them determines what this connector can
do, so grant the least privilege that satisfies the playbooks
(see ``docs/PERMISSIONS.md``).

Region note
-----------
``app.action1.com`` (North America), ``app.eu.action1.com`` (Europe) and
``app.au.action1.com`` (Australia) are separate data centres. The default here is
**europe**; set ``IAM_ACTION1_REGION`` or ``IAM_ACTION1_BASE_URL`` to override.

Read endpoints below follow Action1's published API surface. The write
endpoints (group membership, automation launch) are less publicly documented -
verify them against ``https://app.action1.com/apidocs/`` for your account before
switching ``backend=live``.
"""

from __future__ import annotations

import abc
import time
from typing import Any

from iam_agent.config import Action1Settings
from iam_agent.connectors.base import BaseConnector, HealthStatus, NotConfiguredError
from iam_agent.connectors.mock.store import MockStore, get_mock_store
from iam_agent.core.audit import AuditLog
from iam_agent.core.errors import NotFoundError
from iam_agent.core.models import (
    Device,
    DeviceOwnership,
    DevicePlatform,
    DeviceState,
)

OP = "action1"
OPS = {
    "list_organizations": f"{OP}.list_organizations",
    "list_endpoints": f"{OP}.list_endpoints",
    "get_endpoint": f"{OP}.get_endpoint",
    "get_endpoint_updates": f"{OP}.get_endpoint_updates",
    "list_endpoint_groups": f"{OP}.list_endpoint_groups",
    "get_group_contents": f"{OP}.get_group_contents",
    "add_endpoints_to_group": f"{OP}.add_endpoints_to_group",
    "remove_endpoints_from_group": f"{OP}.remove_endpoints_from_group",
    "move_endpoint_group": f"{OP}.move_endpoint_group",
    "list_updates": f"{OP}.list_updates",
    "list_packages": f"{OP}.list_packages",
    "list_automations": f"{OP}.list_automations",
    "run_automation": f"{OP}.run_automation",
    "reboot_endpoint": f"{OP}.reboot_endpoint",
    "shutdown_endpoint": f"{OP}.shutdown_endpoint",
    "quarantine_endpoint": f"{OP}.quarantine_endpoint",
    "list_reports": f"{OP}.list_reports",
    "get_report_data": f"{OP}.get_report_data",
    "list_audit_events": f"{OP}.list_audit_events",
    "find_endpoints_by_owner": f"{OP}.find_endpoints_by_owner",
}

# Action1 tokens are minted for exactly one hour.
_TOKEN_TTL = 3600
# Refresh a little early so a slow request never races expiry.
_TOKEN_SKEW = 120


def _platform_from_os(os_name: str) -> DevicePlatform:
    lowered = (os_name or "").lower()
    if "windows" in lowered:
        return DevicePlatform.WINDOWS
    if "macos" in lowered or "mac os" in lowered or "darwin" in lowered:
        return DevicePlatform.MACOS
    if "linux" in lowered or "ubuntu" in lowered or "debian" in lowered or "rhel" in lowered:
        return DevicePlatform.LINUX
    return DevicePlatform.UNKNOWN


def _map_endpoint(raw: dict[str, Any]) -> Device:
    """Normalise an Action1 endpoint resource.

    Action1 returns ``fields=*`` payloads with nested ``alerts`` /
    ``missing_updates`` blocks; we flatten what the workflows actually need and
    keep the original under ``raw``.
    """
    os_name = raw.get("os_name") or raw.get("os", {}).get("name", "") if isinstance(raw.get("os"), dict) else raw.get("os_name", "")
    if not os_name and isinstance(raw.get("os"), dict):
        os_name = raw["os"].get("name", "")

    online = raw.get("online")
    if online is None:
        online = raw.get("last_seen_online", {}).get("status") == "online" if isinstance(
            raw.get("last_seen_online"), dict
        ) else None

    missing = raw.get("missing_updates")
    if isinstance(missing, dict):
        missing_count = int(missing.get("total") or missing.get("count") or 0)
    elif isinstance(missing, list):
        missing_count = len(missing)
    else:
        missing_count = int(missing or 0)

    vulns = raw.get("vulnerabilities") or raw.get("critical_vulnerabilities") or {}
    if isinstance(vulns, dict):
        vuln_count = int(vulns.get("critical") or vulns.get("total") or 0)
    elif isinstance(vulns, list):
        vuln_count = len(vulns)
    else:
        vuln_count = int(vulns or 0)

    if raw.get("quarantined"):
        state = DeviceState.QUARANTINED if hasattr(DeviceState, "QUARANTINED") else DeviceState.INACTIVE
    elif online is True:
        state = DeviceState.ACTIVE
    elif online is False:
        state = DeviceState.INACTIVE
    else:
        state = DeviceState.ENROLLED

    last_seen = raw.get("last_seen") or raw.get("last_contact_time")
    return Device(
        platform_console="action1",
        external_id=raw.get("id", ""),
        device_name=raw.get("name", "") or raw.get("hostname", ""),
        asset_tag=raw.get("asset_tag", "") or "",
        serial_number=raw.get("serial_number", "") or "",
        os_name=os_name,
        os_version=str(raw.get("os_version", "") or ""),
        device_platform=_platform_from_os(os_name),
        manufacturer=raw.get("manufacturer", "") or "",
        model=raw.get("model", "") or "",
        ownership=DeviceOwnership.CORPORATE,  # Action1 is agent-based: corporate fleet
        state=state,
        online=bool(online) if online is not None else None,
        last_seen=_parse_iso(last_seen),
        assigned_user=raw.get("owner_name", "") or raw.get("user_name", ""),
        assigned_email=(raw.get("owner_email", "") or "").lower(),
        compliance=raw.get("compliance", "compliant" if missing_count < 5 else "non_compliant"),
        missing_updates=missing_count,
        critical_vulnerabilities=vuln_count,
        raw=raw,
    )


def _parse_iso(value: Any):
    if not value:
        return None
    from datetime import datetime

    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


class Action1Connector(BaseConnector, abc.ABC):
    """Interface for the Action1 RMM platform."""

    name = "action1"
    label = "Action1 RMM"

    def __init__(self, settings: Action1Settings, audit: AuditLog | None = None) -> None:
        super().__init__(
            backend=settings.backend,
            audit=audit,
            timeout=60.0,
            max_retries=3,
            rate_limit_per_minute=120,
        )
        self.settings = settings
        self._organization_id: str = settings.organization_id

    # ---- reads ----------------------------------------------------------- #
    @abc.abstractmethod
    async def list_organizations(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def list_endpoints(self, *, organization_id: str = "") -> list[Device]: ...
    @abc.abstractmethod
    async def get_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> Device | None: ...
    @abc.abstractmethod
    async def find_endpoints_by_owner(self, owner: str, *, organization_id: str = "") -> list[Device]: ...
    @abc.abstractmethod
    async def list_endpoint_groups(self, *, organization_id: str = "") -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def get_group_contents(self, group_id: str, *, organization_id: str = "") -> list[Device]: ...
    @abc.abstractmethod
    async def list_updates(self, *, organization_id: str = "", endpoint_id: str = "") -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def list_packages(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def list_automations(self, *, organization_id: str = "") -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def list_reports(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def get_report_data(self, report_id: str) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def list_audit_events(self, *, limit: int = 100) -> list[dict[str, Any]]: ...

    # ---- writes ---------------------------------------------------------- #
    @abc.abstractmethod
    async def add_endpoints_to_group(
        self, group_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_endpoints_from_group(
        self, group_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def run_automation(
        self, automation_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def reboot_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> dict[str, Any]: ...
    @abc.abstractmethod
    async def quarantine_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> dict[str, Any]: ...

    # ---- shared ---------------------------------------------------------- #
    async def resolve_organization_id(self) -> str:
        if self._organization_id:
            return self._organization_id
        orgs = await self.list_organizations()
        if not orgs:
            raise NotFoundError("no Action1 organizations visible to these credentials", platform=self.name)
        self._organization_id = orgs[0].get("id", "")
        return self._organization_id

    async def resolve_group_id(self, name_or_id: str) -> str:
        if not name_or_id:
            return ""
        for group in await self.list_endpoint_groups():
            if group.get("id") == name_or_id or group.get("name", "").lower() == name_or_id.lower():
                return group.get("id", "")
        raise NotFoundError(f"Action1 endpoint group not found: {name_or_id}", platform=self.name)

    async def resolve_automation_id(self, name_or_id: str) -> str:
        if not name_or_id:
            return ""
        for automation in await self.list_automations():
            if automation.get("id") == name_or_id or automation.get("name", "").lower() == name_or_id.lower():
                return automation.get("id", "")
        raise NotFoundError(f"Action1 automation not found: {name_or_id}", platform=self.name)


# --------------------------------------------------------------------------- #
# Live implementation
# --------------------------------------------------------------------------- #


class LiveAction1Connector(Action1Connector):
    def __init__(self, settings: Action1Settings, audit: AuditLog | None = None) -> None:
        super().__init__(settings, audit)

    @property
    def base(self) -> str:
        return self.settings.api_base

    # ---- auth ------------------------------------------------------------ #

    async def authenticate(self) -> None:
        if not (self.settings.client_id and self.settings.client_secret):
            raise NotConfiguredError(
                "Action1 backend=live requires IAM_ACTION1_CLIENT_ID and IAM_ACTION1_CLIENT_SECRET.",
                platform=self.name,
            )
        url = f"{self.base}/{self.settings.token_url_path}"
        response = await self.client.post(
            url,
            data={
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.audit and self.audit.api_call(self.name, "POST", url, response.status_code, 0.0)

        if response.status_code != 200:
            from iam_agent.core.errors import AuthenticationError

            raise AuthenticationError(
                f"Action1 token request failed ({response.status_code}): {response.text[:300]}",
                platform=self.name,
            )
        payload = response.json()
        self._token = payload.get("access_token", "")
        if not self._token:
            from iam_agent.core.errors import AuthenticationError

            raise AuthenticationError("Action1 response contained no access_token", platform=self.name)
        self._token_expires_at = time.time() + min(
            int(payload.get("expires_in", _TOKEN_TTL)), self.settings.token_ttl_seconds
        ) - _TOKEN_SKEW

    async def health(self) -> HealthStatus:
        started = time.monotonic()
        try:
            orgs = await self.list_organizations()
            names = ", ".join(o.get("name", "?") for o in orgs[:3])
            return HealthStatus(
                self.name, True, "live",
                f"{len(orgs)} organization(s): {names} @ {self.base}",
                (time.monotonic() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001
            return HealthStatus(
                self.name, False, "live", f"{type(exc).__name__}: {exc}", (time.monotonic() - started) * 1000
            )

    # ---- reads ----------------------------------------------------------- #

    async def list_organizations(self) -> list[dict[str, Any]]:
        payload = await self.request("GET", f"{self.base}/organizations")
        return _unwrap(payload)

    async def list_endpoints(self, *, organization_id: str = "") -> list[Device]:
        org = organization_id or await self.resolve_organization_id()
        payload = await self.request(
            "GET", f"{self.base}/endpoints/managed/{org}", params={"fields": "*", "limit": "200"}
        )
        return [_map_endpoint(e) for e in _unwrap(payload)]

    async def get_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> Device | None:
        org = organization_id or await self.resolve_organization_id()
        try:
            raw = await self.request(
                "GET",
                f"{self.base}/endpoints/managed/{org}/{endpoint_id}",
                params={"fields": "*"},
            )
        except NotFoundError:
            return None
        return _map_endpoint(raw)

    async def find_endpoints_by_owner(self, owner: str, *, organization_id: str = "") -> list[Device]:
        endpoints = await self.list_endpoints(organization_id=organization_id)
        needle = owner.lower().strip()
        matches = []
        for device in endpoints:
            haystack = " ".join(
                [device.assigned_email, device.assigned_user, device.device_name]
            ).lower()
            if needle and needle in haystack:
                matches.append(device)
        return matches

    async def list_endpoint_groups(self, *, organization_id: str = "") -> list[dict[str, Any]]:
        org = organization_id or await self.resolve_organization_id()
        return _unwrap(await self.request("GET", f"{self.base}/endpoints/groups/{org}"))

    async def get_group_contents(self, group_id: str, *, organization_id: str = "") -> list[Device]:
        org = organization_id or await self.resolve_organization_id()
        gid = await self.resolve_group_id(group_id)
        payload = await self.request("GET", f"{self.base}/endpoints/groups/{org}/{gid}/contents")
        return [_map_endpoint(e) for e in _unwrap(payload)]

    async def list_updates(self, *, organization_id: str = "", endpoint_id: str = "") -> list[dict[str, Any]]:
        org = organization_id or await self.resolve_organization_id()
        payload = await self.request("GET", f"{self.base}/updates/{org}", params={"fields": "*"})
        updates = _unwrap(payload)
        if endpoint_id:
            updates = [u for u in updates if u.get("endpoint_id") == endpoint_id]
        return updates

    async def list_packages(self) -> list[dict[str, Any]]:
        return _unwrap(await self.request("GET", f"{self.base}/packages/all"))

    async def list_automations(self, *, organization_id: str = "") -> list[dict[str, Any]]:
        org = organization_id or await self.resolve_organization_id()
        return _unwrap(await self.request("GET", f"{self.base}/automations/{org}"))

    async def list_reports(self) -> list[dict[str, Any]]:
        return _unwrap(await self.request("GET", f"{self.base}/reports"))

    async def get_report_data(self, report_id: str) -> list[dict[str, Any]]:
        return _unwrap(await self.request("GET", f"{self.base}/reports/{report_id}/data"))

    async def list_audit_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return _unwrap(
            await self.request("GET", f"{self.base}/audit/enterprise", params={"limit": str(limit)})
        )

    # ---- writes ---------------------------------------------------------- #

    async def add_endpoints_to_group(
        self, group_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]:
        org = organization_id or await self.resolve_organization_id()
        gid = await self.resolve_group_id(group_id)
        result = await self.request(
            "POST",
            f"{self.base}/endpoints/groups/{org}/{gid}/contents",
            json_body={"endpoint_ids": endpoint_ids},
            expected=(200, 201, 202, 204),
        )
        return {"group_id": gid, "added": endpoint_ids, "response": result or {}}

    async def remove_endpoints_from_group(
        self, group_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]:
        org = organization_id or await self.resolve_organization_id()
        gid = await self.resolve_group_id(group_id)
        result = await self.request(
            "DELETE",
            f"{self.base}/endpoints/groups/{org}/{gid}/contents",
            json_body={"endpoint_ids": endpoint_ids},
            expected=(200, 202, 204),
        )
        return {"group_id": gid, "removed": endpoint_ids, "response": result or {}}

    async def run_automation(
        self, automation_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]:
        org = organization_id or await self.resolve_organization_id()
        aid = await self.resolve_automation_id(automation_id)
        result = await self.request(
            "POST",
            f"{self.base}/automations/{org}/{aid}/launch",
            json_body={"endpoint_ids": endpoint_ids},
            expected=(200, 201, 202),
        )
        return {
            "automation_id": aid,
            "endpoints": endpoint_ids,
            "run_id": (result or {}).get("id", ""),
            "response": result or {},
        }

    async def reboot_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> dict[str, Any]:
        org = organization_id or await self.resolve_organization_id()
        result = await self.request(
            "POST",
            f"{self.base}/endpoints/managed/{org}/{endpoint_id}/actions/reboot",
            expected=(200, 202),
        )
        return {"endpoint_id": endpoint_id, "reboot_requested": True, "response": result or {}}

    async def quarantine_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> dict[str, Any]:
        org = organization_id or await self.resolve_organization_id()
        result = await self.request(
            "POST",
            f"{self.base}/endpoints/managed/{org}/{endpoint_id}/actions/quarantine",
            expected=(200, 202),
        )
        return {"endpoint_id": endpoint_id, "quarantined": True, "response": result or {}}


def _unwrap(payload: Any) -> list[dict[str, Any]]:
    """Action1 sometimes returns a bare list, sometimes ``{"items": [...]}``."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("items", "value", "endpoints", "organizations", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


# --------------------------------------------------------------------------- #
# Mock implementation
# --------------------------------------------------------------------------- #


class MockAction1Connector(Action1Connector):
    def __init__(
        self, settings: Action1Settings, audit: AuditLog | None = None, store: MockStore | None = None
    ) -> None:
        super().__init__(settings, audit)
        self.store = store or get_mock_store()

    async def authenticate(self) -> None:
        self._token = "mock-action1-jwt"
        self._token_expires_at = time.time() + _TOKEN_TTL

    async def health(self) -> HealthStatus:
        return HealthStatus(
            self.name, True, "mock",
            f"simulated org '{self.store.organizations[0]['name']}' with "
            f"{len(self.store.action1_endpoints)} endpoints",
        )

    async def list_organizations(self) -> list[dict[str, Any]]:
        return [
            {"id": o["id"], "name": o["name"], "endpoints_count": len(self.store.action1_endpoints)}
            for o in self.store.organizations
        ]

    async def list_endpoints(self, *, organization_id: str = "") -> list[Device]:
        return [
            Device(
                platform_console="action1",
                external_id=e["id"],
                device_name=e["name"],
                asset_tag=e.get("asset_tag", ""),
                serial_number=e.get("serial_number", ""),
                os_name=e.get("os_name", ""),
                os_version=e.get("os_version", ""),
                device_platform=DevicePlatform(e.get("platform", "unknown")),
                manufacturer="Dell" if "windows" in e.get("platform", "") else "Apple",
                model="OptiPlex 7010",
                ownership=DeviceOwnership.CORPORATE,
                state=DeviceState.ACTIVE if e.get("online") else DeviceState.INACTIVE,
                online=e.get("online"),
                last_seen=_parse_iso(e.get("last_seen")),
                assigned_user=e.get("owner_name", ""),
                assigned_email=e.get("owner_email", ""),
                compliance=e.get("compliance", "compliant"),
                missing_updates=e.get("missing_updates", 0),
                critical_vulnerabilities=e.get("critical_vulnerabilities", 0),
                device_group_id=(e.get("groups") or [""])[0],
                raw=e,
            )
            for e in self.store.action1_endpoints.values()
        ]

    async def get_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> Device | None:
        devices = await self.list_endpoints()
        return next(
            (d for d in devices if d.external_id == endpoint_id or d.device_name == endpoint_id), None
        )

    async def find_endpoints_by_owner(self, owner: str, *, organization_id: str = "") -> list[Device]:
        devices = await self.list_endpoints()
        needle = owner.lower().strip()
        return [
            d
            for d in devices
            if needle and needle in " ".join([d.assigned_email, d.assigned_user, d.device_name]).lower()
        ]

    async def list_endpoint_groups(self, *, organization_id: str = "") -> list[dict[str, Any]]:
        return [
            {
                "id": gid,
                "name": g["name"],
                "organization_id": g["organization_id"],
                "endpoint_count": len(g["endpoints"]),
            }
            for gid, g in self.store.action1_groups.items()
        ]

    async def get_group_contents(self, group_id: str, *, organization_id: str = "") -> list[Device]:
        gid = await self.resolve_group_id(group_id)
        group = self.store.action1_groups.get(gid)
        if not group:
            raise NotFoundError(f"mock Action1: no group '{group_id}'", platform=self.name)
        devices = await self.list_endpoints()
        return [d for d in devices if d.external_id in group["endpoints"]]

    async def list_updates(self, *, organization_id: str = "", endpoint_id: str = "") -> list[dict[str, Any]]:
        rows = list(self.store.action1_updates.values())
        if endpoint_id:
            rows = [r for r in rows if r["endpoint_id"] == endpoint_id]
        return rows

    async def list_packages(self) -> list[dict[str, Any]]:
        return [
            {"id": "pkg-chrome", "name": "Google Chrome", "version": "latest"},
            {"id": "pkg-zoom", "name": "Zoom Workplace", "version": "latest"},
            {"id": "pkg-defender", "name": "Microsoft Defender", "version": "latest"},
        ]

    async def list_automations(self, *, organization_id: str = "") -> list[dict[str, Any]]:
        return [
            {"id": aid, "name": a["name"], "enabled": a["enabled"], "runs": len(a["runs"])}
            for aid, a in self.store.action1_automations.items()
        ]

    async def list_reports(self) -> list[dict[str, Any]]:
        return [
            {"id": "rpt-patch", "name": "Patching Status"},
            {"id": "rpt-vuln", "name": "Vulnerabilities by Severity"},
            {"id": "rpt-inventory", "name": "Hardware Inventory"},
        ]

    async def get_report_data(self, report_id: str) -> list[dict[str, Any]]:
        endpoints = await self.list_endpoints()
        return [
            {
                "endpoint": d.device_name,
                "missing_updates": d.missing_updates,
                "critical_vulnerabilities": d.critical_vulnerabilities,
                "compliance": d.compliance,
            }
            for d in endpoints
        ]

    async def list_audit_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return [e for e in self.store.events if e["kind"].startswith("action1")][-limit:]

    # ---- writes ---------------------------------------------------------- #

    async def add_endpoints_to_group(
        self, group_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]:
        gid = await self.resolve_group_id(group_id)
        group = self.store.action1_groups[gid]
        resolved: list[str] = []
        for ref in endpoint_ids:
            target = next(
                (
                    eid
                    for eid, e in self.store.action1_endpoints.items()
                    if eid == ref or e["name"] == ref
                ),
                None,
            )
            if target and target not in group["endpoints"]:
                group["endpoints"].append(target)
                for e in self.store.action1_endpoints[target].setdefault("groups", []):
                    pass
                self.store.action1_endpoints[target].setdefault("groups", [])
                if gid not in self.store.action1_endpoints[target]["groups"]:
                    self.store.action1_endpoints[target]["groups"].append(gid)
                resolved.append(target)
        self.store.log_event("action1.add_endpoints_to_group", group=gid, endpoints=resolved)
        return {"group_id": gid, "added": resolved, "group_name": group["name"]}

    async def remove_endpoints_from_group(
        self, group_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]:
        gid = await self.resolve_group_id(group_id)
        group = self.store.action1_groups[gid]
        before = len(group["endpoints"])
        group["endpoints"] = [e for e in group["endpoints"] if e not in endpoint_ids]
        for eid in endpoint_ids:
            endpoint = self.store.action1_endpoints.get(eid)
            if endpoint:
                endpoint["groups"] = [g for g in endpoint.get("groups", []) if g != gid]
        self.store.log_event("action1.remove_endpoints_from_group", group=gid, endpoints=endpoint_ids)
        return {"group_id": gid, "removed": before - len(group["endpoints"])}

    async def run_automation(
        self, automation_id: str, endpoint_ids: list[str], *, organization_id: str = ""
    ) -> dict[str, Any]:
        aid = await self.resolve_automation_id(automation_id)
        automation = self.store.action1_automations[aid]
        run_id = f"run-{len(automation['runs']) + 1}"
        automation["runs"].append(
            {
                "id": run_id,
                "endpoints": endpoint_ids,
                "status": "completed",
                "at": _now_iso(),
            }
        )
        self.store.log_event("action1.run_automation", automation=aid, endpoints=endpoint_ids)
        return {
            "automation_id": aid,
            "automation_name": automation["name"],
            "run_id": run_id,
            "endpoints": endpoint_ids,
            "status": "completed",
            "simulated": True,
        }

    async def reboot_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> dict[str, Any]:
        device = await self.get_endpoint(endpoint_id)
        if not device:
            raise NotFoundError(f"mock Action1: no endpoint '{endpoint_id}'", platform=self.name)
        self.store.action1_endpoints[device.external_id]["last_seen"] = _now_iso()
        self.store.log_event("action1.reboot_endpoint", endpoint=device.external_id)
        return {"endpoint_id": device.external_id, "reboot_requested": True, "simulated": True}

    async def quarantine_endpoint(self, endpoint_id: str, *, organization_id: str = "") -> dict[str, Any]:
        device = await self.get_endpoint(endpoint_id)
        if not device:
            raise NotFoundError(f"mock Action1: no endpoint '{endpoint_id}'", platform=self.name)
        raw = self.store.action1_endpoints[device.external_id]
        raw["quarantined"] = True
        raw["compliance"] = "quarantined"
        self.store.log_event("action1.quarantine_endpoint", endpoint=device.external_id)
        return {"endpoint_id": device.external_id, "quarantined": True, "simulated": True}


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def build_action1_connector(
    settings: Action1Settings, audit: AuditLog | None = None, store: MockStore | None = None
) -> Action1Connector:
    if settings.enabled and settings.backend == "live":
        return LiveAction1Connector(settings, audit)
    return MockAction1Connector(settings, audit, store)
