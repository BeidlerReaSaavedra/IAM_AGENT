"""Scalefusion UEM/MDM connector - mobile, rugged, kiosk and desktop devices.

Authentication is a **Developer API key** generated in the Scalefusion dashboard
under *Integrations → Developer API*. It is sent as a header on every request.

Hard limits to respect (documented by Scalefusion)
--------------------------------------------------
* **30 requests per minute** and **43,200 per day**.
* Calls **cannot** be made from a browser (CORS is blocked); they must originate
  from a backend - which is exactly what this connector is.

The rate limiter in :class:`BaseConnector` is configured to 30/min here so the
agent self-throttles instead of getting blocked.

Endpoint shapes
---------------
The read endpoints below (``devices.json``, ``device_profiles.json``,
``device_groups.json``, ``battery.json``, ``send_alarm.json``,
``apply_to_device.json``, ``remove_from_device.json``) are documented in the
Scalefusion Developer API. Command endpoints (lock/wipe/retire/user assignment)
vary by plan and OS - validate them in your own API Explorer
(*Integrations → Developer API → READ API DOCS*) before enabling
``backend=live``. Anything unsupported degrades to a reported "manual step
required" instead of failing silently.
"""

from __future__ import annotations

import abc
import time
from typing import Any

from iam_agent.config import ScalefusionSettings
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

OP = "scalefusion"
OPS = {
    "list_devices": f"{OP}.list_devices",
    "get_device": f"{OP}.get_device",
    "get_device_battery": f"{OP}.get_device_battery",
    "get_device_apps": f"{OP}.get_device_apps",
    "get_device_location": f"{OP}.get_device_location",
    "list_device_profiles": f"{OP}.list_device_profiles",
    "list_device_groups": f"{OP}.list_device_groups",
    "find_devices_by_user": f"{OP}.find_devices_by_user",
    "apply_device_profile": f"{OP}.apply_device_profile",
    "remove_device_profile": f"{OP}.remove_device_profile",
    "add_device_to_group": f"{OP}.add_device_to_group",
    "remove_device_from_group": f"{OP}.remove_device_from_group",
    "assign_device_user": f"{OP}.assign_device_user",
    "unassign_device_user": f"{OP}.unassign_device_user",
    "lock_device": f"{OP}.lock_device",
    "unlock_device": f"{OP}.unlock_device",
    "send_alarm": f"{OP}.send_alarm",
    "wipe_device": f"{OP}.wipe_device",
    "retire_device": f"{OP}.retire_device",
}

_STATUS_TO_STATE = {
    "active": DeviceState.ACTIVE,
    "enrolled": DeviceState.ENROLLED,
    "inactive": DeviceState.INACTIVE,
    "locked": DeviceState.LOCKED,
    "lost": DeviceState.LOST,
    "wiped": DeviceState.WIPED,
    "retired": DeviceState.RETIRED,
    "unenrolled": DeviceState.UNMANAGED,
    "pending": DeviceState.ENROLLED,
}


def _map_os(value: Any) -> DevicePlatform:
    text = str(value or "").lower()
    if "android" in text:
        return DevicePlatform.ANDROID
    if "ipad" in text:
        return DevicePlatform.IPADOS
    if "ios" in text or "iphone" in text:
        return DevicePlatform.IOS
    if "windows" in text:
        return DevicePlatform.WINDOWS
    if "mac" in text:
        return DevicePlatform.MACOS
    if "linux" in text:
        return DevicePlatform.LINUX
    if "chrome" in text:
        return DevicePlatform.CHROMEOS
    return DevicePlatform.UNKNOWN


def _map_device(raw: dict[str, Any]) -> Device:
    status = str(raw.get("status") or raw.get("device_status") or "").lower()
    state = _STATUS_TO_STATE.get(status, DeviceState.ENROLLED)
    if raw.get("wiped"):
        state = DeviceState.WIPED
    elif raw.get("retired"):
        state = DeviceState.RETIRED
    elif raw.get("locked"):
        state = DeviceState.LOCKED

    os_value = raw.get("os") or raw.get("platform") or raw.get("device_os") or ""
    ownership = str(raw.get("ownership") or raw.get("device_ownership") or "").lower()

    return Device(
        platform_console="scalefusion",
        external_id=str(raw.get("id", "")),
        device_name=raw.get("device_name") or raw.get("name") or "",
        asset_tag=raw.get("asset_tag") or "",
        serial_number=raw.get("serial_number") or raw.get("serial") or "",
        imei=raw.get("imei") or "",
        os_name=str(os_value),
        os_version=str(raw.get("os_version") or ""),
        device_platform=_map_os(os_value),
        manufacturer=raw.get("manufacturer") or "",
        model=raw.get("model") or raw.get("device_model") or "",
        ownership=(
            DeviceOwnership.BYOD
            if ownership == "byod"
            else DeviceOwnership.CORPORATE
            if ownership == "corporate"
            else DeviceOwnership.UNKNOWN
        ),
        state=state,
        online=(raw.get("status") == "active") if raw.get("status") else None,
        last_seen=_parse_iso(raw.get("last_seen") or raw.get("last_contact")),
        assigned_user=raw.get("user_name") or raw.get("assigned_user") or "",
        assigned_email=(raw.get("user_email") or raw.get("assigned_email") or "").lower(),
        compliance=raw.get("compliance") or ("compliant" if state == DeviceState.ACTIVE else "unknown"),
        battery_level=raw.get("battery_level"),
        device_group_id=str(raw.get("device_group_id") or ""),
        device_profile_id=str(raw.get("device_profile_id") or ""),
        enrolled_at=_parse_iso(raw.get("enrolled_at")),
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


class ScalefusionConnector(BaseConnector, abc.ABC):
    """Interface for the Scalefusion UEM platform."""

    name = "scalefusion"
    label = "Scalefusion MDM"

    def __init__(self, settings: ScalefusionSettings, audit: AuditLog | None = None) -> None:
        super().__init__(
            backend=settings.backend,
            audit=audit,
            timeout=settings.request_timeout,
            max_retries=4,
            rate_limit_per_minute=settings.rate_limit_per_minute,
        )
        self.settings = settings

    def _auth_header(self) -> dict[str, str]:
        return {self.settings.auth_header_name: f"{self.settings.auth_header_prefix}{self.settings.api_key}"}

    # ---- reads ----------------------------------------------------------- #
    @abc.abstractmethod
    async def list_devices(self, *, page: int | None = None) -> list[Device]: ...
    @abc.abstractmethod
    async def get_device(self, device_id: str) -> Device | None: ...
    @abc.abstractmethod
    async def get_device_battery(self, device_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def get_device_apps(self, device_id: str, *, installed: bool = True) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def get_device_location(self, device_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def list_device_profiles(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def list_device_groups(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def find_devices_by_user(self, user: str) -> list[Device]: ...

    # ---- writes ---------------------------------------------------------- #
    @abc.abstractmethod
    async def apply_device_profile(self, profile_id: str, device_ids: list[str]) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_device_profile(self, profile_id: str, device_ids: list[str]) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def add_device_to_group(self, group_id: str, device_ids: list[str]) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_device_from_group(self, group_id: str, device_ids: list[str]) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def assign_device_user(self, device_id: str, user_email: str, user_name: str = "") -> dict[str, Any]: ...
    @abc.abstractmethod
    async def unassign_device_user(self, device_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def lock_device(self, device_id: str, *, message: str = "") -> dict[str, Any]: ...
    @abc.abstractmethod
    async def unlock_device(self, device_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def send_alarm(self, device_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def wipe_device(self, device_id: str, *, retention: bool = False) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def retire_device(self, device_id: str) -> dict[str, Any]: ...

    # ---- shared ---------------------------------------------------------- #
    async def resolve_profile_id(self, name_or_id: str) -> str:
        if not name_or_id:
            return ""
        for profile in await self.list_device_profiles():
            if str(profile.get("id")) == name_or_id or profile.get("name", "").lower() == name_or_id.lower():
                return str(profile.get("id", ""))
        raise NotFoundError(f"Scalefusion device profile not found: {name_or_id}", platform=self.name)

    async def resolve_group_id(self, name_or_id: str) -> str:
        if not name_or_id:
            return ""
        for group in await self.list_device_groups():
            if str(group.get("id")) == name_or_id or group.get("name", "").lower() == name_or_id.lower():
                return str(group.get("id", ""))
        raise NotFoundError(f"Scalefusion device group not found: {name_or_id}", platform=self.name)


# --------------------------------------------------------------------------- #
# Live implementation
# --------------------------------------------------------------------------- #


class LiveScalefusionConnector(ScalefusionConnector):
    def __init__(self, settings: ScalefusionSettings, audit: AuditLog | None = None) -> None:
        super().__init__(settings, audit)

    @property
    def base(self) -> str:
        return self.settings.base_url.rstrip("/")

    def _v(self, version: str, path: str) -> str:
        return f"{self.base}/api/{version}/{path.lstrip('/')}"

    async def authenticate(self) -> None:
        if not self.settings.api_key:
            raise NotConfiguredError(
                "Scalefusion backend=live requires IAM_SCALEFUSION_API_KEY.", platform=self.name
            )
        # API keys do not expire; mark the token valid for the process lifetime.
        self._token = self.settings.api_key
        self._token_expires_at = time.time() + 86_400

    def _auth_headers(self) -> dict[str, str]:
        """Scalefusion uses a static key header rather than a bearer JWT."""
        return {
            **self._auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def health(self) -> HealthStatus:
        started = time.monotonic()
        try:
            profiles = await self.list_device_profiles()
            return HealthStatus(
                self.name, True, "live",
                f"{len(profiles)} device profile(s) visible @ {self.base}",
                (time.monotonic() - started) * 1000,
            )
        except Exception as exc:
            return HealthStatus(
                self.name, False, "live", f"{type(exc).__name__}: {exc}", (time.monotonic() - started) * 1000
            )

    # ---- reads ----------------------------------------------------------- #

    async def list_devices(self, *, page: int | None = None) -> list[Device]:
        version = self.settings.devices_api_version
        params = {"page": str(page)} if page else None
        payload = await self.request("GET", self._v(version, "devices.json"), params=params)
        return [_map_device(d) for d in _unwrap(payload)]

    async def get_device(self, device_id: str) -> Device | None:
        version = self.settings.devices_api_version
        try:
            raw = await self.request("GET", self._v(version, f"devices/{device_id}.json"))
        except NotFoundError:
            return None
        return _map_device(raw)

    async def get_device_battery(self, device_id: str) -> dict[str, Any]:
        payload = await self.request("GET", self._v("v1", f"devices/{device_id}/battery.json"))
        return payload if isinstance(payload, dict) else {"raw": payload}

    async def get_device_apps(self, device_id: str, *, installed: bool = True) -> list[dict[str, Any]]:
        kind = "registered_apps" if installed else "enabled_apps"
        payload = await self.request(
            "GET", self._v("v1", f"devices/{device_id}/device_apps/{kind}.json")
        )
        return _unwrap(payload)

    async def get_device_location(self, device_id: str) -> dict[str, Any]:
        payload = await self.request("GET", self._v("v1", f"devices/{device_id}/locations.json"))
        rows = _unwrap(payload)
        return {"device_id": device_id, "locations": rows[:10]}

    async def list_device_profiles(self) -> list[dict[str, Any]]:
        return _unwrap(await self.request("GET", self._v("v1", "device_profiles.json")))

    async def list_device_groups(self) -> list[dict[str, Any]]:
        return _unwrap(await self.request("GET", self._v("v1", "device_groups.json")))

    async def find_devices_by_user(self, user: str) -> list[Device]:
        devices = await self.list_devices()
        needle = user.lower().strip()
        return [
            d
            for d in devices
            if needle and needle in " ".join([d.assigned_email, d.assigned_user, d.device_name]).lower()
        ]

    # ---- writes ---------------------------------------------------------- #

    async def apply_device_profile(self, profile_id: str, device_ids: list[str]) -> dict[str, Any]:
        pid = await self.resolve_profile_id(profile_id)
        results = []
        for device_id in device_ids:
            outcome = await self.request(
                "POST",
                self._v("v1", f"device_profiles/{pid}/apply_to_device.json"),
                json_body={"device_id": device_id},
                expected=(200, 201, 202),
            )
            results.append({"device_id": device_id, "response": outcome or {}})
        return {"profile_id": pid, "applied_to": device_ids, "results": results}

    async def remove_device_profile(self, profile_id: str, device_ids: list[str]) -> dict[str, Any]:
        pid = await self.resolve_profile_id(profile_id)
        results = []
        for device_id in device_ids:
            outcome = await self.request(
                "POST",
                self._v("v1", f"device_profiles/{pid}/remove_from_device.json"),
                json_body={"device_id": device_id},
                expected=(200, 202),
            )
            results.append({"device_id": device_id, "response": outcome or {}})
        return {"profile_id": pid, "removed_from": device_ids, "results": results}

    async def add_device_to_group(self, group_id: str, device_ids: list[str]) -> dict[str, Any]:
        gid = await self.resolve_group_id(group_id)
        outcome = await self.request(
            "POST",
            self._v("v1", f"device_groups/{gid}/add_devices.json"),
            json_body={"device_ids": device_ids},
            expected=(200, 201, 202),
        )
        return {"group_id": gid, "added": device_ids, "response": outcome or {}}

    async def remove_device_from_group(self, group_id: str, device_ids: list[str]) -> dict[str, Any]:
        gid = await self.resolve_group_id(group_id)
        outcome = await self.request(
            "POST",
            self._v("v1", f"device_groups/{gid}/remove_devices.json"),
            json_body={"device_ids": device_ids},
            expected=(200, 202),
        )
        return {"group_id": gid, "removed": device_ids, "response": outcome or {}}

    async def assign_device_user(self, device_id: str, user_email: str, user_name: str = "") -> dict[str, Any]:
        outcome = await self.request(
            "POST",
            self._v("v1", f"devices/{device_id}/assign_user.json"),
            json_body={"user_email": user_email, "user_name": user_name},
            expected=(200, 201, 202),
        )
        return {"device_id": device_id, "user_email": user_email, "response": outcome or {}}

    async def unassign_device_user(self, device_id: str) -> dict[str, Any]:
        outcome = await self.request(
            "POST",
            self._v("v1", f"devices/{device_id}/unassign_user.json"),
            expected=(200, 202),
        )
        return {"device_id": device_id, "response": outcome or {}}

    async def _command(self, device_id: str, command: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            outcome = await self.request(
                "POST",
                self._v("v1", f"devices/{device_id}/{command}.json"),
                json_body=body or {},
                expected=(200, 201, 202),
            )
        except NotFoundError:
            return {
                "device_id": device_id,
                "command": command,
                "supported_by_plan": False,
                "manual_step_required": (
                    f"Command '{command}' is not exposed by your Scalefusion plan/API version. "
                    "Perform it in the dashboard."
                ),
            }
        return {"device_id": device_id, "command": command, "issued": True, "response": outcome or {}}

    async def lock_device(self, device_id: str, *, message: str = "") -> dict[str, Any]:
        return await self._command(device_id, "lock_device", {"message": message} if message else None)

    async def unlock_device(self, device_id: str) -> dict[str, Any]:
        return await self._command(device_id, "unlock_device")

    async def send_alarm(self, device_id: str) -> dict[str, Any]:
        """Buzz the device to locate it. Not supported on iOS 13+."""
        return await self._command(device_id, "send_alarm")

    async def wipe_device(self, device_id: str, *, retention: bool = False) -> dict[str, Any]:
        """``retention=True`` performs a *work-profile only* wipe (BYOD-safe)."""
        body = {"retain_data": retention} if retention else {}
        return await self._command(device_id, "wipe_device", body)

    async def retire_device(self, device_id: str) -> dict[str, Any]:
        return await self._command(device_id, "retire_device")


def _unwrap(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("devices", "items", "value", "data", "results", "device_profiles", "device_groups"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


# --------------------------------------------------------------------------- #
# Mock implementation
# --------------------------------------------------------------------------- #


class MockScalefusionConnector(ScalefusionConnector):
    def __init__(
        self, settings: ScalefusionSettings, audit: AuditLog | None = None, store: MockStore | None = None
    ) -> None:
        super().__init__(settings, audit)
        self.store = store or get_mock_store()

    async def authenticate(self) -> None:
        self._token = "mock-scalefusion-key"
        self._token_expires_at = time.time() + 86_400

    async def health(self) -> HealthStatus:
        return HealthStatus(
            self.name, True, "mock",
            f"simulated fleet: {len(self.store.scalefusion_devices)} devices, "
            f"{len(self.store.scalefusion_profiles)} profiles",
        )

    def _dev(self, device_id: str) -> dict[str, Any]:
        device = self.store.scalefusion_devices.get(device_id)
        if not device:
            device = next(
                (d for d in self.store.scalefusion_devices.values() if d["device_name"] == device_id), None
            )
        if not device:
            raise NotFoundError(f"mock Scalefusion: no device '{device_id}'", platform=self.name)
        return device

    async def list_devices(self, *, page: int | None = None) -> list[Device]:
        return [_map_device(d) for d in self.store.scalefusion_devices.values()]

    async def get_device(self, device_id: str) -> Device | None:
        try:
            return _map_device(self._dev(device_id))
        except NotFoundError:
            return None

    async def get_device_battery(self, device_id: str) -> dict[str, Any]:
        device = self._dev(device_id)
        return {
            "device_id": device["id"],
            "battery_level": device.get("battery_level"),
            "charging": False,
            "temperature_c": 31,
        }

    async def get_device_apps(self, device_id: str, *, installed: bool = True) -> list[dict[str, Any]]:
        device = self._dev(device_id)
        base = [
            {"name": "Microsoft Outlook", "package": "com.microsoft.office.outlook", "version": "4.2412"},
            {"name": "Microsoft Teams", "package": "com.microsoft.teams", "version": "1416/1.0"},
            {"name": "Scalefusion Agent", "package": "com.promobitech.mobilock.pro", "version": "12.4"},
        ]
        if device.get("ownership") == "byod":
            base.append({"name": "WhatsApp", "package": "com.whatsapp", "version": "2.26.1"})
        return base

    async def get_device_location(self, device_id: str) -> dict[str, Any]:
        device = self._dev(device_id)
        return {"device_id": device["id"], "locations": [device.get("location", {})]}

    async def list_device_profiles(self) -> list[dict[str, Any]]:
        return [
            {"id": pid, "name": p["name"], "description": p.get("description", "")}
            for pid, p in self.store.scalefusion_profiles.items()
        ]

    async def list_device_groups(self) -> list[dict[str, Any]]:
        return [
            {
                "id": gid,
                "name": g["name"],
                "device_profile_id": g["device_profile_id"],
                "device_count": len(g["devices"]),
            }
            for gid, g in self.store.scalefusion_groups.items()
        ]

    async def find_devices_by_user(self, user: str) -> list[Device]:
        devices = await self.list_devices()
        needle = user.lower().strip()
        return [
            d
            for d in devices
            if needle and needle in " ".join([d.assigned_email, d.assigned_user, d.device_name]).lower()
        ]

    # ---- writes ---------------------------------------------------------- #

    async def apply_device_profile(self, profile_id: str, device_ids: list[str]) -> dict[str, Any]:
        pid = await self.resolve_profile_id(profile_id)
        profile = self.store.scalefusion_profiles[pid]
        applied = []
        for ref in device_ids:
            device = self._dev(ref)
            device["device_profile_id"] = pid
            applied.append(device["id"])
        self.store.log_event(
            "scalefusion.apply_device_profile", profile=pid, name=profile["name"], devices=applied
        )
        return {"profile_id": pid, "profile_name": profile["name"], "applied_to": applied, "simulated": True}

    async def remove_device_profile(self, profile_id: str, device_ids: list[str]) -> dict[str, Any]:
        pid = await self.resolve_profile_id(profile_id)
        removed = []
        for ref in device_ids:
            device = self._dev(ref)
            if device["device_profile_id"] == pid:
                device["device_profile_id"] = ""
                removed.append(device["id"])
        self.store.log_event("scalefusion.remove_device_profile", profile=pid, devices=removed)
        return {"profile_id": pid, "removed_from": removed, "simulated": True}

    async def add_device_to_group(self, group_id: str, device_ids: list[str]) -> dict[str, Any]:
        gid = await self.resolve_group_id(group_id)
        group = self.store.scalefusion_groups[gid]
        added = []
        for ref in device_ids:
            device = self._dev(ref)
            if device["id"] not in group["devices"]:
                group["devices"].append(device["id"])
            device["device_group_id"] = gid
            added.append(device["id"])
        self.store.log_event("scalefusion.add_device_to_group", group=gid, devices=added)
        return {"group_id": gid, "group_name": group["name"], "added": added, "simulated": True}

    async def remove_device_from_group(self, group_id: str, device_ids: list[str]) -> dict[str, Any]:
        gid = await self.resolve_group_id(group_id)
        group = self.store.scalefusion_groups[gid]
        targets = {self._dev(ref)["id"] for ref in device_ids}
        group["devices"] = [d for d in group["devices"] if d not in targets]
        self.store.log_event("scalefusion.remove_device_from_group", group=gid, devices=sorted(targets))
        return {"group_id": gid, "removed": sorted(targets), "simulated": True}

    async def assign_device_user(self, device_id: str, user_email: str, user_name: str = "") -> dict[str, Any]:
        device = self._dev(device_id)
        user = self.store.find_user(email=user_email)
        device["user_email"] = user_email.lower()
        device["user_name"] = user_name or (user or {}).get("display_name", "")
        device["user_id"] = (user or {}).get("id", device.get("user_id", ""))
        self.store.log_event("scalefusion.assign_device_user", device=device["id"], user=user_email)
        return {"device_id": device["id"], "user_email": user_email, "assigned": True, "simulated": True}

    async def unassign_device_user(self, device_id: str) -> dict[str, Any]:
        device = self._dev(device_id)
        previous = device.get("user_email", "")
        device["user_email"] = ""
        device["user_name"] = ""
        device["user_id"] = ""
        self.store.log_event("scalefusion.unassign_device_user", device=device["id"], previous=previous)
        return {"device_id": device["id"], "previous_user": previous, "unassigned": True, "simulated": True}

    async def lock_device(self, device_id: str, *, message: str = "") -> dict[str, Any]:
        device = self._dev(device_id)
        device["locked"] = True
        device["status"] = "locked"
        self.store.log_event("scalefusion.lock_device", device=device["id"], message=message)
        return {"device_id": device["id"], "locked": True, "simulated": True}

    async def unlock_device(self, device_id: str) -> dict[str, Any]:
        device = self._dev(device_id)
        device["locked"] = False
        device["status"] = "active"
        self.store.log_event("scalefusion.unlock_device", device=device["id"])
        return {"device_id": device["id"], "unlocked": True, "simulated": True}

    async def send_alarm(self, device_id: str) -> dict[str, Any]:
        device = self._dev(device_id)
        self.store.log_event("scalefusion.send_alarm", device=device["id"])
        return {
            "device_id": device["id"],
            "buzzed": True,
            "simulated": True,
            "note": "Not supported on iOS 13+" if device.get("os") == "ios" else "",
        }

    async def wipe_device(self, device_id: str, *, retention: bool = False) -> dict[str, Any]:
        device = self._dev(device_id)
        # Hard guard duplicated here: the policy engine is the authority, but the
        # connector must never wipe a BYOD device even if called directly.
        if str(device.get("ownership", "")).lower() == "byod" and not retention:
            return {
                "device_id": device["id"],
                "wiped": False,
                "refused": True,
                "reason": "BYOD device: full wipe refused. Use retention=True (work profile only) or retire_device.",
            }
        device["wiped"] = True
        device["status"] = "wiped"
        device["user_email"] = ""
        device["user_name"] = ""
        self.store.log_event("scalefusion.wipe_device", device=device["id"], retention=retention)
        return {
            "device_id": device["id"],
            "wiped": True,
            "work_profile_only": retention,
            "simulated": True,
        }

    async def retire_device(self, device_id: str) -> dict[str, Any]:
        device = self._dev(device_id)
        device["retired"] = True
        device["status"] = "retired"
        device["user_email"] = ""
        device["user_name"] = ""
        for group in self.store.scalefusion_groups.values():
            group["devices"] = [d for d in group["devices"] if d != device["id"]]
        self.store.log_event("scalefusion.retire_device", device=device["id"])
        return {"device_id": device["id"], "retired": True, "unenrolled": True, "simulated": True}


def build_scalefusion_connector(
    settings: ScalefusionSettings, audit: AuditLog | None = None, store: MockStore | None = None
) -> ScalefusionConnector:
    if settings.enabled and settings.backend == "live":
        return LiveScalefusionConnector(settings, audit)
    return MockScalefusionConnector(settings, audit, store)
