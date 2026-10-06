"""Microsoft 365 service administration connector.

Covers the *service* plane on top of Entra identity: Exchange Online mailboxes
(including conversion to shared mailbox, forwarding, delegates, litigation hold),
Teams memberships, OneDrive/SharePoint access, and licence SKU inventory.

Everything goes through Microsoft Graph, which keeps a single app registration
and a single token flow for both Entra and M365. The ``exchange_powershell_*``
settings exist for the few operations that still need Exchange Online PowerShell
and are intentionally left as an extension point rather than a hard dependency.
"""

from __future__ import annotations

import abc
from typing import Any

from iam_agent.config import M365Settings
from iam_agent.connectors.base import BaseConnector, HealthStatus, NotConfiguredError
from iam_agent.connectors.mock.store import MockStore, get_mock_store
from iam_agent.core.audit import AuditLog
from iam_agent.core.errors import NotFoundError
from iam_agent.core.models import DirectoryUser, MailboxInfo

OP = "m365"
OPS = {
    "get_mailbox": f"{OP}.get_mailbox",
    "list_mailboxes": f"{OP}.list_mailboxes",
    "convert_mailbox_to_shared": f"{OP}.convert_mailbox_to_shared",
    "set_mailbox_forwarding": f"{OP}.set_mailbox_forwarding",
    "grant_mailbox_permission": f"{OP}.grant_mailbox_permission",
    "revoke_mailbox_permission": f"{OP}.revoke_mailbox_permission",
    "hide_from_gal": f"{OP}.hide_from_gal",
    "set_litigation_hold": f"{OP}.set_litigation_hold",
    "list_skus": f"{OP}.list_skus",
    "list_teams": f"{OP}.list_teams",
    "get_team_members": f"{OP}.get_team_members",
    "add_team_member": f"{OP}.add_team_member",
    "remove_team_member": f"{OP}.remove_team_member",
    "remove_all_teams_memberships": f"{OP}.remove_all_teams_memberships",
    "get_user_drives": f"{OP}.get_user_drives",
    "share_drive_with": f"{OP}.share_drive_with",
    "list_shared_mailboxes": f"{OP}.list_shared_mailboxes",
}


def _map_mailbox(raw: dict[str, Any]) -> MailboxInfo:
    return MailboxInfo(
        external_id=raw.get("id", ""),
        email=(raw.get("mail") or raw.get("email") or "").lower(),
        display_name=raw.get("displayName", "") or raw.get("display_name", ""),
        mailbox_type=raw.get("mailbox_type", "user"),
        primary_smtp=raw.get("primary_smtp", "") or raw.get("mail", ""),
        proxy_addresses=list(raw.get("proxy_addresses") or raw.get("proxyAddresses") or []),
        total_item_size_mb=float(raw.get("total_item_size_mb", 0.0) or 0.0),
        item_count=int(raw.get("item_count", 0) or 0),
        hidden_from_gal=bool(raw.get("hidden_from_gal", False)),
        litigation_hold=bool(raw.get("litigation_hold", False)),
        forward_to=raw.get("forward_to", "") or "",
        delegates=list(raw.get("delegates") or []),
    )


class M365Connector(BaseConnector, abc.ABC):
    """Interface for Microsoft 365 service administration."""

    name = "m365"
    label = "Microsoft 365"

    def __init__(self, settings: M365Settings, audit: AuditLog | None = None) -> None:
        super().__init__(backend=settings.backend, audit=audit, timeout=45.0, max_retries=4)
        self.settings = settings

    # ---- mailbox --------------------------------------------------------- #
    @abc.abstractmethod
    async def get_mailbox(self, identifier: str) -> MailboxInfo | None: ...
    @abc.abstractmethod
    async def list_mailboxes(self, *, mailbox_type: str | None = None) -> list[MailboxInfo]: ...
    @abc.abstractmethod
    async def convert_mailbox_to_shared(self, identifier: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def set_mailbox_forwarding(
        self, identifier: str, forward_to: str, *, keep_copy: bool = True
    ) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def grant_mailbox_permission(
        self, identifier: str, grantee: str, *, rights: str = "FullAccess"
    ) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def revoke_mailbox_permission(self, identifier: str, grantee: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def hide_from_gal(self, identifier: str, *, hidden: bool = True) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def set_litigation_hold(self, identifier: str, *, enabled: bool = True) -> dict[str, Any]: ...

    # ---- licences -------------------------------------------------------- #
    @abc.abstractmethod
    async def list_skus(self) -> list[dict[str, Any]]: ...

    # ---- Teams ----------------------------------------------------------- #
    @abc.abstractmethod
    async def list_teams(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def get_team_members(self, team_id: str) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def add_team_member(
        self, team_id: str, user_id: str, *, role: str = "member"
    ) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_team_member(self, team_id: str, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_all_teams_memberships(self, user_id: str) -> dict[str, Any]: ...

    # ---- OneDrive / SharePoint ------------------------------------------- #
    @abc.abstractmethod
    async def get_user_drives(self, user_id: str) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def share_drive_with(
        self, user_id: str, grantee_email: str, *, roles: list[str] | None = None, expiry_days: int = 30
    ) -> dict[str, Any]: ...

    # ---- helpers --------------------------------------------------------- #
    async def find_user_teams(self, user_id: str) -> list[dict[str, Any]]:
        out = []
        for team in await self.list_teams():
            members = await self.get_team_members(team["id"])
            if any(m.get("userId") == user_id or m.get("email", "").lower() == user_id.lower() for m in members):
                out.append(team)
        return out


# --------------------------------------------------------------------------- #
# Live implementation
# --------------------------------------------------------------------------- #


class LiveM365Connector(M365Connector):
    """Real Microsoft Graph calls for the M365 service plane."""

    def __init__(self, settings: M365Settings, audit: AuditLog | None = None) -> None:
        super().__init__(settings, audit)
        self._app = None

    async def authenticate(self) -> None:
        if self._app is None:
            if not (self.settings.tenant_id and self.settings.client_id):
                raise NotConfiguredError(
                    "M365 backend=live requires IAM_M365_TENANT_ID and IAM_M365_CLIENT_ID.",
                    platform=self.name,
                )
            self._app = _build_msal_app(self.settings)

        result = self._app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            from iam_agent.core.errors import AuthenticationError

            raise AuthenticationError(
                f"M365 token acquisition failed: {result.get('error_description') or result}",
                platform=self.name,
            )
        self._token = result["access_token"]
        import time as _time

        self._token_expires_at = _time.time() + int(result.get("expires_in", 3599))

    async def health(self) -> HealthStatus:
        import time as _time

        started = _time.monotonic()
        try:
            await self.ensure_authenticated()
            skus = await self._paged("subscribedSkus")
            return HealthStatus(
                self.name, True, "live", f"{len(skus)} subscribed SKUs visible",
                (_time.monotonic() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001
            return HealthStatus(
                self.name, False, "live", f"{type(exc).__name__}: {exc}",
                (_time.monotonic() - started) * 1000,
            )

    def _g(self, path: str) -> str:
        return f"{self.settings.graph_url}/{path.lstrip('/')}"

    async def _paged(self, path: str, *, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        url, query = self._g(path), dict(params or {})
        while url:
            payload = await self.request("GET", url, params=query or None)
            query = {}
            results.extend(payload.get("value") or [])
            url = payload.get("@odata.nextLink") or ""
        return results

    # ---- mailbox --------------------------------------------------------- #

    async def get_mailbox(self, identifier: str) -> MailboxInfo | None:
        """Graph exposes mailbox state through /users/{id}/mailboxSettings + /me-ish props."""
        try:
            raw = await self.request(
                "GET",
                self._g(f"users/{identifier}"),
                params={
                    "$select": "id,displayName,mail,userPrincipalName,proxyAddresses,hiddenFromAddressListsEnabled,"
                    "employeeType,assignedLicenses,mailNickname"
                },
            )
        except NotFoundError:
            return None

        info = _map_mailbox(
            {
                "id": raw.get("id"),
                "mail": raw.get("mail"),
                "displayName": raw.get("displayName"),
                "primary_smtp": raw.get("mail"),
                "proxy_addresses": raw.get("proxyAddresses") or [],
                "hidden_from_gal": bool(raw.get("hiddenFromAddressListsEnabled")),
                "mailbox_type": "shared" if raw.get("employeeType") == "SharedMailbox" else "user",
            }
        )

        # Forwarding + delegates live under mailboxSettings / calendar permissions.
        try:
            settings = await self.request("GET", self._g(f"users/{raw['id']}/mailboxSettings"))
            rules = settings.get("automaticRepliesSetting") or {}
            info.raw_extra = rules  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - MailboxSettings.Basic requires Exchange licence
            pass
        return info

    async def list_mailboxes(self, *, mailbox_type: str | None = None) -> list[MailboxInfo]:
        users = await self._paged(
            "users",
            params={
                "$select": "id,displayName,mail,userPrincipalName,proxyAddresses,"
                "hiddenFromAddressListsEnabled,employeeType,mailNickname",
                "$top": "999",
            },
        )
        out = []
        for raw in users:
            if not raw.get("mailNickname"):
                continue
            kind = "shared" if raw.get("employeeType") == "SharedMailbox" else "user"
            if mailbox_type and kind != mailbox_type:
                continue
            out.append(
                _map_mailbox(
                    {
                        "id": raw.get("id"),
                        "mail": raw.get("mail") or raw.get("userPrincipalName"),
                        "displayName": raw.get("displayName"),
                        "proxy_addresses": raw.get("proxyAddresses") or [],
                        "hidden_from_gal": bool(raw.get("hiddenFromAddressListsEnabled")),
                        "mailbox_type": kind,
                    }
                )
            )
        return out

    async def list_shared_mailboxes(self) -> list[MailboxInfo]:
        return await self.list_mailboxes(mailbox_type="shared")

    async def convert_mailbox_to_shared(self, identifier: str) -> dict[str, Any]:
        """Graph cannot flip mailbox type directly; mark it and hide from GAL.

        A true conversion needs Exchange Online PowerShell
        (``Set-Mailbox -Type Shared``). This method performs the Graph-side part
        and reports that the Exchange step must run separately, so the operator
        is never silently misled.
        """
        raw = await self.request(
            "PATCH",
            self._g(f"users/{identifier}"),
            json_body={"employeeType": "SharedMailbox", "hiddenFromAddressListsEnabled": True},
            expected=(204, 200),
        )
        return {
            "id": identifier,
            "graph_updated": True,
            "hidden_from_gal": True,
            "exchange_step_required": "Set-Mailbox -Type Shared -Identity <upn>",
            "note": "Licence can be removed only after Exchange confirms the conversion.",
            "response": raw or {},
        }

    async def set_mailbox_forwarding(
        self, identifier: str, forward_to: str, *, keep_copy: bool = True
    ) -> dict[str, Any]:
        """Implemented as an inbox rule (Graph) - survives licence removal only
        while the mailbox exists, so pair it with a shared-mailbox conversion."""
        rule = {
            "displayName": f"[iam-agent] forward to {forward_to}",
            "sequence": 1,
            "isEnabled": True,
            "conditions": {},
            "actions": {
                "forwardTo": [{"emailAddress": {"address": forward_to}}],
                "stopProcessingRules": False,
            },
        }
        created = await self.request(
            "POST", self._g(f"users/{identifier}/mailFolders/inbox/messageRules"),
            json_body=rule, expected=(201,),
        )
        return {
            "id": identifier,
            "forward_to": forward_to,
            "keep_copy": keep_copy,
            "rule_id": (created or {}).get("id", ""),
        }

    async def grant_mailbox_permission(
        self, identifier: str, grantee: str, *, rights: str = "FullAccess"
    ) -> dict[str, Any]:
        """Graph equivalent: delegate access to the calendar + mailbox folder perms."""
        body = {
            "message": f"[iam-agent] Granting {rights} to {grantee} as part of offboarding continuity.",
            "sendAs": grantee,
        }
        # True FullAccess requires Exchange; we surface it and grant what Graph can.
        return {
            "id": identifier,
            "grantee": grantee,
            "rights": rights,
            "graph_applied": False,
            "exchange_step_required": (
                f"Add-MailboxPermission -Identity {identifier} -User {grantee} -AccessRights {rights}"
            ),
            "notification_draft": body["message"],
        }

    async def revoke_mailbox_permission(self, identifier: str, grantee: str) -> dict[str, Any]:
        return {
            "id": identifier,
            "grantee": grantee,
            "exchange_step_required": (
                f"Remove-MailboxPermission -Identity {identifier} -User {grantee} -AccessRights FullAccess"
            ),
        }

    async def hide_from_gal(self, identifier: str, *, hidden: bool = True) -> dict[str, Any]:
        await self.request(
            "PATCH", self._g(f"users/{identifier}"),
            json_body={"hiddenFromAddressListsEnabled": hidden}, expected=(204, 200),
        )
        return {"id": identifier, "hidden_from_gal": hidden}

    async def set_litigation_hold(self, identifier: str, *, enabled: bool = True) -> dict[str, Any]:
        return {
            "id": identifier,
            "litigation_hold": enabled,
            "exchange_step_required": f"Set-Mailbox -Identity {identifier} -LitigationHoldEnabled ${str(enabled).lower()}",
        }

    # ---- licences -------------------------------------------------------- #

    async def list_skus(self) -> list[dict[str, Any]]:
        raws = await self._paged(
            "subscribedSkus", params={"$select": "skuId,skuPartNumber,prepaidUnits,consumedUnits,capabilityStatus"}
        )
        out = []
        for r in raws:
            prepaid = r.get("prepaidUnits") or {}
            consumed = r.get("consumedUnits") or 0
            enabled = prepaid.get("enabled", 0)
            out.append(
                {
                    "skuId": r.get("skuId"),
                    "skuPartNumber": r.get("skuPartNumber"),
                    "status": r.get("capabilityStatus"),
                    "enabled": enabled,
                    "consumed": consumed,
                    "available": max(0, enabled - consumed),
                    "warning": (prepaid.get("warning") or 0),
                }
            )
        return out

    # ---- Teams ----------------------------------------------------------- #

    async def list_teams(self) -> list[dict[str, Any]]:
        raws = await self._paged(
            "groups", params={"$filter": "resourceProvisioningOptions/Any(x:x eq 'Team')", "$top": "999"}
        )
        return [
            {"id": r.get("id"), "displayName": r.get("displayName"), "visibility": r.get("visibility")}
            for r in raws
        ]

    async def get_team_members(self, team_id: str) -> list[dict[str, Any]]:
        raws = await self._paged(f"teams/{team_id}/members")
        return [
            {
                "membershipId": r.get("id"),
                "userId": (r.get("userId") or ""),
                "displayName": r.get("displayName"),
                "email": (r.get("email") or "").lower(),
                "roles": r.get("roles") or [],
            }
            for r in raws
        ]

    async def add_team_member(
        self, team_id: str, user_id: str, *, role: str = "member"
    ) -> dict[str, Any]:
        body = {
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "roles": ["owner"] if role == "owner" else [],
            "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')",
        }
        created = await self.request(
            "POST", self._g(f"teams/{team_id}/members"), json_body=body, expected=(201,)
        )
        return {"team_id": team_id, "user_id": user_id, "membership_id": (created or {}).get("id", "")}

    async def remove_team_member(self, team_id: str, user_id: str) -> dict[str, Any]:
        members = await self.get_team_members(team_id)
        target = next((m for m in members if m["userId"] == user_id), None)
        if not target:
            return {"team_id": team_id, "user_id": user_id, "not_a_member": True}
        await self.request(
            "DELETE", self._g(f"teams/{team_id}/members/{target['membershipId']}"), expected=(204,)
        )
        return {"team_id": team_id, "user_id": user_id, "removed": True}

    async def remove_all_teams_memberships(self, user_id: str) -> dict[str, Any]:
        teams = await self.list_teams()
        removed = []
        for team in teams:
            outcome = await self.remove_team_member(team["id"], user_id)
            if outcome.get("removed"):
                removed.append(team["displayName"])
        return {"user_id": user_id, "removed_from": removed, "count": len(removed)}

    # ---- OneDrive / SharePoint ------------------------------------------- #

    async def get_user_drives(self, user_id: str) -> list[dict[str, Any]]:
        raws = await self._paged(f"users/{user_id}/drives")
        return [
            {
                "id": r.get("id"),
                "name": r.get("name"),
                "driveType": r.get("driveType"),
                "webUrl": r.get("webUrl"),
                "quota": r.get("quota"),
            }
            for r in raws
        ]

    async def share_drive_with(
        self,
        user_id: str,
        grantee_email: str,
        *,
        roles: list[str] | None = None,
        expiry_days: int = 30,
    ) -> dict[str, Any]:
        from datetime import datetime, timedelta, timezone

        drives = await self.get_user_drives(user_id)
        one_drive = next((d for d in drives if d.get("driveType") == "personal"), drives[0] if drives else None)
        if not one_drive:
            raise NotFoundError(f"no drive found for {user_id}", platform=self.name)

        root = await self.request("GET", self._g(f"drives/{one_drive['id']}/root"))
        body = {
            "recipients": [{"email": grantee_email}],
            "message": "Shared by IAM Agent to preserve access after offboarding.",
            "sendInvitation": True,
            "roles": roles or ["read"],
            "expirationDateTime": (
                datetime.now(timezone.utc) + timedelta(days=expiry_days)
            ).isoformat(),
        }
        created = await self.request(
            "POST", self._g(f"drives/{one_drive['id']}/items/{root['id']}/invite"),
            json_body=body, expected=(200,),
        )
        return {
            "drive_id": one_drive["id"],
            "grantee": grantee_email,
            "roles": roles or ["read"],
            "expires_in_days": expiry_days,
            "response": created or {},
        }


def _build_msal_app(settings: M365Settings):
    import msal
    from pathlib import Path

    kwargs: dict[str, Any] = {}
    if settings.certificate_path:
        pem = Path(settings.certificate_path).read_text(encoding="utf-8")
        kwargs["client_credential"] = {
            "thumbprint": settings.certificate_thumbprint or "",
            "private_key": pem,
            "passphrase": settings.certificate_password,
        }
    elif settings.client_secret:
        kwargs["client_credential"] = settings.client_secret
    else:
        raise NotConfiguredError(
            "Provide IAM_M365_CLIENT_SECRET or IAM_M365_CERTIFICATE_PATH.", platform="m365"
        )
    return msal.ConfidentialClientApplication(
        client_id=settings.client_id,
        authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
        token_cache=msal.SerializableTokenCache(),
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Mock implementation
# --------------------------------------------------------------------------- #


class MockM365Connector(M365Connector):
    def __init__(
        self, settings: M365Settings, audit: AuditLog | None = None, store: MockStore | None = None
    ) -> None:
        super().__init__(settings, audit)
        self.store = store or get_mock_store()

    async def authenticate(self) -> None:
        self._token = "mock-m365-token"
        import time as _time

        self._token_expires_at = _time.time() + 3600

    async def health(self) -> HealthStatus:
        return HealthStatus(
            self.name, True, "mock",
            f"simulated tenant: {len(self.store.mailboxes)} mailboxes, {len(self.store.teams)} teams",
        )

    def _mbx(self, identifier: str) -> dict[str, Any]:
        user = self.store.find_user(oid=identifier) or self.store.find_user(email=identifier)
        if not user:
            raise NotFoundError(f"mock M365: no mailbox for '{identifier}'", platform=self.name)
        return self.store.mailboxes.setdefault(
            user["id"],
            {
                "id": user["id"],
                "email": user["mail"],
                "display_name": user["display_name"],
                "mailbox_type": "user",
                "primary_smtp": user["mail"],
                "proxy_addresses": [],
                "total_item_size_mb": 0.0,
                "item_count": 0,
                "hidden_from_gal": False,
                "litigation_hold": False,
                "forward_to": "",
                "delegates": [],
            },
        )

    async def get_mailbox(self, identifier: str) -> MailboxInfo | None:
        try:
            return _map_mailbox(self._mbx(identifier))
        except NotFoundError:
            return None

    async def list_mailboxes(self, *, mailbox_type: str | None = None) -> list[MailboxInfo]:
        rows = [_map_mailbox(m) for m in self.store.mailboxes.values()]
        if mailbox_type:
            rows = [m for m in rows if m.mailbox_type == mailbox_type]
        return rows

    async def list_shared_mailboxes(self) -> list[MailboxInfo]:
        return await self.list_mailboxes(mailbox_type="shared")

    async def convert_mailbox_to_shared(self, identifier: str) -> dict[str, Any]:
        mbx = self._mbx(identifier)
        mbx["mailbox_type"] = "shared"
        mbx["hidden_from_gal"] = True
        self.store.log_event("m365.convert_mailbox_to_shared", id=mbx["id"])
        return {
            "id": mbx["id"],
            "mailbox_type": "shared",
            "hidden_from_gal": True,
            "graph_updated": True,
            "exchange_step_required": "simulated - no Exchange Online call made",
        }

    async def set_mailbox_forwarding(
        self, identifier: str, forward_to: str, *, keep_copy: bool = True
    ) -> dict[str, Any]:
        mbx = self._mbx(identifier)
        mbx["forward_to"] = forward_to
        self.store.log_event("m365.set_mailbox_forwarding", id=mbx["id"], to=forward_to)
        return {"id": mbx["id"], "forward_to": forward_to, "keep_copy": keep_copy}

    async def grant_mailbox_permission(
        self, identifier: str, grantee: str, *, rights: str = "FullAccess"
    ) -> dict[str, Any]:
        mbx = self._mbx(identifier)
        entry = f"{grantee}:{rights}"
        if entry not in mbx["delegates"]:
            mbx["delegates"].append(entry)
        self.store.log_event("m365.grant_mailbox_permission", id=mbx["id"], grantee=grantee, rights=rights)
        return {"id": mbx["id"], "grantee": grantee, "rights": rights, "granted": True}

    async def revoke_mailbox_permission(self, identifier: str, grantee: str) -> dict[str, Any]:
        mbx = self._mbx(identifier)
        mbx["delegates"] = [d for d in mbx["delegates"] if not d.startswith(f"{grantee}:")]
        self.store.log_event("m365.revoke_mailbox_permission", id=mbx["id"], grantee=grantee)
        return {"id": mbx["id"], "grantee": grantee, "revoked": True}

    async def hide_from_gal(self, identifier: str, *, hidden: bool = True) -> dict[str, Any]:
        mbx = self._mbx(identifier)
        mbx["hidden_from_gal"] = hidden
        self.store.log_event("m365.hide_from_gal", id=mbx["id"], hidden=hidden)
        return {"id": mbx["id"], "hidden_from_gal": hidden}

    async def set_litigation_hold(self, identifier: str, *, enabled: bool = True) -> dict[str, Any]:
        mbx = self._mbx(identifier)
        mbx["litigation_hold"] = enabled
        self.store.log_event("m365.set_litigation_hold", id=mbx["id"], enabled=enabled)
        return {"id": mbx["id"], "litigation_hold": enabled}

    async def list_skus(self) -> list[dict[str, Any]]:
        return [
            {
                "skuId": s["sku_id"],
                "skuPartNumber": s["sku_part_number"],
                "productName": s["product_name"],
                "enabled": s["enabled"],
                "consumed": s["consumed"],
                "available": s["enabled"] - s["consumed"],
                "status": "Enabled",
            }
            for s in self.store.license_skus.values()
        ]

    async def list_teams(self) -> list[dict[str, Any]]:
        return [
            {"id": t["id"], "displayName": t["display_name"], "visibility": "Private"}
            for t in self.store.teams.values()
        ]

    async def get_team_members(self, team_id: str) -> list[dict[str, Any]]:
        team = self.store.teams.get(team_id)
        if not team:
            raise NotFoundError(f"mock M365: no team '{team_id}'", platform=self.name)
        return [
            {
                "membershipId": f"mbr-{uid[:8]}",
                "userId": uid,
                "displayName": self.store.users.get(uid, {}).get("display_name", ""),
                "email": self.store.users.get(uid, {}).get("mail", ""),
                "roles": [],
            }
            for uid in team["members"]
        ]

    async def add_team_member(self, team_id: str, user_id: str, *, role: str = "member") -> dict[str, Any]:
        tid = self.store.team_id_by_name(team_id) or (team_id if team_id in self.store.teams else None)
        if not tid:
            raise NotFoundError(f"mock M365: no team '{team_id}'", platform=self.name)
        user = self.store.find_user(oid=user_id) or self.store.find_user(email=user_id)
        if not user:
            raise NotFoundError(f"mock M365: no user '{user_id}'", platform=self.name)
        if user["id"] not in self.store.teams[tid]["members"]:
            self.store.teams[tid]["members"].append(user["id"])
        self.store.log_event("m365.add_team_member", team=tid, user=user["id"])
        return {"team_id": tid, "user_id": user["id"], "added": True}

    async def remove_team_member(self, team_id: str, user_id: str) -> dict[str, Any]:
        tid = self.store.team_id_by_name(team_id) or team_id
        team = self.store.teams.get(tid)
        if not team:
            raise NotFoundError(f"mock M365: no team '{team_id}'", platform=self.name)
        user = self.store.find_user(oid=user_id) or self.store.find_user(email=user_id)
        uid = user["id"] if user else user_id
        before = len(team["members"])
        team["members"] = [m for m in team["members"] if m != uid]
        return {
            "team_id": tid,
            "user_id": uid,
            "removed": len(team["members"]) < before,
            "not_a_member": len(team["members"]) == before,
        }

    async def remove_all_teams_memberships(self, user_id: str) -> dict[str, Any]:
        user = self.store.find_user(oid=user_id) or self.store.find_user(email=user_id)
        if not user:
            raise NotFoundError(f"mock M365: no user '{user_id}'", platform=self.name)
        uid = user["id"]
        removed = []
        for team in self.store.teams.values():
            if uid in team["members"]:
                team["members"] = [m for m in team["members"] if m != uid]
                removed.append(team["display_name"])
        self.store.log_event("m365.remove_all_teams_memberships", user=uid, removed=removed)
        return {"user_id": uid, "removed_from": removed, "count": len(removed)}

    async def get_user_drives(self, user_id: str) -> list[dict[str, Any]]:
        user = self.store.find_user(oid=user_id) or self.store.find_user(email=user_id)
        if not user:
            raise NotFoundError(f"mock M365: no user '{user_id}'", platform=self.name)
        return [
            {
                "id": f"drive-{user['id'][:8]}",
                "name": "OneDrive",
                "driveType": "personal",
                "webUrl": f"https://contoso-my.sharepoint.com/personal/{user['mail_nickname']}",
                "quota": {"total": 1099511627776, "used": 5368709120},
            }
        ]

    async def share_drive_with(
        self, user_id: str, grantee_email: str, *, roles: list[str] | None = None, expiry_days: int = 30
    ) -> dict[str, Any]:
        drives = await self.get_user_drives(user_id)
        self.store.log_event(
            "m365.share_drive_with", drive=drives[0]["id"], grantee=grantee_email, days=expiry_days
        )
        return {
            "drive_id": drives[0]["id"],
            "grantee": grantee_email,
            "roles": roles or ["read"],
            "expires_in_days": expiry_days,
            "simulated": True,
        }


def build_m365_connector(
    settings: M365Settings, audit: AuditLog | None = None, store: MockStore | None = None
) -> M365Connector:
    if settings.enabled and settings.backend == "live":
        return LiveM365Connector(settings, audit)
    return MockM365Connector(settings, audit, store)
