"""Azure Entra ID connector (Microsoft Graph).

This is the *identity plane*: user objects, group membership, directory roles,
sign-in activity, MFA registration and Entra ID Governance Lifecycle Workflows.

Authentication is the OAuth 2.0 **client credentials** flow via ``msal``'s
``ConfidentialClientApplication``. Use an app registration with *application*
permissions (not delegated) so the agent can run unattended; grant admin consent
for the scopes listed in ``docs/PERMISSIONS.md``.
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any

import msal

from iam_agent.config import EntraSettings
from iam_agent.connectors.base import BaseConnector, HealthStatus, NotConfiguredError
from iam_agent.connectors.mock.store import MockStore, get_mock_store
from iam_agent.core.audit import AuditLog
from iam_agent.core.errors import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
)
from iam_agent.core.models import DirectoryGroup, DirectoryUser, Employee

# Operation verbs - these strings are what the policy engine matches on.
OP = "entra"
OPS = {
    "get_user": f"{OP}.get_user",
    "list_users": f"{OP}.list_users",
    "create_user": f"{OP}.create_user",
    "update_user": f"{OP}.update_user",
    "disable_user": f"{OP}.disable_user",
    "enable_user": f"{OP}.enable_user",
    "delete_user": f"{OP}.delete_user",
    "add_group_member": f"{OP}.add_group_member",
    "remove_group_member": f"{OP}.remove_group_member",
    "remove_all_group_memberships": f"{OP}.remove_all_group_memberships",
    "assign_license": f"{OP}.assign_license",
    "remove_all_licenses": f"{OP}.remove_all_licenses",
    "grant_role": f"{OP}.grant_role",
    "revoke_role": f"{OP}.revoke_role",
    "create_temporary_access_pass": f"{OP}.create_temporary_access_pass",
    "revoke_all_sessions": f"{OP}.revoke_all_sessions",
    "set_manager": f"{OP}.set_manager",
    "run_lifecycle_workflow": f"{OP}.run_lifecycle_workflow",
    "list_lifecycle_workflows": f"{OP}.list_lifecycle_workflows",
    "get_default_domain": f"{OP}.get_default_domain",
}

# Well-known Lifecycle Workflows task definition IDs (Microsoft-published, stable).
TASK_DEFINITION_IDS: dict[str, str] = {
    "enable_user_account": "6fc52c9d-398b-4305-9763-15f42c1676fc",
    "disable_user_account": "1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950",
    "delete_user": "8d18588d-9ad3-4c0f-99d0-ec215f0e3dff",
    "add_user_to_groups": "22085229-5809-45e8-97fd-270d28d66910",
    "remove_user_from_selected_groups": "1953a66c-751c-45e5-8bfe-01462c70da3c",
    "remove_user_from_all_groups": "b3a31406-2a15-4c9a-b25b-a658fa5f07fc",
    "add_user_to_teams": "e440ed8d-25a1-4618-84ce-091ed5be5594",
    "remove_user_from_selected_teams": "06aa7acb-01af-4824-8899-b14e5ed788d6",
    "remove_user_from_all_teams": "81f7b200-2816-4b3b-8c5d-dc556f07b024",
    "remove_all_licenses": "8fa97d28-3e52-4985-b3a9-a1126f9b8b4e",
    "generate_tap_and_send_email": "1b555e50-7f65-41d5-b514-5894a026d10d",
    "send_welcome_email": "70b29d51-b59a-4773-9280-8841dfd3f2ea",
    "run_custom_task_extension": "4262b724-8dba-4fad-afc3-43fcbb497a0e",
    "email_manager_before_last_day": "52853a3e-f4e5-4eb8-bb24-1ac09a1da935",
    "email_on_last_day": "9c0a1eaf-5bda-4392-9d9e-6e155bb57411",
    "email_manager_after_last_day": "6f22ddd4-b3a5-47a4-a846-0d7c201a49ce",
    "email_about_user_inactivity": "92f74cb4-f1b6-4ec0-b766-96210f56edc2",
    "notify_manager_of_move": "aab41899-9972-422a-9d97-f626014578b7",
}


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _map_user(raw: dict[str, Any]) -> DirectoryUser:
    """Translate a Graph user resource into the normalised model."""
    licenses = []
    for assigned in raw.get("assignedLicenses") or []:
        licenses.append(str(assigned.get("skuId", "")))
    # Graph returns skuId GUIDs; the mock uses part numbers - keep both usable.
    licenses += [str(s) for s in raw.get("licensePartNumbers") or []]

    sign_in = raw.get("signInActivity") or {}
    return DirectoryUser(
        platform="entra",
        external_id=raw.get("id", ""),
        username=raw.get("mailNickname") or raw.get("onPremisesSamAccountName") or "",
        upn=raw.get("userPrincipalName", ""),
        email=(raw.get("mail") or raw.get("userPrincipalName") or "").lower(),
        display_name=raw.get("displayName", ""),
        first_name=raw.get("givenName", ""),
        last_name=raw.get("surname", ""),
        job_title=raw.get("jobTitle", "") or "",
        department=raw.get("department", "") or "",
        company=raw.get("companyName", "") or "",
        manager_id=(raw.get("manager") or {}).get("id", "") if isinstance(raw.get("manager"), dict) else "",
        dn=raw.get("onPremisesDistinguishedName", "") or "",
        enabled=bool(raw.get("accountEnabled", True)),
        mfa_registered=raw.get("mfaRegistered"),
        license_skus=licenses,
        group_ids=[g.get("id", "") for g in raw.get("memberOf") or [] if isinstance(g, dict)],
        employee_id=raw.get("employeeId", "") or "",
        on_premises_sync=bool(raw.get("onPremisesSyncEnabled")),
        last_sign_in=_parse_dt(
            sign_in.get("lastSignInDateTime") or raw.get("lastSignInDateTime")
        ),
        account_expires=_parse_dt(raw.get("accountExpires")),
        raw=raw,
    )


def _map_group(raw: dict[str, Any]) -> DirectoryGroup:
    return DirectoryGroup(
        platform="entra",
        external_id=raw.get("id", ""),
        display_name=raw.get("displayName", ""),
        description=raw.get("description", "") or "",
        mail=raw.get("mail", "") or "",
        security_enabled=bool(raw.get("securityEnabled", True)),
        membership_rule=raw.get("membershipRule", "") or "",
        is_dynamic=bool(raw.get("membershipRule")),
        is_role_assignable=bool(raw.get("isAssignableToRole")),
        raw=raw,
    )


def _store_to_graph(raw: dict[str, Any]) -> dict[str, Any]:
    """Map the mock store's snake_case user record onto Graph's camelCase shape.

    The mock must produce exactly what the live connector produces, otherwise a
    workflow validated against the simulator can break in production.
    """
    return {
        "id": raw.get("id", ""),
        "displayName": raw.get("display_name", ""),
        "givenName": raw.get("given_name", ""),
        "surname": raw.get("surname", ""),
        "mail": raw.get("mail", ""),
        "mailNickname": raw.get("mail_nickname", ""),
        "userPrincipalName": raw.get("user_principal_name", ""),
        "jobTitle": raw.get("job_title", ""),
        "department": raw.get("department", ""),
        "companyName": raw.get("company_name", ""),
        "officeLocation": raw.get("office_location", ""),
        "country": raw.get("country", ""),
        "mobilePhone": raw.get("mobile_phone", ""),
        "employeeId": raw.get("employee_id", ""),
        "employeeType": raw.get("employee_type", ""),
        "employeeHireDate": raw.get("employee_hire_date"),
        "employeeLeaveDateTime": raw.get("employee_leave_date_time"),
        "accountEnabled": bool(raw.get("account_enabled", True)),
        "onPremisesSyncEnabled": bool(raw.get("on_premises_sync_enabled", False)),
        "onPremisesSamAccountName": raw.get("on_premises_sam_account_name", ""),
        "onPremisesDistinguishedName": raw.get("dn", ""),
        "lastSignInDateTime": raw.get("last_sign_in"),
        "mfaRegistered": raw.get("mfa_registered"),
        "assignedLicenses": [{"skuId": s} for s in raw.get("licenses", [])],
        "manager": {"id": raw.get("manager_id", "")} if raw.get("manager_id") else None,
        "accountExpires": raw.get("account_expires"),
        "aboutMe": raw.get("description", ""),
    }


def _store_group_to_graph(raw: dict[str, Any]) -> dict[str, Any]:
    """Snake_case store group -> Graph-shaped group."""
    return {
        "id": raw.get("id", ""),
        "displayName": raw.get("display_name", ""),
        "description": raw.get("description", ""),
        "mail": raw.get("mail", ""),
        "securityEnabled": bool(raw.get("security_enabled", True)),
        "membershipRule": raw.get("membership_rule") or "",
        "isAssignableToRole": bool(raw.get("is_role_assignable", False)),
        "groupTypes": raw.get("group_types", []),
        "members": raw.get("members", []),
    }


def employee_to_graph_payload(
    employee: Employee,
    *,
    password: str,
    domain: str = "",
    license_skus: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the POST /users body for a new hire."""
    upn = employee.suggested_upn(domain)
    username = employee.suggested_username(domain)
    payload: dict[str, Any] = {
        "accountEnabled": True,
        "displayName": employee.full_name,
        "givenName": employee.first_name,
        "surname": employee.last_name,
        "mailNickname": username,
        "userPrincipalName": upn,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": password,
        },
        "jobTitle": employee.job_title,
        "department": employee.department,
        "companyName": employee.company,
        "officeLocation": employee.office_location,
        "country": employee.country,
        "city": employee.office_location,
        "mobilePhone": employee.mobile_phone,
        "businessPhones": [p for p in (employee.office_phone,) if p],
        "employeeId": employee.employee_id or employee.worker_id,
        "employeeType": employee.employment_type.value,
        "employeeHireDate": (
            datetime.combine(employee.hire_date, datetime.min.time(), tzinfo=timezone.utc).isoformat()
            if employee.hire_date
            else None
        ),
        "preferredLanguage": "es-ES",
        "usageLocation": employee.country or "ES",
    }
    if employee.email:
        payload["mail"] = employee.email
    if license_skus:
        payload["assignedLicenses"] = license_skus
    return {k: v for k, v in payload.items() if v not in (None, "", [])}


# --------------------------------------------------------------------------- #
# Contract
# --------------------------------------------------------------------------- #


class EntraConnector(BaseConnector, abc.ABC):
    """Interface every Entra backend must satisfy."""

    name = "entra"
    label = "Microsoft Entra ID"

    def __init__(self, settings: EntraSettings, audit: AuditLog | None = None) -> None:
        super().__init__(
            backend=settings.backend,
            audit=audit,
            timeout=45.0,
            max_retries=4,
        )
        self.settings = settings

    # ---- reads ----------------------------------------------------------- #
    @abc.abstractmethod
    async def get_user(self, identifier: str) -> DirectoryUser | None: ...
    @abc.abstractmethod
    async def list_users(self, *, only_enabled: bool | None = None, top: int = 999) -> list[DirectoryUser]: ...
    @abc.abstractmethod
    async def search_users(self, query: str) -> list[DirectoryUser]: ...
    @abc.abstractmethod
    async def list_groups(self) -> list[DirectoryGroup]: ...
    @abc.abstractmethod
    async def get_group(self, identifier: str) -> DirectoryGroup | None: ...
    @abc.abstractmethod
    async def get_user_groups(self, user_id: str) -> list[DirectoryGroup]: ...
    @abc.abstractmethod
    async def get_user_manager(self, user_id: str) -> DirectoryUser | None: ...
    @abc.abstractmethod
    async def list_directory_roles(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def get_user_roles(self, user_id: str) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def get_sign_in_activity(self, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def get_mfa_status(self, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def list_deleted_users(self) -> list[DirectoryUser]: ...
    @abc.abstractmethod
    async def get_default_domain(self) -> str:
        """The tenant's default verified domain, used to build UPNs."""

    # ---- writes ---------------------------------------------------------- #
    @abc.abstractmethod
    async def create_user(self, employee: Employee, *, password: str) -> DirectoryUser: ...
    @abc.abstractmethod
    async def update_user(self, user_id: str, attributes: dict[str, Any]) -> DirectoryUser: ...
    @abc.abstractmethod
    async def disable_user(self, user_id: str, *, reason: str = "") -> DirectoryUser: ...
    @abc.abstractmethod
    async def enable_user(self, user_id: str) -> DirectoryUser: ...
    @abc.abstractmethod
    async def delete_user(self, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def set_manager(self, user_id: str, manager_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def add_group_member(self, group_id: str, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_group_member(self, group_id: str, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_all_group_memberships(self, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def assign_license(self, user_id: str, sku_part_numbers: list[str]) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_all_licenses(self, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def grant_role(self, role_id: str, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def revoke_role(self, role_id: str, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def create_temporary_access_pass(
        self, user_id: str, *, lifetime_minutes: int = 480, one_time: bool = True
    ) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def revoke_sign_in_sessions(self, user_id: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def list_lifecycle_workflows(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    async def run_lifecycle_workflow(self, workflow_id: str, user_ids: list[str]) -> dict[str, Any]: ...

    # ---- shared helpers --------------------------------------------------- #

    async def resolve_role_id(self, name_or_id: str) -> str:
        """Accept either a role display name or an object id."""
        if not name_or_id:
            return ""
        for role in await self.list_directory_roles():
            if role.get("id") == name_or_id or role.get("displayName", "").lower() == name_or_id.lower():
                return role.get("id", "")
        raise NotFoundError(f"Directory role not found: {name_or_id}", platform=self.name)

    async def resolve_group_id(self, name_or_id: str) -> str:
        if not name_or_id:
            return ""
        for group in await self.list_groups():
            if group.external_id == name_or_id or group.display_name.lower() == name_or_id.lower():
                return group.external_id
        raise NotFoundError(f"Group not found: {name_or_id}", platform=self.name)


# --------------------------------------------------------------------------- #
# Live implementation (Microsoft Graph)
# --------------------------------------------------------------------------- #


class LiveEntraConnector(EntraConnector):
    """Talks to the real Microsoft Graph."""

    def __init__(self, settings: EntraSettings, audit: AuditLog | None = None) -> None:
        super().__init__(settings, audit)
        self._app: msal.ConfidentialClientApplication | None = None

    # ---- auth ------------------------------------------------------------ #

    def _build_app(self) -> msal.ConfidentialClientApplication:
        if not (self.settings.tenant_id and self.settings.client_id):
            raise NotConfiguredError(
                "Entra is enabled with backend=live but IAM_ENTRA_TENANT_ID / "
                "IAM_ENTRA_CLIENT_ID are not set.",
                platform=self.name,
            )
        credential_kwargs: dict[str, Any] = {}
        if self.settings.certificate_path:
            from pathlib import Path

            pem = Path(self.settings.certificate_path).read_text(encoding="utf-8")
            credential_kwargs["client_credential"] = {
                "thumbprint": self.settings.certificate_thumbprint or "",
                "private_key": pem,
                "passphrase": self.settings.certificate_password,
            }
        elif self.settings.client_secret:
            credential_kwargs["client_credential"] = self.settings.client_secret
        else:
            raise NotConfiguredError(
                "Provide IAM_ENTRA_CLIENT_SECRET or IAM_ENTRA_CERTIFICATE_PATH.",
                platform=self.name,
            )

        return msal.ConfidentialClientApplication(
            client_id=self.settings.client_id,
            authority=self.settings.resolved_authority(),
            token_cache=msal.SerializableTokenCache(),
            **credential_kwargs,
        )

    async def authenticate(self) -> None:
        if self._app is None:
            self._app = self._build_app()
        result = self._app.acquire_token_for_client(scopes=self.settings.scopes)
        if "access_token" not in result:
            raise AuthenticationError(
                f"Entra token acquisition failed: {result.get('error_description') or result}",
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
            org = await self.request("GET", f"{self.settings.graph_url}/organization")
            name = (org.get("value") or [{}])[0].get("displayName", "unknown tenant")
            return HealthStatus(
                self.name, True, "live", f"connected to tenant '{name}'", (_time.monotonic() - started) * 1000
            )
        except Exception as exc:  # noqa: BLE001 - health must never raise
            return HealthStatus(
                self.name, False, "live", f"{type(exc).__name__}: {exc}", (_time.monotonic() - started) * 1000
            )

    # ---- graph plumbing --------------------------------------------------- #

    def _g(self, path: str) -> str:
        return f"{self.settings.graph_url}/{path.lstrip('/')}"

    async def _paged(self, path: str, *, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Follow @odata.nextLink until exhausted (Graph caps pages at 999)."""
        results: list[dict[str, Any]] = []
        url = self._g(path)
        query = dict(params or {})
        while url:
            payload = await self.request("GET", url, params=query or None)
            query = {}
            results.extend(payload.get("value") or [])
            url = payload.get("@odata.nextLink") or ""
        return results

    async def _resolve_user_id(self, identifier: str) -> str:
        """Accept id, UPN or mail and return the object id."""
        if not identifier:
            raise NotFoundError("empty user identifier", platform=self.name)
        path = f"users/{identifier}"
        try:
            raw = await self.request("GET", self._g(path))
            return raw.get("id", identifier)
        except NotFoundError:
            found = await self.request(
                "GET",
                self._g("users"),
                params={
                    "$filter": (
                        f"mail eq '{identifier}' or userPrincipalName eq '{identifier}' "
                        f"or displayName eq '{identifier}'"
                    ),
                    "$top": "2",
                },
            )
            values = found.get("value") or []
            if not values:
                raise NotFoundError(f"no Entra user matches '{identifier}'", platform=self.name) from None
            if len(values) > 1:
                raise ConflictError(
                    f"'{identifier}' matched {len(values)} users; use the object id", platform=self.name
                )
            return values[0]["id"]

    # ---- reads ----------------------------------------------------------- #

    async def get_user(self, identifier: str) -> DirectoryUser | None:
        try:
            uid = await self._resolve_user_id(identifier)
        except NotFoundError:
            return None
        raw = await self.request(
            "GET",
            self._g(f"users/{uid}"),
            params={
                "$select": ",".join(
                    [
                        "id", "displayName", "givenName", "surname", "mail", "mailNickname",
                        "userPrincipalName", "accountEnabled", "jobTitle", "department",
                        "companyName", "officeLocation", "country", "mobilePhone", "employeeId",
                        "employeeType", "employeeHireDate", "employeeLeaveDateTime",
                        "onPremisesSyncEnabled", "onPremisesSamAccountName",
                        "onPremisesDistinguishedName", "createdDateTime", "usageLocation",
                        "assignedLicenses", "preferredLanguage",
                    ]
                )
            },
        )
        sign_in = await self.get_sign_in_activity(uid)
        mfa = await self.get_mfa_status(uid)
        raw["signInActivity"] = sign_in
        raw["mfaRegistered"] = mfa.get("registered", False)
        return _map_user(raw)

    async def list_users(self, *, only_enabled: bool | None = None, top: int = 999) -> list[DirectoryUser]:
        params: dict[str, Any] = {
            "$select": "id,displayName,mail,userPrincipalName,mailNickname,accountEnabled,"
            "department,jobTitle,employeeId,onPremisesSyncEnabled,onPremisesSamAccountName,"
            "employeeLeaveDateTime,assignedLicenses",
            "$top": str(min(top, 999)),
        }
        if only_enabled is not None:
            params["$filter"] = f"accountEnabled eq {str(bool(only_enabled)).lower()}"
        raws = await self._paged("users", params=params)
        return [_map_user(r) for r in raws]

    async def search_users(self, query: str) -> list[DirectoryUser]:
        raws = await self._paged(
            "users",
            params={
                "$search": f'"displayName:{query}" OR "mail:{query}" OR "userPrincipalName:{query}"',
                "$select": "id,displayName,mail,userPrincipalName,accountEnabled,department,jobTitle",
            },
        )
        return [_map_user(r) for r in raws]

    async def list_groups(self) -> list[DirectoryGroup]:
        raws = await self._paged(
            "groups",
            params={
                "$select": "id,displayName,description,mail,securityEnabled,membershipRule,"
                "isAssignableToRole,groupTypes,visibility",
                "$top": "999",
            },
        )
        return [_map_group(r) for r in raws]

    async def get_group(self, identifier: str) -> DirectoryGroup | None:
        try:
            gid = await self.resolve_group_id(identifier)
        except NotFoundError:
            return None
        raw = await self.request("GET", self._g(f"groups/{gid}"))
        return _map_group(raw)

    async def get_user_groups(self, user_id: str) -> list[DirectoryGroup]:
        uid = await self._resolve_user_id(user_id)
        raws = await self._paged(f"users/{uid}/memberOf")
        return [_map_group(r) for r in raws if r.get("@odata.type", "").endswith("#microsoft.graph.group")]

    async def get_user_manager(self, user_id: str) -> DirectoryUser | None:
        uid = await self._resolve_user_id(user_id)
        try:
            raw = await self.request("GET", self._g(f"users/{uid}/manager"))
        except NotFoundError:
            return None
        return _map_user(raw) if raw.get("id") else None

    async def list_directory_roles(self) -> list[dict[str, Any]]:
        return await self._paged(
            "directoryRoles", params={"$select": "id,displayName,description,roleTemplateId"}
        )

    async def get_user_roles(self, user_id: str) -> list[dict[str, Any]]:
        uid = await self._resolve_user_id(user_id)
        raws = await self._paged(f"users/{uid}/memberOf")
        return [
            {"id": r.get("id"), "displayName": r.get("displayName"), "roleTemplateId": r.get("roleTemplateId")}
            for r in raws
            if r.get("@odata.type", "").endswith("#microsoft.graph.directoryRole")
        ]

    async def get_sign_in_activity(self, user_id: str) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        try:
            raw = await self.request(
                "GET", self._g(f"users/{uid}"), params={"$select": "id,signInActivity"}
            )
        except NotFoundError:
            return {}
        activity = raw.get("signInActivity") or {}
        return {
            "lastSignInDateTime": activity.get("lastSignInDateTime"),
            "lastNonInteractiveSignInDateTime": activity.get("lastNonInteractiveSignInDateTime"),
        }

    async def get_mfa_status(self, user_id: str) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        try:
            methods = await self._paged(f"users/{uid}/authentication/methods")
        except (NotFoundError, Exception):  # noqa: BLE001
            return {"registered": None, "methods": [], "detail": "methods not readable"}
        kinds = [m.get("@odata.type", "").split(".")[-1] for m in methods]
        strong = [k for k in kinds if k not in ("passwordAuthenticationMethod", "")]
        return {"registered": bool(strong), "methods": kinds, "strong_methods": strong}

    async def list_deleted_users(self) -> list[DirectoryUser]:
        raws = await self._paged("directory/deletedItems/microsoft.graph.user")
        return [_map_user(r) for r in raws]

    async def get_default_domain(self) -> str:
        if self.settings.primary_domain:
            return self.settings.primary_domain
        try:
            payload = await self.request(
                "GET", self._g("domains"), params={"$filter": "isDefault eq true", "$top": "1"}
            )
            values = payload.get("value") or []
            if values:
                return str(values[0].get("id", ""))
        except Exception:  # noqa: BLE001 - Domain.Read.All may not be granted
            pass
        # Fall back to whatever the organization object reports.
        try:
            org = await self.request("GET", self._g("organization"))
            domains = ((org.get("value") or [{}])[0]).get("verifiedDomains") or []
            for entry in domains:
                if entry.get("isDefault"):
                    return str(entry.get("name", ""))
            if domains:
                return str(domains[0].get("name", ""))
        except Exception:  # noqa: BLE001
            pass
        return ""

    # ---- writes ---------------------------------------------------------- #

    async def create_user(self, employee: Employee, *, password: str) -> DirectoryUser:
        domain = self.settings.primary_domain or (employee.email.split("@")[-1] if employee.email else "")
        skus = await self._resolve_skus(employee.license_skus or self.settings.default_license_skus)
        payload = employee_to_graph_payload(employee, password=password, domain=domain, license_skus=skus)

        # Idempotency: if the UPN already exists, return it instead of failing.
        existing = await self.get_user(payload["userPrincipalName"])
        if existing:
            return existing

        raw = await self.request("POST", self._g("users"), json_body=payload, expected=(201,))
        user = _map_user(raw)
        if employee.manager and employee.manager.entra_id:
            await self.set_manager(user.external_id, employee.manager.entra_id)
        return user

    async def _resolve_skus(self, part_numbers: list[str]) -> list[dict[str, Any]]:
        """Translate SKU part numbers into Graph's ``{skuId}`` shape."""
        if not part_numbers:
            return []
        catalog = await self._paged(
            "subscribedSkus", params={"$select": "skuId,skuPartNumber,prepaidUnits,consumedUnits"}
        )
        by_part = {s.get("skuPartNumber", "").upper(): s for s in catalog}
        out = []
        for part in part_numbers:
            sku = by_part.get(part.upper()) or by_part.get(part.upper().replace(" ", "_"))
            if sku and sku.get("skuId"):
                out.append({"skuId": sku["skuId"]})
        return out

    async def update_user(self, user_id: str, attributes: dict[str, Any]) -> DirectoryUser:
        uid = await self._resolve_user_id(user_id)
        await self.request("PATCH", self._g(f"users/{uid}"), json_body=attributes, expected=(204, 200))
        return await self.get_user(uid) or DirectoryUser(platform="entra", external_id=uid)

    async def disable_user(self, user_id: str, *, reason: str = "") -> DirectoryUser:
        uid = await self._resolve_user_id(user_id)
        body: dict[str, Any] = {"accountEnabled": False}
        if reason:
            body["aboutMe"] = f"[iam-agent] disabled: {reason}"[:1000]
        await self.request("PATCH", self._g(f"users/{uid}"), json_body=body, expected=(204, 200))
        return await self.get_user(uid) or DirectoryUser(platform="entra", external_id=uid, enabled=False)

    async def enable_user(self, user_id: str) -> DirectoryUser:
        uid = await self._resolve_user_id(user_id)
        await self.request(
            "PATCH", self._g(f"users/{uid}"), json_body={"accountEnabled": True}, expected=(204, 200)
        )
        return await self.get_user(uid) or DirectoryUser(platform="entra", external_id=uid, enabled=True)

    async def delete_user(self, user_id: str) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        await self.request("DELETE", self._g(f"users/{uid}"), expected=(204,))
        return {"deleted": True, "id": uid, "note": "recoverable for 30 days from deletedItems"}

    async def set_manager(self, user_id: str, manager_id: str) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        mid = await self._resolve_user_id(manager_id)
        await self.request(
            "PUT",
            self._g(f"users/{uid}/manager/$ref"),
            json_body={"@odata.id": self._g(f"users/{mid}")},
            expected=(204,),
        )
        return {"user_id": uid, "manager_id": mid}

    async def add_group_member(self, group_id: str, user_id: str) -> dict[str, Any]:
        gid = await self.resolve_group_id(group_id)
        uid = await self._resolve_user_id(user_id)
        try:
            await self.request(
                "POST",
                self._g(f"groups/{gid}/members/$ref"),
                json_body={"@odata.id": self._g(f"users/{uid}")},
                expected=(204,),
            )
        except ConflictError:
            return {"group_id": gid, "user_id": uid, "already_member": True}
        return {"group_id": gid, "user_id": uid, "added": True}

    async def remove_group_member(self, group_id: str, user_id: str) -> dict[str, Any]:
        gid = await self.resolve_group_id(group_id)
        uid = await self._resolve_user_id(user_id)
        await self.request("DELETE", self._g(f"groups/{gid}/members/{uid}/$ref"), expected=(204,))
        return {"group_id": gid, "user_id": uid, "removed": True}

    async def remove_all_group_memberships(self, user_id: str) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        groups = await self.get_user_groups(uid)
        removed, skipped = [], []
        for group in groups:
            if group.is_dynamic:
                skipped.append({"id": group.external_id, "reason": "dynamic group"})
                continue
            try:
                await self.request(
                    "DELETE",
                    self._g(f"groups/{group.external_id}/members/{uid}/$ref"),
                    expected=(204,),
                )
                removed.append(group.display_name)
            except NotFoundError:
                skipped.append({"id": group.external_id, "reason": "already removed"})
        return {"user_id": uid, "removed_from": removed, "skipped": skipped}

    async def assign_license(self, user_id: str, sku_part_numbers: list[str]) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        skus = await self._resolve_skus(sku_part_numbers)
        if not skus:
            return {"user_id": uid, "assigned": [], "warning": "no matching subscribed SKUs"}
        body = {"addLicenses": skus, "removeLicenses": []}
        raw = await self.request("POST", self._g(f"users/{uid}/assignLicense"), json_body=body)
        return {
            "user_id": uid,
            "assigned": [s["skuId"] for s in skus],
            "requested": sku_part_numbers,
            "licenses": [l.get("skuPartNumber") for l in (raw or {}).get("assignedLicenses", [])],
        }

    async def remove_all_licenses(self, user_id: str) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        user = await self.get_user(uid)
        current = user.raw.get("assignedLicenses") or [] if user else []
        body = {"addLicenses": [], "removeLicenses": [l.get("skuId") for l in current if l.get("skuId")]}
        await self.request("POST", self._g(f"users/{uid}/assignLicense"), json_body=body)
        return {"user_id": uid, "removed": len(body["removeLicenses"])}

    async def grant_role(self, role_id: str, user_id: str) -> dict[str, Any]:
        rid = await self.resolve_role_id(role_id)
        uid = await self._resolve_user_id(user_id)
        try:
            await self.request(
                "POST",
                self._g(f"directoryRoles/{rid}/members/$ref"),
                json_body={"@odata.id": self._g(f"users/{uid}")},
                expected=(204,),
            )
        except ConflictError:
            return {"role_id": rid, "user_id": uid, "already_member": True}
        return {"role_id": rid, "user_id": uid, "granted": True}

    async def revoke_role(self, role_id: str, user_id: str) -> dict[str, Any]:
        rid = await self.resolve_role_id(role_id)
        uid = await self._resolve_user_id(user_id)
        await self.request("DELETE", self._g(f"directoryRoles/{rid}/members/{uid}/$ref"), expected=(204,))
        return {"role_id": rid, "user_id": uid, "revoked": True}

    async def create_temporary_access_pass(
        self, user_id: str, *, lifetime_minutes: int = 480, one_time: bool = True
    ) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        body = {
            "startDateTime": datetime.now(timezone.utc).isoformat(),
            "lifetimeInMinutes": lifetime_minutes,
            "isUsableOnce": one_time,
        }
        raw = await self.request(
            "POST", self._g(f"users/{uid}/authentication/temporaryAccessPassMethods"), json_body=body,
            expected=(201,),
        )
        return {
            "user_id": uid,
            "temporaryAccessPass": (raw or {}).get("temporaryAccessPass", ""),
            "expires": (raw or {}).get("lifetimeInMinutes"),
            "one_time": one_time,
        }

    async def revoke_sign_in_sessions(self, user_id: str) -> dict[str, Any]:
        uid = await self._resolve_user_id(user_id)
        await self.request("POST", self._g(f"users/{uid}/revokeSignInSessions"), expected=(200,))
        return {"user_id": uid, "revoked": True}

    async def list_lifecycle_workflows(self) -> list[dict[str, Any]]:
        if not self.settings.enable_lifecycle_workflows:
            return []
        try:
            return await self._paged("identityGovernance/lifecycleWorkflows/workflows")
        except Exception:  # noqa: BLE001 - Governance may not be licensed
            return []

    async def run_lifecycle_workflow(self, workflow_id: str, user_ids: list[str]) -> dict[str, Any]:
        resolved = [await self._resolve_user_id(u) for u in user_ids]
        body = {"subjects": [{"id": uid} for uid in resolved]}
        await self.request(
            "POST",
            self._g(f"identityGovernance/lifecycleWorkflows/workflows/{workflow_id}/run"),
            json_body=body,
            expected=(202, 200),
        )
        return {"workflow_id": workflow_id, "users": resolved, "started": True}


# --------------------------------------------------------------------------- #
# Mock implementation
# --------------------------------------------------------------------------- #


class MockEntraConnector(EntraConnector):
    """In-memory Entra backed by the shared :class:`MockStore`."""

    def __init__(
        self,
        settings: EntraSettings,
        audit: AuditLog | None = None,
        store: MockStore | None = None,
    ) -> None:
        super().__init__(settings, audit)
        self.store = store or get_mock_store()

    async def authenticate(self) -> None:
        self._token = "mock-entra-token"
        import time as _time

        self._token_expires_at = _time.time() + 3600

    async def health(self) -> HealthStatus:
        return HealthStatus(
            self.name, True, "mock", f"simulated tenant with {len(self.store.users)} users"
        )

    # ---- helpers --------------------------------------------------------- #

    def _u(self, identifier: str) -> dict[str, Any]:
        user = self.store.find_user(oid=identifier) or self.store.find_user(email=identifier)
        if not user:
            user = self.store.find_user(username=identifier)
        if not user:
            raise NotFoundError(f"mock Entra: no user '{identifier}'", platform=self.name)
        return user

    def _opt_user(self, identifier: str) -> dict[str, Any] | None:
        try:
            return self._u(identifier)
        except NotFoundError:
            return None

    def _to_model(self, raw: dict[str, Any]) -> DirectoryUser:
        """Translate store (snake_case) records into Graph-shaped (camelCase) ones.

        Keeping the mapping here means ``_map_user`` has a single, faithful
        contract and the mock cannot silently diverge from live behaviour.
        """
        enriched = _store_to_graph(raw)
        enriched["memberOf"] = [
            {"id": gid, "displayName": g["display_name"]}
            for gid, g in self.store.groups.items()
            if raw["id"] in g["members"]
        ]
        enriched["licensePartNumbers"] = raw.get("licenses", [])
        return _map_user(enriched)

    # ---- reads ----------------------------------------------------------- #

    async def get_user(self, identifier: str) -> DirectoryUser | None:
        raw = self._opt_user(identifier)
        return self._to_model(raw) if raw else None

    async def list_users(self, *, only_enabled: bool | None = None, top: int = 999) -> list[DirectoryUser]:
        rows = list(self.store.users.values())
        if only_enabled is not None:
            rows = [r for r in rows if r["account_enabled"] == only_enabled]
        return [self._to_model(r) for r in rows[:top]]

    async def search_users(self, query: str) -> list[DirectoryUser]:
        q = query.lower()
        rows = [
            r
            for r in self.store.users.values()
            if q in r["display_name"].lower() or q in r["mail"].lower() or q in r.get("employee_id", "").lower()
        ]
        return [self._to_model(r) for r in rows]

    async def list_groups(self) -> list[DirectoryGroup]:
        return [_map_group(_store_group_to_graph(g)) for g in self.store.groups.values()]

    async def get_group(self, identifier: str) -> DirectoryGroup | None:
        gid = self.store.group_id_by_name(identifier) or (
            identifier if identifier in self.store.groups else None
        )
        return _map_group(_store_group_to_graph(self.store.groups[gid])) if gid else None

    async def get_user_groups(self, user_id: str) -> list[DirectoryGroup]:
        uid = self._u(user_id)["id"]
        return [
            _map_group(_store_group_to_graph(g))
            for g in self.store.groups.values()
            if uid in g["members"]
        ]

    async def get_user_manager(self, user_id: str) -> DirectoryUser | None:
        user = self._u(user_id)
        mid = user.get("manager_id")
        return self._to_model(self.store.users[mid]) if mid and mid in self.store.users else None

    async def list_directory_roles(self) -> list[dict[str, Any]]:
        return [
            {"id": r["id"], "displayName": r["display_name"], "members": r["members"]}
            for r in self.store.directory_roles.values()
        ]

    async def get_user_roles(self, user_id: str) -> list[dict[str, Any]]:
        uid = self._u(user_id)["id"]
        return [
            {"id": r["id"], "displayName": r["display_name"]}
            for r in self.store.directory_roles.values()
            if uid in r["members"]
        ]

    async def get_sign_in_activity(self, user_id: str) -> dict[str, Any]:
        user = self._u(user_id)
        return {"lastSignInDateTime": user.get("last_sign_in")}

    async def get_mfa_status(self, user_id: str) -> dict[str, Any]:
        user = self._u(user_id)
        return {
            "registered": bool(user.get("mfa_registered")),
            "methods": ["passwordAuthenticationMethod", "microsoftAuthenticatorAuthenticationMethod"]
            if user.get("mfa_registered")
            else ["passwordAuthenticationMethod"],
        }

    async def list_deleted_users(self) -> list[DirectoryUser]:
        return [self._to_model(u) for u in self.store.deleted_users.values()]

    async def get_default_domain(self) -> str:
        """Infer the domain from the simulated tenant, like a real tenant would report."""
        if self.settings.primary_domain:
            return self.settings.primary_domain
        counts: dict[str, int] = {}
        for user in self.store.users.values():
            mail = user.get("mail") or ""
            if "@" in mail:
                domain = mail.split("@", 1)[1].lower()
                counts[domain] = counts.get(domain, 0) + 1
        if not counts:
            return "contoso-balears.example"
        return max(counts.items(), key=lambda kv: kv[1])[0]

    # ---- writes ---------------------------------------------------------- #

    async def create_user(self, employee: Employee, *, password: str) -> DirectoryUser:
        existing = self._opt_user(employee.email or employee.suggested_upn(""))
        if existing:
            self.store.log_event("entra.create_user.idempotent", upn=existing["user_principal_name"])
            return self._to_model(existing)

        uid = str(uuid4_hex())
        domain = self.settings.primary_domain or (
            employee.email.split("@")[-1] if employee.email else "contoso-balears.example"
        )
        upn = employee.suggested_upn(domain)
        username = employee.suggested_username(domain)
        self.store.users[uid] = {
            "id": uid,
            "user_principal_name": upn,
            "mail": employee.email or upn,
            "mail_nickname": username,
            "display_name": employee.full_name,
            "given_name": employee.first_name,
            "surname": employee.last_name,
            "job_title": employee.job_title,
            "department": employee.department,
            "company_name": employee.company or "Contoso Balears",
            "office_location": employee.office_location,
            "country": employee.country or "ES",
            "employee_id": employee.employee_id,
            "employee_hire_date": employee.hire_date.isoformat() if employee.hire_date else None,
            "employee_leave_date_time": None,
            "account_enabled": True,
            "on_premises_sync_enabled": False,
            "on_premises_sam_account_name": username,
            "dn": f"CN={employee.full_name},OU={employee.department or 'Usuarios'},OU=Usuarios,DC=corp,DC=local",
            "password_last_set": datetime.now(timezone.utc).isoformat(),
            "last_sign_in": None,
            "mfa_registered": False,
            "licenses": list(employee.license_skus),
            "manager_id": employee.manager.entra_id if employee.manager else "",
            "source": "entra",
            "ad_attributes": {
                "sAMAccountName": username,
                "userPrincipalName": upn,
                "title": employee.job_title,
                "department": employee.department,
                "memberOf": [],
                "userAccountControl": 512,
            },
            "_provisional_password": password,
        }
        self.store.log_event("entra.create_user", upn=upn)
        return self._to_model(self.store.users[uid])

    async def update_user(self, user_id: str, attributes: dict[str, Any]) -> DirectoryUser:
        user = self._u(user_id)
        field_map = {
            "jobTitle": "job_title",
            "department": "department",
            "companyName": "company_name",
            "officeLocation": "office_location",
            "country": "country",
            "mobilePhone": "mobile_phone",
            "employeeId": "employee_id",
            "employeeType": "employee_type",
            "employeeHireDate": "employee_hire_date",
            "employeeLeaveDateTime": "employee_leave_date_time",
            "displayName": "display_name",
            "givenName": "given_name",
            "surname": "surname",
            "accountEnabled": "account_enabled",
            "mailNickname": "mail_nickname",
        }
        for key, value in attributes.items():
            target = field_map.get(key, key)
            user[target] = value
            if target in ("job_title", "department") and "ad_attributes" in user:
                user["ad_attributes"]["title"] = user.get("job_title", "")
                user["ad_attributes"]["department"] = user.get("department", "")
        self.store.log_event("entra.update_user", id=user["id"], fields=list(attributes))
        return self._to_model(user)

    async def disable_user(self, user_id: str, *, reason: str = "") -> DirectoryUser:
        user = self._u(user_id)
        user["account_enabled"] = False
        user["description"] = f"disabled by iam-agent: {reason}"
        if "ad_attributes" in user:
            user["ad_attributes"]["userAccountControl"] = 514
        self.store.log_event("entra.disable_user", id=user["id"], reason=reason)
        return self._to_model(user)

    async def enable_user(self, user_id: str) -> DirectoryUser:
        user = self._u(user_id)
        user["account_enabled"] = True
        if "ad_attributes" in user:
            user["ad_attributes"]["userAccountControl"] = 512
        self.store.log_event("entra.enable_user", id=user["id"])
        return self._to_model(user)

    async def delete_user(self, user_id: str) -> dict[str, Any]:
        user = self._u(user_id)
        uid = user["id"]
        self.store.deleted_users[uid] = self.store.users.pop(uid)
        self.store.mailboxes.pop(uid, None)
        for group in self.store.groups.values():
            group["members"] = [m for m in group["members"] if m != uid]
        for team in self.store.teams.values():
            team["members"] = [m for m in team["members"] if m != uid]
        for role in self.store.directory_roles.values():
            role["members"] = [m for m in role["members"] if m != uid]
        self.store.log_event("entra.delete_user", id=uid)
        return {"deleted": True, "id": uid}

    async def set_manager(self, user_id: str, manager_id: str) -> dict[str, Any]:
        user = self._u(user_id)
        manager = self._u(manager_id)
        user["manager_id"] = manager["id"]
        self.store.log_event("entra.set_manager", id=user["id"], manager=manager["id"])
        return {"user_id": user["id"], "manager_id": manager["id"]}

    async def add_group_member(self, group_id: str, user_id: str) -> dict[str, Any]:
        gid = self.store.group_id_by_name(group_id) or (
            group_id if group_id in self.store.groups else None
        )
        if not gid:
            raise NotFoundError(f"mock Entra: no group '{group_id}'", platform=self.name)
        uid = self._u(user_id)["id"]
        if uid not in self.store.groups[gid]["members"]:
            self.store.groups[gid]["members"].append(uid)
            self.store.log_event("entra.add_group_member", group=gid, user=uid)
            return {"group_id": gid, "user_id": uid, "added": True}
        return {"group_id": gid, "user_id": uid, "already_member": True}

    async def remove_group_member(self, group_id: str, user_id: str) -> dict[str, Any]:
        gid = self.store.group_id_by_name(group_id) or group_id
        uid = self._u(user_id)["id"]
        group = self.store.groups.get(gid)
        if not group:
            raise NotFoundError(f"mock Entra: no group '{group_id}'", platform=self.name)
        group["members"] = [m for m in group["members"] if m != uid]
        self.store.log_event("entra.remove_group_member", group=gid, user=uid)
        return {"group_id": gid, "user_id": uid, "removed": True}

    async def remove_all_group_memberships(self, user_id: str) -> dict[str, Any]:
        uid = self._u(user_id)["id"]
        removed, skipped = [], []
        for gid, group in self.store.groups.items():
            if uid in group["members"]:
                if group.get("membership_rule"):
                    skipped.append({"id": gid, "reason": "dynamic group"})
                    continue
                group["members"] = [m for m in group["members"] if m != uid]
                removed.append(group["display_name"])
        for team in self.store.teams.values():
            team["members"] = [m for m in team["members"] if m != uid]
        self.store.log_event("entra.remove_all_group_memberships", id=uid, removed=removed)
        return {"user_id": uid, "removed_from": removed, "skipped": skipped}

    async def assign_license(self, user_id: str, sku_part_numbers: list[str]) -> dict[str, Any]:
        user = self._u(user_id)
        current = set(user.get("licenses", []))
        current.update(sku_part_numbers)
        user["licenses"] = sorted(current)
        for sku in sku_part_numbers:
            entry = self.store.license_skus.get(sku)
            if entry:
                entry["consumed"] += 1
        self.store.log_event("entra.assign_license", id=user["id"], skus=sku_part_numbers)
        return {"user_id": user["id"], "assigned": sku_part_numbers}

    async def remove_all_licenses(self, user_id: str) -> dict[str, Any]:
        user = self._u(user_id)
        removed = list(user.get("licenses", []))
        for sku in removed:
            entry = self.store.license_skus.get(sku)
            if entry:
                entry["consumed"] = max(0, entry["consumed"] - 1)
        user["licenses"] = []
        self.store.log_event("entra.remove_all_licenses", id=user["id"], count=len(removed))
        return {"user_id": user["id"], "removed": len(removed), "skus": removed}

    async def grant_role(self, role_id: str, user_id: str) -> dict[str, Any]:
        uid = self._u(user_id)["id"]
        rid = None
        for candidate_id, role in self.store.directory_roles.items():
            if candidate_id == role_id or role["display_name"].lower() == role_id.lower():
                rid = candidate_id
                break
        if not rid:
            raise NotFoundError(f"mock Entra: no directory role '{role_id}'", platform=self.name)
        if uid not in self.store.directory_roles[rid]["members"]:
            self.store.directory_roles[rid]["members"].append(uid)
        self.store.log_event("entra.grant_role", role=rid, user=uid)
        return {"role_id": rid, "user_id": uid, "granted": True}

    async def revoke_role(self, role_id: str, user_id: str) -> dict[str, Any]:
        uid = self._u(user_id)["id"]
        rid = None
        for candidate_id, role in self.store.directory_roles.items():
            if candidate_id == role_id or role["display_name"].lower() == role_id.lower():
                rid = candidate_id
                break
        if not rid:
            raise NotFoundError(f"mock Entra: no directory role '{role_id}'", platform=self.name)
        self.store.directory_roles[rid]["members"] = [
            m for m in self.store.directory_roles[rid]["members"] if m != uid
        ]
        self.store.log_event("entra.revoke_role", role=rid, user=uid)
        return {"role_id": rid, "user_id": uid, "revoked": True}

    async def create_temporary_access_pass(
        self, user_id: str, *, lifetime_minutes: int = 480, one_time: bool = True
    ) -> dict[str, Any]:
        user = self._u(user_id)
        tap = "".join(str(random_digit()) for _ in range(9))
        tap = f"{tap[:3]}-{tap[3:6]}-{tap[6:]}"
        self.store.log_event("entra.create_tap", id=user["id"])
        return {
            "user_id": user["id"],
            "temporaryAccessPass": tap,
            "lifetime_minutes": lifetime_minutes,
            "one_time": one_time,
            "note": "SIMULATED TAP - not usable for real sign-in",
        }

    async def revoke_sign_in_sessions(self, user_id: str) -> dict[str, Any]:
        user = self._u(user_id)
        self.store.log_event("entra.revoke_sign_in_sessions", id=user["id"])
        return {"user_id": user["id"], "revoked": True}

    async def list_lifecycle_workflows(self) -> list[dict[str, Any]]:
        return list(self.store.lifecycle_workflows.values())

    async def run_lifecycle_workflow(self, workflow_id: str, user_ids: list[str]) -> dict[str, Any]:
        resolved = [self._u(u)["id"] for u in user_ids]
        self.store.workflow_runs.append(
            {"workflow_id": workflow_id, "users": resolved, "at": datetime.now(timezone.utc).isoformat()}
        )
        return {"workflow_id": workflow_id, "users": resolved, "started": True, "simulated": True}


def uuid4_hex() -> str:
    import uuid

    return uuid.uuid4()


def random_digit() -> int:
    import random

    return random.randint(0, 9)


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #


def build_entra_connector(
    settings: EntraSettings, audit: AuditLog | None = None, store: MockStore | None = None
) -> EntraConnector:
    if settings.enabled and settings.backend == "live":
        return LiveEntraConnector(settings, audit)
    return MockEntraConnector(settings, audit, store)
