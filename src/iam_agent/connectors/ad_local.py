"""On-premises Active Directory Domain Services connector (LDAP/LDAPS).

``ldap3`` is synchronous, so every call is dispatched with :func:`asyncio.to_thread`
to keep the agent's event loop responsive while it talks to domain controllers.

Important operational notes
---------------------------
* **Use LDAPS (port 636).** Password writes require it: AD only accepts
  ``unicodePwd`` over an encrypted channel.
* The bind account needs *write* rights on the target OUs and membership of
  ``Account Operators`` (or a delegated custom role). Never bind as Domain Admin.
* **Never delete by default.** ``allow_hard_delete`` is off; the offboarding
  playbook disables the account and moves it to the leaver OU instead.
* If Entra Connect syncs this domain, most attributes are authoritative on-prem
  and changes made in Entra will be reverted on the next sync cycle. The
  connector detects ``onPremisesSyncEnabled`` and warns about it.
"""

from __future__ import annotations

import abc
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from iam_agent.config import ActiveDirectorySettings
from iam_agent.connectors.base import BaseConnector, HealthStatus, NotConfiguredError
from iam_agent.connectors.mock.store import MockStore, get_mock_store
from iam_agent.core.audit import AuditLog
from iam_agent.core.errors import (
    AuthorizationError,
    ConfigurationError,
    ConnectorError,
    NotFoundError,
)
from iam_agent.core.models import DirectoryGroup, DirectoryUser, Employee

OP = "active_directory"
OPS = {
    "get_user": f"{OP}.get_user",
    "list_users": f"{OP}.list_users",
    "search_users": f"{OP}.search_users",
    "create_user": f"{OP}.create_user",
    "update_user": f"{OP}.update_user",
    "disable_user": f"{OP}.disable_user",
    "enable_user": f"{OP}.enable_user",
    "delete_user": f"{OP}.delete_user",
    "move_user": f"{OP}.move_user",
    "set_password": f"{OP}.set_password",
    "expire_password": f"{OP}.expire_password",
    "set_account_expiry": f"{OP}.set_account_expiry",
    "add_group_member": f"{OP}.add_group_member",
    "remove_group_member": f"{OP}.remove_group_member",
    "get_user_groups": f"{OP}.get_user_groups",
    "list_groups": f"{OP}.list_groups",
    "unlock_user": f"{OP}.unlock_user",
}

# userAccountControl bit flags
UAC_SCRIPT = 0x0001
UAC_ACCOUNTDISABLE = 0x0002
UAC_HOMEDIR_REQUIRED = 0x0008
UAC_LOCKOUT = 0x0010
UAC_PASSWD_NOTREQD = 0x0020
UAC_NORMAL_ACCOUNT = 0x0200
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_PASSWORD_EXPIRED = 0x800000

DEFAULT_UAC_ENABLED = UAC_NORMAL_ACCOUNT  # 512
DEFAULT_UAC_DISABLED = UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE  # 514

# Attributes pulled on every read - keep this tight, AD searches are expensive.
_USER_ATTRS = [
    "objectGUID",
    "distinguishedName",
    "sAMAccountName",
    "userPrincipalName",
    "cn",
    "givenName",
    "sn",
    "displayName",
    "mail",
    "title",
    "department",
    "company",
    "manager",
    "memberOf",
    "userAccountControl",
    "pwdLastSet",
    "accountExpires",
    "lastLogonTimestamp",
    "employeeID",
    "description",
    "physicalDeliveryOfficeName",
    "telephoneNumber",
    "mobile",
    "whenCreated",
    "whenChanged",
    "objectClass",
]

# Windows FILETIME epoch: 1601-01-01, in 100ns ticks.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_dt(value: Any) -> datetime | None:
    """Convert an AD FILETIME (100ns since 1601) to a timezone-aware datetime."""
    try:
        ticks = int(str(value))
    except (TypeError, ValueError):
        return None
    if ticks in (0, 9223372036854775807, -1):
        # 0 = never, max-int64 = never expires
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)


def datetime_to_filetime(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return int((value - _FILETIME_EPOCH).total_seconds() * 10_000_000)


def uac_is_enabled(uac: Any) -> bool:
    try:
        return not (int(uac) & UAC_ACCOUNTDISABLE)
    except (TypeError, ValueError):
        return True


def uac_is_locked(uac: Any) -> bool:
    try:
        return bool(int(uac) & UAC_LOCKOUT)
    except (TypeError, ValueError):
        return False


def _first(value: Any) -> str:
    """AD attributes come back as lists; take the first element safely."""
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return "" if value is None else str(value)


def _guid_bytes_to_str(value: Any) -> str:
    if isinstance(value, bytes) and len(value) == 16:
        import uuid

        return str(uuid.UUID(bytes_le=value))
    return _first(value)


def _map_ad_user(entry: dict[str, Any]) -> DirectoryUser:
    uac = _first(entry.get("userAccountControl"))
    pwd_last_set = filetime_to_datetime(entry.get("pwdLastSet"))
    last_logon = filetime_to_datetime(entry.get("lastLogonTimestamp"))
    return DirectoryUser(
        platform="active_directory",
        external_id=_guid_bytes_to_str(entry.get("objectGUID")) or _first(entry.get("distinguishedName")),
        username=_first(entry.get("sAMAccountName")),
        upn=_first(entry.get("userPrincipalName")),
        email=_first(entry.get("mail")).lower(),
        display_name=_first(entry.get("displayName")) or _first(entry.get("cn")),
        first_name=_first(entry.get("givenName")),
        last_name=_first(entry.get("sn")),
        job_title=_first(entry.get("title")),
        department=_first(entry.get("department")),
        company=_first(entry.get("company")),
        manager_id=_first(entry.get("manager")),
        dn=_first(entry.get("distinguishedName")),
        enabled=uac_is_enabled(uac),
        license_skus=[],
        group_ids=list(entry.get("memberOf") or []),
        employee_id=_first(entry.get("employeeID")),
        on_premises_sync=True,
        last_sign_in=last_logon,
        account_expires=filetime_to_datetime(entry.get("accountExpires")),
        raw={
            **{k: _first(v) if not isinstance(v, list) else v for k, v in entry.items()},
            "userAccountControl": uac,
            "locked": uac_is_locked(uac),
            "passwordLastSet": pwd_last_set.isoformat() if pwd_last_set else None,
            "passwordExpired": pwd_last_set is None,
        },
    )


class ADConnector(BaseConnector, abc.ABC):
    """Interface for on-premises Active Directory."""

    name = "active_directory"
    label = "On-prem Active Directory"

    def __init__(self, settings: ActiveDirectorySettings, audit: AuditLog | None = None) -> None:
        super().__init__(backend=settings.backend, audit=audit, timeout=float(settings.receive_timeout))
        self.settings = settings

    # ---- reads ----------------------------------------------------------- #
    @abc.abstractmethod
    async def get_user(self, identifier: str) -> DirectoryUser | None: ...
    @abc.abstractmethod
    async def list_users(self, *, ou: str = "", only_enabled: bool | None = None) -> list[DirectoryUser]: ...
    @abc.abstractmethod
    async def search_users(self, query: str) -> list[DirectoryUser]: ...
    @abc.abstractmethod
    async def list_groups(self, *, ou: str = "") -> list[DirectoryGroup]: ...
    @abc.abstractmethod
    async def get_user_groups(self, identifier: str) -> list[DirectoryGroup]: ...

    # ---- writes ---------------------------------------------------------- #
    @abc.abstractmethod
    async def create_user(self, employee: Employee, *, password: str, ou: str = "") -> DirectoryUser: ...
    @abc.abstractmethod
    async def update_user(self, identifier: str, attributes: dict[str, Any]) -> DirectoryUser: ...
    @abc.abstractmethod
    async def disable_user(self, identifier: str, *, reason: str = "") -> DirectoryUser: ...
    @abc.abstractmethod
    async def enable_user(self, identifier: str) -> DirectoryUser: ...
    @abc.abstractmethod
    async def delete_user(self, identifier: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def move_user(self, identifier: str, target_ou: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def set_password(self, identifier: str, password: str, *, must_change: bool = True) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def expire_password(self, identifier: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def set_account_expiry(self, identifier: str, expires_at: datetime | None) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def add_group_member(self, group_dn: str, member_dn: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def remove_group_member(self, group_dn: str, member_dn: str) -> dict[str, Any]: ...
    @abc.abstractmethod
    async def unlock_user(self, identifier: str) -> dict[str, Any]: ...

    # ---- convenience ----------------------------------------------------- #
    @property
    def users_container(self) -> str:
        return self.settings.users_ou or self.settings.base_dn

    @property
    def disabled_container(self) -> str:
        return self.settings.disabled_ou or self.settings.users_ou or self.settings.base_dn

    def build_dn(self, employee: Employee) -> str:
        container = self.users_container
        dept = (employee.department or "").strip()
        cn = employee.full_name
        if dept and container:
            return f"CN={cn},OU={dept},{container}"
        return f"CN={cn},{container}"


# --------------------------------------------------------------------------- #
# Live implementation (ldap3)
# --------------------------------------------------------------------------- #


class LiveADConnector(ADConnector):
    """Real LDAPS connector against domain controllers."""

    def __init__(self, settings: ActiveDirectorySettings, audit: AuditLog | None = None) -> None:
        super().__init__(settings, audit)
        self._server = None
        self._conn = None

    # ---- connection ------------------------------------------------------ #

    def _require_config(self) -> None:
        if not self.settings.servers:
            raise NotConfiguredError(
                "IAM_AD_SERVERS is empty. Provide one or more domain controllers.", platform=self.name
            )
        if not self.settings.base_dn:
            raise NotConfiguredError("IAM_AD_BASE_DN is required (e.g. DC=corp,DC=local).", platform=self.name)
        if not (self.settings.bind_user and self.settings.bind_password):
            raise NotConfiguredError(
                "IAM_AD_BIND_USER / IAM_AD_BIND_PASSWORD are required.", platform=self.name
            )

    def _sync_connect(self):
        import ssl

        from ldap3 import ALL, Connection, Server, Tls

        self._require_config()

        tls = None
        if self.settings.use_ssl:
            tls = Tls(
                validate=ssl.CERT_REQUIRED if self.settings.tls_validate else ssl.CERT_NONE,
                ca_certs_file=self.settings.ca_certs_file,
            )

        servers = [
            Server(
                host,
                port=self.settings.port,
                use_ssl=self.settings.use_ssl,
                get_info=ALL if self.settings.get_info else None,
                tls=tls,
                connect_timeout=self.settings.connect_timeout,
            )
            for host in self.settings.servers
        ]
        conn = Connection(
            servers if len(servers) > 1 else servers[0],
            user=self.settings.bind_user,
            password=self.settings.bind_password,
            auto_bind=True,
            receive_timeout=self.settings.receive_timeout,
            raise_exceptions=True,
        )
        self._server = servers[0]
        self._conn = conn
        return conn

    async def authenticate(self) -> None:
        if self._conn is not None and self._conn.bound:
            return
        self._conn = await asyncio.to_thread(self._sync_connect)
        self._token = "ldap-session"
        self._token_expires_at = datetime.now(timezone.utc).timestamp() + 300

    async def health(self) -> HealthStatus:
        import time as _time

        started = _time.monotonic()
        try:
            conn = await self._run(lambda: self._ensure_conn())
            root_dse = conn.server.info.other if conn.server.info else {}
            return HealthStatus(
                self.name, True, "live",
                f"bound to {conn.server.host}:{conn.server.port}; "
                f"{root_dse.get('dnsHostName', 'domain')} | TLS={conn.server.ssl}",
                (_time.monotonic() - started) * 1000,
            )
        except Exception as exc:  # noqa: BLE001
            return HealthStatus(
                self.name, False, "live", f"{type(exc).__name__}: {exc}",
                (_time.monotonic() - started) * 1000,
            )

    def _ensure_conn(self):
        if self._conn is None or not self._conn.bound:
            return self._sync_connect()
        return self._conn

    async def _run(self, fn, *args: Any, **kwargs: Any) -> Any:
        """Execute a blocking ldap3 operation off the event loop."""
        await self.ensure_authenticated()

        def _call():
            conn = self._ensure_conn()
            return fn(conn, *args, **kwargs) if args or kwargs else fn(conn)

        try:
            return await asyncio.to_thread(_call)
        except Exception as exc:  # noqa: BLE001 - normalise ldap3 exceptions
            raise self._normalise(exc) from exc

    def _normalise(self, exc: Exception) -> ConnectorError:
        text = str(exc)
        lowered = text.lower()
        if "invalidcredentials" in lowered or "49" in text and "data 52e" in lowered:
            return AuthorizationError(f"AD bind failed: {text}", platform=self.name)
        if "data 530" in lowered:
            return AuthorizationError("AD refused the bind: insufficient rights", platform=self.name)
        if "data 525" in lowered or "not found" in lowered:
            return NotFoundError(f"AD object not found: {text}", platform=self.name)
        if "constraint" in lowered or "already exists" in lowered:
            from iam_agent.core.errors import ConflictError

            return ConflictError(f"AD constraint violation: {text}", platform=self.name)
        return ConnectorError(f"AD operation failed: {text}", platform=self.name)

    # ---- search plumbing -------------------------------------------------- #

    @staticmethod
    def _filter_escape(value: str) -> str:
        """RFC 4515 escaping - never build LDAP filters from raw input."""
        out = []
        for ch in value:
            code = ord(ch)
            if ch in "\\*()\0":
                out.append(f"\\{code:02x}")
            elif code < 128:
                out.append(ch)
            else:
                out.append("".join(f"\\{b:02x}" for b in ch.encode("utf-8")))
        return "".join(out)

    async def _search(self, search_filter: str, *, base: str = "", attributes: list[str] | None = None) -> list[dict]:
        base_dn = base or self.settings.base_dn

        def _do(conn) -> list[dict]:
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope="SUBTREE",
                attributes=attributes or _USER_ATTRS,
                paged_size=500,
            )
            return [dict(e.attributes) | {"dn": e.entry_dn} for e in conn.entries]

        return await self._run(_do)

    def _identifier_filter(self, identifier: str) -> str:
        esc = self._filter_escape(identifier)
        if identifier.startswith("CN=") or identifier.startswith("OU=") or identifier.startswith("DC="):
            return f"(distinguishedName={esc})"
        return (
            f"(|(sAMAccountName={esc})(userPrincipalName={esc})(mail={esc})"
            f"(objectGUID={esc})(employeeID={esc}))"
        )

    # ---- reads ----------------------------------------------------------- #

    async def get_user(self, identifier: str) -> DirectoryUser | None:
        results = await self._search(f"(&(objectClass=user)(objectCategory=person){self._identifier_filter(identifier)[1:-1]})")
        if not results:
            # Allow the filter to be a full OR group already
            results = await self._search(f"(&(objectClass=user)(objectCategory=person){self._identifier_filter(identifier)})")
        if not results:
            return None
        return _map_ad_user(results[0])

    async def list_users(self, *, ou: str = "", only_enabled: bool | None = None) -> list[DirectoryUser]:
        parts = ["(objectClass=user)", "(objectCategory=person)"]
        if only_enabled is True:
            parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
        elif only_enabled is False:
            parts.append("(userAccountControl:1.2.840.113556.1.4.803:=2)")
        filt = "(&" + "".join(parts) + ")"
        rows = await self._search(filt, base=ou or self.settings.base_dn)
        return [_map_ad_user(r) for r in rows]

    async def search_users(self, query: str) -> list[DirectoryUser]:
        esc = self._filter_escape(query)
        filt = (
            f"(&(objectClass=user)(objectCategory=person)"
            f"(|(displayName=*{esc}*)(sAMAccountName=*{esc}*)(mail=*{esc}*)))"
        )
        return [_map_ad_user(r) for r in await self._search(filt)]

    async def list_groups(self, *, ou: str = "") -> list[DirectoryGroup]:
        rows = await self._search(
            "(objectClass=group)",
            base=ou or self.settings.groups_ou or self.settings.base_dn,
            attributes=["objectGUID", "distinguishedName", "cn", "description", "mail", "groupType", "member"],
        )
        return [
            DirectoryGroup(
                platform="active_directory",
                external_id=_guid_bytes_to_str(r.get("objectGUID")) or _first(r.get("distinguishedName")),
                display_name=_first(r.get("cn")),
                description=_first(r.get("description")),
                mail=_first(r.get("mail")).lower(),
                security_enabled=True,
                dn=_first(r.get("distinguishedName")),
                member_count=len(r.get("member") or []),
                raw={k: _first(v) if not isinstance(v, list) else v for k, v in r.items()},
            )
            for r in rows
        ]

    async def get_user_groups(self, identifier: str) -> list[DirectoryGroup]:
        user = await self.get_user(identifier)
        if not user:
            return []
        member_of = user.raw.get("memberOf") or []
        if isinstance(member_of, str):
            member_of = [member_of]
        return [
            DirectoryGroup(
                platform="active_directory",
                external_id=dn,
                display_name=dn.split(",", 1)[0].replace("CN=", ""),
                dn=dn,
            )
            for dn in member_of
        ]

    # ---- writes ---------------------------------------------------------- #

    async def create_user(self, employee: Employee, *, password: str, ou: str = "") -> DirectoryUser:
        dn = self.build_dn(employee)
        cn = employee.full_name
        username = employee.suggested_username()
        upn = employee.suggested_upn(self.settings.upn_suffix)
        container = ou or self.users_container

        attributes = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "sAMAccountName": username,
            "userPrincipalName": upn,
            "givenName": employee.first_name,
            "sn": employee.last_name,
            "displayName": cn,
            "name": cn,
            "mail": employee.email or upn,
            "title": employee.job_title,
            "department": employee.department,
            "company": employee.company,
            "physicalDeliveryOfficeName": employee.office_location,
            "mobile": employee.mobile_phone,
            "telephoneNumber": employee.office_phone,
            "employeeID": employee.employee_id,
            "description": f"Created by IAM Agent on {datetime.now(timezone.utc).date()}",
            # Created disabled; enabled only after the password is set.
            "userAccountControl": DEFAULT_UAC_DISABLED,
        }
        attributes = {k: v for k, v in attributes.items() if v not in ("", None)}

        def _do(conn) -> str:
            conn.add(dn, attributes=attributes)
            if not conn.result.get("result", 0) == 0 and conn.result.get("result") != 68:
                raise ConnectorError(f"AD add failed: {conn.result}", platform=self.name)
            return dn

        try:
            await self._run(_do)
        except ConnectorError as exc:
            if "already exists" in str(exc).lower() or "68" in str(exc.details):
                existing = await self.get_user(username)
                if existing:
                    return existing
            raise

        await self.set_password(dn, password, must_change=True)
        await self.enable_user(dn)
        return await self.get_user(dn) or DirectoryUser(platform="active_directory", external_id=dn, dn=dn)

    async def update_user(self, identifier: str, attributes: dict[str, Any]) -> DirectoryUser:
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)
        dn = user.dn
        clean = {k: v for k, v in attributes.items() if v is not None}
        if not clean:
            return user

        def _do(conn) -> None:
            conn.modify(dn, {k: [("MODIFY_REPLACE", [v] if not isinstance(v, list) else v)] for k, v in clean.items()})
            if conn.result.get("result") not in (0, None):
                raise ConnectorError(f"AD modify failed: {conn.result}", platform=self.name)

        await self._run(_do)
        return await self.get_user(dn) or user

    async def _set_uac(self, identifier: str, uac: int) -> DirectoryUser:
        return await self.update_user(identifier, {"userAccountControl": str(uac)})

    async def disable_user(self, identifier: str, *, reason: str = "") -> DirectoryUser:
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)
        uac = int(user.raw.get("userAccountControl") or DEFAULT_UAC_ENABLED)
        attrs: dict[str, Any] = {"userAccountControl": str(uac | UAC_ACCOUNTDISABLE)}
        if reason:
            attrs["description"] = f"[iam-agent] {reason}"[:1024]
        updated = await self.update_user(user.dn, attrs)

        # Move to the leaver OU when one is configured.
        if self.settings.disabled_ou:
            try:
                await self.move_user(user.dn, self.settings.disabled_ou)
            except ConnectorError:
                pass  # a failed move must not fail the disable
        return updated

    async def enable_user(self, identifier: str) -> DirectoryUser:
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)
        uac = int(user.raw.get("userAccountControl") or DEFAULT_UAC_DISABLED)
        return await self._set_uac(user.dn, uac & ~UAC_ACCOUNTDISABLE)

    async def delete_user(self, identifier: str) -> dict[str, Any]:
        if not self.settings.allow_hard_delete:
            raise AuthorizationError(
                "Hard delete is disabled by policy (IAM_AD_ALLOW_HARD_DELETE=false). "
                "Disable the account and move it to the leaver OU instead.",
                platform=self.name,
            )
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)

        def _do(conn) -> None:
            conn.delete(user.dn)
            if conn.result.get("result") not in (0, None):
                raise ConnectorError(f"AD delete failed: {conn.result}", platform=self.name)

        await self._run(_do)
        return {"deleted": True, "dn": user.dn}

    async def move_user(self, identifier: str, target_ou: str) -> dict[str, Any]:
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)
        new_rdn = user.dn.split(",", 1)[0]

        def _do(conn) -> None:
            conn.modify_dn(user.dn, new_rdn, new_superior=target_ou)
            if conn.result.get("result") not in (0, None):
                raise ConnectorError(f"AD move failed: {conn.result}", platform=self.name)

        await self._run(_do)
        return {"moved": True, "from": user.dn, "to": f"{new_rdn},{target_ou}"}

    async def set_password(self, identifier: str, password: str, *, must_change: bool = True) -> dict[str, Any]:
        if not self.settings.use_ssl:
            raise ConfigurationError(
                "Password changes require LDAPS. Set IAM_AD_USE_SSL=true and IAM_AD_PORT=636.",
                platform=self.name,
            )
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)

        # AD wants the password quoted and UTF-16LE encoded.
        encoded = f'"{password}"'.encode("utf-16-le")

        def _do(conn) -> None:
            conn.modify(user.dn, {"unicodePwd": [("MODIFY_REPLACE", [encoded])]})
            if conn.result.get("result") not in (0, None):
                raise ConnectorError(f"AD password set failed: {conn.result}", platform=self.name)
            if must_change:
                conn.modify(user.dn, {"pwdLastSet": [("MODIFY_REPLACE", ["0"])]})

        await self._run(_do)
        return {"dn": user.dn, "password_set": True, "must_change_at_logon": must_change}

    async def expire_password(self, identifier: str) -> dict[str, Any]:
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)

        def _do(conn) -> None:
            conn.modify(user.dn, {"pwdLastSet": [("MODIFY_REPLACE", ["0"])]})

        await self._run(_do)
        return {"dn": user.dn, "password_expired": True}

    async def set_account_expiry(self, identifier: str, expires_at: datetime | None) -> dict[str, Any]:
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)
        value = "0" if expires_at is None else str(datetime_to_filetime(expires_at))

        def _do(conn) -> None:
            conn.modify(user.dn, {"accountExpires": [("MODIFY_REPLACE", [value])]})

        await self._run(_do)
        return {
            "dn": user.dn,
            "account_expires": expires_at.isoformat() if expires_at else "never",
        }

    async def _resolve_group_dn(self, group: str) -> str:
        if group.startswith("CN=") or "," in group:
            return group
        rows = await self._search(
            f"(&(objectClass=group)(|(cn={self._filter_escape(group)})(sAMAccountName={self._filter_escape(group)})))",
            attributes=["distinguishedName", "cn"],
        )
        if not rows:
            raise NotFoundError(f"AD group '{group}' not found", platform=self.name)
        return _first(rows[0].get("distinguishedName"))

    async def add_group_member(self, group_dn: str, member_dn: str) -> dict[str, Any]:
        gdn = await self._resolve_group_dn(group_dn)
        user = await self.get_user(member_dn)
        mdn = user.dn if user else member_dn

        def _do(conn) -> None:
            conn.modify(gdn, {"member": [("MODIFY_ADD", [mdn])]})
            if conn.result.get("result") not in (0, 53):  # 53 = already a member
                raise ConnectorError(f"AD group add failed: {conn.result}", platform=self.name)

        await self._run(_do)
        return {"group": gdn, "member": mdn, "added": True}

    async def remove_group_member(self, group_dn: str, member_dn: str) -> dict[str, Any]:
        gdn = await self._resolve_group_dn(group_dn)
        user = await self.get_user(member_dn)
        mdn = user.dn if user else member_dn

        def _do(conn) -> None:
            conn.modify(gdn, {"member": [("MODIFY_DELETE", [mdn])]})

        await self._run(_do)
        return {"group": gdn, "member": mdn, "removed": True}

    async def unlock_user(self, identifier: str) -> dict[str, Any]:
        user = await self.get_user(identifier)
        if not user:
            raise NotFoundError(f"AD user '{identifier}' not found", platform=self.name)

        def _do(conn) -> None:
            conn.extend.microsoft.unlock_account(user.dn)

        await self._run(_do)
        return {"dn": user.dn, "unlocked": True}


# --------------------------------------------------------------------------- #
# Mock implementation
# --------------------------------------------------------------------------- #


class MockADConnector(ADConnector):
    """Simulates a domain by mirroring the Entra users that are sync-enabled."""

    def __init__(
        self, settings: ActiveDirectorySettings, audit: AuditLog | None = None, store: MockStore | None = None
    ) -> None:
        super().__init__(settings, audit)
        self.store = store or get_mock_store()
        self.base_dn = settings.base_dn or "DC=corp,DC=local"

    async def authenticate(self) -> None:
        self._token = "mock-ldap-session"
        self._token_expires_at = datetime.now(timezone.utc).timestamp() + 300

    async def health(self) -> HealthStatus:
        count = sum(1 for u in self.store.users.values() if u.get("on_premises_sync_enabled"))
        return HealthStatus(
            self.name, True, "mock", f"simulated domain {self.base_dn} with {count} synced accounts"
        )

    # The mock AD view is the same objects as Entra with on_premises_sync_enabled,
    # plus locally-managed-only accounts. This makes sync drift observable.
    def _ad_users(self) -> dict[str, dict[str, Any]]:
        return {
            uid: u
            for uid, u in self.store.users.items()
            if u.get("on_premises_sync_enabled") or u.get("source") == "ad"
        }

    def _find(self, identifier: str) -> dict[str, Any] | None:
        for u in self._ad_users().values():
            if (
                u["id"] == identifier
                or u.get("dn", "").lower() == identifier.lower()
                or u.get("on_premises_sam_account_name", "").lower() == identifier.lower()
                or u.get("mail", "").lower() == identifier.lower()
                or u.get("user_principal_name", "").lower() == identifier.lower()
                or u.get("employee_id", "") == identifier
            ):
                return u
        return None

    def _to_model(self, raw: dict[str, Any]) -> DirectoryUser:
        attrs = raw.get("ad_attributes", {})
        return DirectoryUser(
            platform="active_directory",
            external_id=raw["id"],
            username=attrs.get("sAMAccountName", raw.get("mail_nickname", "")),
            upn=attrs.get("userPrincipalName", raw.get("user_principal_name", "")),
            email=raw.get("mail", "").lower(),
            display_name=raw.get("display_name", ""),
            first_name=raw.get("given_name", ""),
            last_name=raw.get("surname", ""),
            job_title=attrs.get("title", raw.get("job_title", "")),
            department=attrs.get("department", raw.get("department", "")),
            company=raw.get("company_name", ""),
            manager_id=raw.get("manager_id", ""),
            dn=raw.get("dn", ""),
            enabled=bool(raw.get("account_enabled", True)),
            license_skus=[],
            group_ids=list(attrs.get("memberOf", [])),
            employee_id=raw.get("employee_id", ""),
            on_premises_sync=True,
            last_sign_in=None,
            raw={
                "dn": raw.get("dn", ""),
                "userAccountControl": str(attrs.get("userAccountControl", 512)),
                "locked": False,
                "memberOf": attrs.get("memberOf", []),
                "passwordLastSet": raw.get("password_last_set"),
                "accountExpires": raw.get("account_expires"),
            },
        )

    async def get_user(self, identifier: str) -> DirectoryUser | None:
        raw = self._find(identifier)
        return self._to_model(raw) if raw else None

    async def list_users(self, *, ou: str = "", only_enabled: bool | None = None) -> list[DirectoryUser]:
        rows = list(self._ad_users().values())
        if ou:
            rows = [r for r in rows if ou.lower() in r.get("dn", "").lower()]
        if only_enabled is not None:
            rows = [r for r in rows if bool(r.get("account_enabled")) == only_enabled]
        return [self._to_model(r) for r in rows]

    async def search_users(self, query: str) -> list[DirectoryUser]:
        q = query.lower()
        rows = [
            r
            for r in self._ad_users().values()
            if q in r.get("display_name", "").lower()
            or q in r.get("mail", "").lower()
            or q in r.get("ad_attributes", {}).get("sAMAccountName", "").lower()
        ]
        return [self._to_model(r) for r in rows]

    async def list_groups(self, *, ou: str = "") -> list[DirectoryGroup]:
        return [
            DirectoryGroup(
                platform="active_directory",
                external_id=gid,
                display_name=g["display_name"],
                description=g.get("description", ""),
                mail=g.get("mail", ""),
                dn=f"CN={g['display_name']},OU=Grupos,{self.base_dn}",
                member_count=len(g.get("members", [])),
            )
            for gid, g in self.store.groups.items()
            if g.get("on_premises_sync")
        ]

    async def get_user_groups(self, identifier: str) -> list[DirectoryGroup]:
        raw = self._find(identifier)
        if not raw:
            return []
        return [
            DirectoryGroup(
                platform="active_directory",
                external_id=gid,
                display_name=g["display_name"],
                dn=f"CN={g['display_name']},OU=Grupos,{self.base_dn}",
            )
            for gid, g in self.store.groups.items()
            if raw["id"] in g.get("members", []) and g.get("on_premises_sync")
        ]

    async def create_user(self, employee: Employee, *, password: str, ou: str = "") -> DirectoryUser:
        existing = self._find(employee.email or employee.suggested_username())
        if existing:
            return self._to_model(existing)

        username = employee.suggested_username()
        upn = employee.suggested_upn(self.settings.upn_suffix or "corp.local")
        dn = self.build_dn(employee).replace(",DC=corp,DC=local", f",{self.base_dn}")
        uid = f"ad-{username}-{len(self.store.users)}"
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
            "account_enabled": True,
            "on_premises_sync_enabled": True,
            "on_premises_sam_account_name": username,
            "dn": dn,
            "password_last_set": datetime.now(timezone.utc).isoformat(),
            "licenses": [],
            "manager_id": employee.manager.entra_id if employee.manager else "",
            "source": "ad",
            "ad_attributes": {
                "sAMAccountName": username,
                "userPrincipalName": upn,
                "title": employee.job_title,
                "department": employee.department,
                "memberOf": [],
                "userAccountControl": DEFAULT_UAC_ENABLED,
            },
            "_provisional_password": password,
        }
        self.store.log_event("ad.create_user", dn=dn, sam=username)
        return self._to_model(self.store.users[uid])

    async def update_user(self, identifier: str, attributes: dict[str, Any]) -> DirectoryUser:
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        field_map = {
            "title": "job_title",
            "department": "department",
            "company": "company_name",
            "mail": "mail",
            "displayName": "display_name",
            "physicalDeliveryOfficeName": "office_location",
            "mobile": "mobile_phone",
            "employeeID": "employee_id",
            "description": "description",
        }
        for key, value in attributes.items():
            if key == "userAccountControl":
                raw["ad_attributes"]["userAccountControl"] = int(value)
                raw["account_enabled"] = uac_is_enabled(value)
                continue
            target = field_map.get(key, key)
            raw[target] = value
            if key in ("title", "department"):
                raw["ad_attributes"][key] = value
        self.store.log_event("ad.update_user", dn=raw.get("dn"), fields=list(attributes))
        return self._to_model(raw)

    async def disable_user(self, identifier: str, *, reason: str = "") -> DirectoryUser:
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        raw["account_enabled"] = False
        raw["ad_attributes"]["userAccountControl"] = DEFAULT_UAC_DISABLED
        raw["description"] = f"[iam-agent] {reason}"
        if self.settings.disabled_ou:
            raw["dn"] = raw.get("dn", "").split(",", 1)[-1]
            raw["dn"] = f"{raw['dn'].split(',')[0]},{self.settings.disabled_ou}"
        self.store.log_event("ad.disable_user", dn=raw.get("dn"), reason=reason)
        return self._to_model(raw)

    async def enable_user(self, identifier: str) -> DirectoryUser:
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        raw["account_enabled"] = True
        raw["ad_attributes"]["userAccountControl"] = DEFAULT_UAC_ENABLED
        self.store.log_event("ad.enable_user", dn=raw.get("dn"))
        return self._to_model(raw)

    async def delete_user(self, identifier: str) -> dict[str, Any]:
        if not self.settings.allow_hard_delete:
            raise AuthorizationError(
                "Hard delete disabled (IAM_AD_ALLOW_HARD_DELETE=false). Disable + move instead.",
                platform=self.name,
            )
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        self.store.users.pop(raw["id"], None)
        self.store.log_event("ad.delete_user", dn=raw.get("dn"))
        return {"deleted": True, "dn": raw.get("dn")}

    async def move_user(self, identifier: str, target_ou: str) -> dict[str, Any]:
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        rdn = raw.get("dn", "").split(",", 1)[0]
        old = raw.get("dn", "")
        raw["dn"] = f"{rdn},{target_ou}"
        self.store.log_event("ad.move_user", **{"from": old, "to": raw["dn"]})
        return {"moved": True, "from": old, "to": raw["dn"]}

    async def set_password(self, identifier: str, password: str, *, must_change: bool = True) -> dict[str, Any]:
        if not self.settings.use_ssl:
            raise ConfigurationError("Password changes require LDAPS (IAM_AD_USE_SSL=true).", platform=self.name)
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        raw["_provisional_password"] = password
        raw["password_last_set"] = "0" if must_change else datetime.now(timezone.utc).isoformat()
        self.store.log_event("ad.set_password", dn=raw.get("dn"), must_change=must_change)
        return {"dn": raw.get("dn"), "password_set": True, "must_change_at_logon": must_change}

    async def expire_password(self, identifier: str) -> dict[str, Any]:
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        raw["password_last_set"] = "0"
        return {"dn": raw.get("dn"), "password_expired": True}

    async def set_account_expiry(self, identifier: str, expires_at: datetime | None) -> dict[str, Any]:
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        raw["account_expires"] = expires_at.isoformat() if expires_at else None
        return {"dn": raw.get("dn"), "account_expires": raw["account_expires"] or "never"}

    async def add_group_member(self, group_dn: str, member_dn: str) -> dict[str, Any]:
        gid = self.store.group_id_by_name(group_dn) or (group_dn if group_dn in self.store.groups else None)
        if not gid:
            # match by DN form CN=Name,OU=...
            name = group_dn.split(",")[0].replace("CN=", "")
            gid = self.store.group_id_by_name(name)
        if not gid:
            raise NotFoundError(f"mock AD: no group '{group_dn}'", platform=self.name)
        raw = self._find(member_dn)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{member_dn}'", platform=self.name)
        if raw["id"] not in self.store.groups[gid]["members"]:
            self.store.groups[gid]["members"].append(raw["id"])
        raw["ad_attributes"].setdefault("memberOf", []).append(self.store.groups[gid]["display_name"])
        self.store.log_event("ad.add_group_member", group=gid, user=raw["id"])
        return {"group": gid, "member": raw["id"], "added": True}

    async def remove_group_member(self, group_dn: str, member_dn: str) -> dict[str, Any]:
        gid = self.store.group_id_by_name(group_dn) or group_dn
        if gid not in self.store.groups:
            name = group_dn.split(",")[0].replace("CN=", "")
            gid = self.store.group_id_by_name(name) or gid
        raw = self._find(member_dn)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{member_dn}'", platform=self.name)
        group = self.store.groups.get(gid)
        if group:
            group["members"] = [m for m in group["members"] if m != raw["id"]]
        raw["ad_attributes"]["memberOf"] = [
            m for m in raw["ad_attributes"].get("memberOf", []) if m != (group or {}).get("display_name")
        ]
        self.store.log_event("ad.remove_group_member", group=gid, user=raw["id"])
        return {"group": gid, "member": raw["id"], "removed": True}

    async def unlock_user(self, identifier: str) -> dict[str, Any]:
        raw = self._find(identifier)
        if not raw:
            raise NotFoundError(f"mock AD: no user '{identifier}'", platform=self.name)
        raw["ad_attributes"]["userAccountControl"] = int(
            raw["ad_attributes"].get("userAccountControl", DEFAULT_UAC_ENABLED)
        ) & ~UAC_LOCKOUT
        return {"dn": raw.get("dn"), "unlocked": True}


def build_ad_connector(
    settings: ActiveDirectorySettings, audit: AuditLog | None = None, store: MockStore | None = None
) -> ADConnector:
    if settings.enabled and settings.backend == "live":
        return LiveADConnector(settings, audit)
    return MockADConnector(settings, audit, store)
