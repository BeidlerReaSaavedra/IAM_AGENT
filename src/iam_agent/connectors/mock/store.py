"""A coherent in-memory simulation of the whole estate.

All five *mock* connectors read and write this single store, so a simulated
onboarding genuinely moves a user through Entra → AD → M365 → Action1 →
Scalefusion and a later reconciliation sees consistent state. This is what makes
the system demoable and testable with zero credentials, and what lets the
``mock`` backend double as an integration-test fixture.

The store is seeded with a small but realistic company (departments, groups,
licences, a fleet of laptops and phones) and can optionally persist to disk.
"""

from __future__ import annotations

import json
import random
import threading
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from iam_agent.core.models import DevicePlatform, normalize_logon


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Deterministic id generation.
#
# uuid4() here meant the simulated estate got *different* object ids in every
# process. That breaks cross-process resume, which is a first-class feature: a
# run planned in the CLI carries the manager's Entra object id in its params, and
# an orchestrator restarting to approve it finds that id no longer exists. Real
# directories return stable ids, so the simulator has to as well.
#
# The counter resets whenever the store is (re)seeded, and seeding is
# deterministic, so the Nth id minted is always the same. uuid5 keeps them
# looking like real GUIDs rather than "1", "2", "3".
_OID_NAMESPACE = uuid.UUID("8f4f0f2a-6a1b-5c3d-9e7f-2b1a0c9d8e7f")
_oid_counter = 0


def _oid(hint: str = "") -> str:
    """Mint a stable object id; pass a natural key as ``hint`` when you have one."""
    global _oid_counter
    _oid_counter += 1
    basis = hint if hint else f"seq:{_oid_counter}"
    return str(uuid.uuid5(_OID_NAMESPACE, basis))


def _reset_oid_counter() -> None:
    global _oid_counter
    _oid_counter = 0


class _PersistingDict(dict):
    """A plain dict that writes the estate back to disk on every mutation.

    The simulator is in-memory, but the CLI, the REST API and the MCP server are
    three separate processes. Without this, a user created by ``iam-agent
    onboard`` does not exist for the ``iam-agent approvals decide`` that follows
    it, and every multi-step demo falls over with "no user ...". Live directories
    share state by definition; the simulator has to earn the same property.
    """

    def __init__(self, store: "MockStore", *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Bypass object.__setattr__ concerns: dict has no __slots__ issues here.
        object.__setattr__(self, "_store", store)

    def _touch(self) -> None:
        store = getattr(self, "_store", None)
        if store is not None:
            store._autosave()

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(key, value)
        self._touch()

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(key)
        self._touch()

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        super().update(*args, **kwargs)
        self._touch()

    def pop(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        result = super().pop(*args, **kwargs)
        self._touch()
        return result

    def setdefault(self, key: Any, default: Any = None) -> Any:  # type: ignore[override]
        existed = key in self
        result = super().setdefault(key, default)
        if not existed:
            self._touch()
        return result

    def clear(self) -> None:  # type: ignore[override]
        super().clear()
        self._touch()


# --------------------------------------------------------------------------- #
# Seed data
# --------------------------------------------------------------------------- #

_LICENSE_CATALOG = {
    "ENTERPRISEPACK": "Microsoft 365 E3",
    "DEVELOPERPACK": "Microsoft 365 E3 Developer",
    "EMS": "Enterprise Mobility + Security E3",
    "EXCHANGESTANDARD": "Exchange Online (Plan 1)",
    "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Premium",
    "POWER_BI_STANDARD": "Power BI (free)",
}

_DIRECTORY_ROLES = {
    "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
    "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "Exchange Administrator": "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "Teams Administrator": "69091246-20e8-4a56-aa4d-066075b2a7a8",
    "Intune Administrator": "3a2c62db-5318-420d-8d74-23affee5d9d5",
    "License Administrator": "4d6ac14f-3453-41d0-bef9-a3e0c569773a",
}

_DEPARTMENTS = {
    "IT": {
        "groups": ["IT-All", "IT-Support", "SecOps"],
        "licenses": ["ENTERPRISEPACK", "EMS"],
        "teams": ["IT Operations", "Security"],
    },
    "Ventas": {
        "groups": ["Ventas-All", "Ventas-Campo"],
        "licenses": ["O365_BUSINESS_PREMIUM"],
        "teams": ["Comercial"],
    },
    "Finanzas": {
        "groups": ["Finanzas-All", "Finanzas-Cierre"],
        "licenses": ["ENTERPRISEPACK"],
        "teams": ["Finance"],
    },
    "RRHH": {
        "groups": ["RRHH-All"],
        "licenses": ["ENTERPRISEPACK"],
        "teams": ["People"],
    },
    "Marketing": {
        "groups": ["Marketing-All"],
        "licenses": ["O365_BUSINESS_PREMIUM"],
        "teams": ["Marketing"],
    },
}


def _seed_people() -> list[dict[str, Any]]:
    """A handful of existing employees so reconciliation and drift detection
    have something real to find."""
    people = [
        # first, last, dept, title, manager idx, state, has mobile, is BYOD
        ("Laura", "Ferrà", "IT", "Directora de IT", None, "active", True, False),
        ("Marc", "Oliver", "IT", "Técnico de soporte", 0, "active", True, False),
        ("Núria", "Serra", "Ventas", "Account executive", 0, "active", True, False),
        ("Jordi", "Puig", "Finanzas", "Controller", 0, "active", False, False),
        ("Aina", "Vidal", "RRHH", "HR Business Partner", 0, "active", False, False),
        # A leaver disabled in Entra but still holding a live AD account and an
        # enrolled BYOD phone -> exactly the drift the agent must catch, and the
        # case where a wipe would destroy personal data.
        ("Pau", "Roca", "Marketing", "Diseñador", 0, "disabled", True, True),
        # An orphan: enabled everywhere, but left 40 days ago.
        ("Bea", "Solà", "Ventas", "BDR", 0, "orphan", True, False),
    ]
    out: list[dict[str, Any]] = []
    for idx, (first, last, dept, title, mgr, state, mobile, byod) in enumerate(people):
        # Derive the logon name exactly as the product does: accents folded away.
        username = f"{normalize_logon(first)[:1]}{normalize_logon(last)}"
        email = f"{username}@contoso-balears.example"
        enabled = state != "disabled"
        out.append(
            {
                "idx": idx,
                "first_name": first,
                "last_name": last,
                "department": dept,
                "job_title": title,
                "manager_idx": mgr,
                "username": username,
                "email": email,
                "enabled": enabled,
                "state_hint": state,
                "employee_id": f"EMP-{1000 + idx}",
                "mobile": mobile,
                "hire_date": (date.today() - timedelta(days=400 + idx * 30)).isoformat(),
                "byod": byod,
            }
        )
    return out


# --------------------------------------------------------------------------- #
# The store
# --------------------------------------------------------------------------- #


class MockStore:
    """In-memory estate simulator with optional JSON persistence."""

    #: Collections that hold estate state and therefore need write-through.
    _PERSISTED_COLLECTIONS = (
        "users", "groups", "directory_roles", "deleted_users",
        "mailboxes", "license_skus", "teams",
        "action1_endpoints", "action1_groups", "action1_automations", "action1_updates",
        "scalefusion_devices", "scalefusion_profiles", "scalefusion_groups",
        "lifecycle_workflows", "organizations",
    )

    def __init__(self, *, seed: bool = True, persist_path: str | Path | None = None) -> None:
        self._lock = threading.RLock()
        self.persist_path = Path(persist_path) if persist_path else None
        # Seeding mints hundreds of ids and inserts hundreds of rows; writing the
        # estate back on each one would be quadratic. Suppressed until seeded.
        self._suppress_autosave = True
        # Deterministic ids: every fresh store must mint the same estate.
        _reset_oid_counter()

        # ---- Entra / AD -------------------------------------------------- #
        self.users: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.groups: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.directory_roles: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.deleted_users: dict[str, dict[str, Any]] = _PersistingDict(self)

        # ---- M365 -------------------------------------------------------- #
        self.mailboxes: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.license_skus: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.teams: dict[str, dict[str, Any]] = _PersistingDict(self)

        # ---- UEM --------------------------------------------------------- #
        self.action1_endpoints: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.action1_groups: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.action1_automations: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.action1_updates: dict[str, dict[str, Any]] = _PersistingDict(self)

        self.scalefusion_devices: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.scalefusion_profiles: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.scalefusion_groups: dict[str, dict[str, Any]] = _PersistingDict(self)

        # ---- Lifecycle Workflows ----------------------------------------- #
        self.lifecycle_workflows: dict[str, dict[str, Any]] = _PersistingDict(self)
        self.workflow_runs: list[dict[str, Any]] = []

        # ---- Misc -------------------------------------------------------- #
        self.organizations: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []

        if seed:
            self._seed()

    # ---- seeding --------------------------------------------------------- #

    def _seed(self, rng_seed: int = 20261006) -> None:
        rng = random.Random(rng_seed)

        self.organizations = [
            {"id": "org_contoso", "name": "Contoso Balears", "endpoints_count": 0},
        ]

        # Licences
        for sku, name in _LICENSE_CATALOG.items():
            self.license_skus[sku] = {
                "sku_id": f"sku-{sku.lower()}",
                "sku_part_number": sku,
                "product_name": name,
                "enabled": 250,
                "consumed": rng.randint(10, 90),
                "warning": 10,
            }

        # Directory roles
        for role_name, role_id in _DIRECTORY_ROLES.items():
            self.directory_roles[role_id] = {
                "id": role_id,
                "display_name": role_name,
                "members": [],
            }

        # Groups
        seen_groups: set[str] = set()
        for dept, cfg in _DEPARTMENTS.items():
            for gname in cfg["groups"]:
                if gname in seen_groups:
                    continue
                seen_groups.add(gname)
                gid = _oid()
                self.groups[gid] = {
                    "id": gid,
                    "display_name": gname,
                    "description": f"Security group for {dept}",
                    "mail": f"{gname.lower().replace(' ', '')}@contoso-balears.example",
                    "security_enabled": True,
                    "group_types": ["Unified"] if gname.endswith("-All") else [],
                    "members": [],
                    "owners": [],
                    "membership_rule": None,
                    "on_premises_sync": True,
                    "department": dept,
                }

        # Everyone / leavers groups
        for gname, desc in (
            ("All-Employees", "All active staff"),
            ("Leavers-Pending", "Accounts in offboarding"),
            ("MFA-Required", "Users with MFA enforced"),
            ("MDM-Enrolled", "Users with managed devices"),
        ):
            gid = _oid()
            self.groups[gid] = {
                "id": gid,
                "display_name": gname,
                "description": desc,
                "mail": "",
                "security_enabled": True,
                "group_types": [],
                "members": [],
                "owners": [],
                "membership_rule": None,
                "on_premises_sync": False,
                "department": "",
            }

        # Teams
        for team_name in sorted({t for cfg in _DEPARTMENTS.values() for t in cfg["teams"]}):
            tid = _oid()
            self.teams[tid] = {
                "id": tid,
                "display_name": team_name,
                "members": [],
            }

        # Scalefusion profiles & groups
        for pname, pdesc in (
            ("Standard-Android-Work", "Baseline Android Enterprise profile"),
            ("iOS-Supervised", "Supervised iOS configuration"),
            ("Kiosk-Warehouse", "Single-app kiosk lockdown"),
            ("Leaver-Restricted", "Locked-down profile applied during offboarding"),
        ):
            pid = _oid()
            self.scalefusion_profiles[pid] = {"id": pid, "name": pname, "description": pdesc}

        for gname in ("Corporativo-Móviles", "BYOD", "Almacén-Kioskos", "Leavers"):
            gid = _oid()
            self.scalefusion_groups[gid] = {
                "id": gid,
                "name": gname,
                "device_profile_id": next(iter(self.scalefusion_profiles), ""),
                "devices": [],
            }

        # Action1 endpoint groups & automations
        for gname in ("All Endpoints", "Workstations", "Servers", "New Joiners", "Leavers"):
            gid = _oid()
            self.action1_groups[gid] = {
                "id": gid,
                "name": gname,
                "organization_id": "org_contoso",
                "endpoints": [],
            }
        for aname in ("Onboard New Endpoint", "Offboard Endpoint - Isolate"):
            aid = _oid()
            self.action1_automations[aid] = {
                "id": aid,
                "name": aname,
                "organization_id": "org_contoso",
                "enabled": True,
                "runs": [],
            }

        # People + their devices/mailboxes
        people = _seed_people()
        manager_ids: dict[int, str] = {}
        for person in people:
            uid = _oid()
            manager_ids[person["idx"]] = uid
            enabled = person["state_hint"] != "disabled"
            dept = person["department"]
            cfg = _DEPARTMENTS.get(dept, {"groups": [], "licenses": [], "teams": []})

            self.users[uid] = {
                "id": uid,
                "user_principal_name": person["email"],
                "mail": person["email"],
                "mail_nickname": person["username"],
                "display_name": f"{person['first_name']} {person['last_name']}",
                "given_name": person["first_name"],
                "surname": person["last_name"],
                "job_title": person["job_title"],
                "department": dept,
                "company_name": "Contoso Balears",
                "office_location": "Palma de Mallorca",
                "country": "ES",
                "employee_id": person["employee_id"],
                "employee_hire_date": person["hire_date"],
                "employee_leave_date_time": None,
                "account_enabled": enabled,
                "on_premises_sync_enabled": True,
                "on_premises_sam_account_name": person["username"],
                "on_premises_distinguished_name": (
                    f"CN={person['first_name']} {person['last_name']},"
                    f"OU={dept},OU=Usuarios,DC=corp,DC=local"
                ),
                "dn": f"CN={person['first_name']} {person['last_name']},OU={dept},OU=Usuarios,DC=corp,DC=local",
                "password_last_set": (_utcnow() - timedelta(days=rng.randint(10, 200))).isoformat(),
                "last_sign_in": (_utcnow() - timedelta(days=rng.randint(0, 45))).isoformat()
                if person["state_hint"] != "orphan"
                else (_utcnow() - timedelta(days=41)).isoformat(),
                "mfa_registered": person["state_hint"] != "orphan",
                "licenses": [] if person["state_hint"] == "disabled" else list(cfg["licenses"]),
                "manager_id": "",
                "source": "entra",
                # AD-only extras
                "ad_attributes": {
                    "sAMAccountName": person["username"],
                    "userPrincipalName": person["email"],
                    "title": person["job_title"],
                    "department": dept,
                    "memberOf": [],
                    "userAccountControl": 512 if enabled else 514,
                },
                "account_expires": None,
                "description": "",
            }

            # Manager wiring
            if person["manager_idx"] is not None:
                mgr_uid = manager_ids.get(person["manager_idx"])
                if mgr_uid and mgr_uid in self.users:
                    self.users[uid]["manager_id"] = mgr_uid

            # Group membership
            for gname in cfg["groups"] + (["All-Employees"] if enabled else ["Leavers-Pending"]):
                gid = self.group_id_by_name(gname)
                if gid:
                    self.groups[gid]["members"].append(uid)

            for team_name in cfg["teams"]:
                tid = self.team_id_by_name(team_name)
                if tid:
                    self.teams[tid]["members"].append(uid)

            # Mailbox
            self.mailboxes[uid] = {
                "id": uid,
                "email": person["email"],
                "display_name": self.users[uid]["display_name"],
                "mailbox_type": "user",
                "primary_smtp": person["email"],
                "proxy_addresses": [f"SMTP:{person['email']}", f"smtp:alias-{person['username']}@contoso-balears.example"],
                "total_item_size_mb": round(rng.uniform(200, 12000), 1),
                "item_count": rng.randint(500, 40000),
                "hidden_from_gal": not enabled,
                "litigation_hold": False,
                "forward_to": "",
                "delegates": [],
                "archived": False,
            }

            # A laptop for everyone, managed by Action1
            self._add_action1_endpoint(
                name=f"{person['username']}-LT01",
                owner_uid=uid,
                os_name="Windows 11 Pro",
                os_version="23H2",
                platform=DevicePlatform.WINDOWS,
                online=enabled,
                missing_updates=0 if enabled else rng.randint(5, 40),
                asset_tag=f"LT-{1000 + person['idx']}",
                rng=rng,
            )

            # A mobile phone for those flagged, managed by Scalefusion
            if person["mobile"]:
                android = rng.random() < 0.6
                device_id = self._add_scalefusion_device(
                    name=f"{person['first_name']}'s {'Galaxy S24' if android else 'iPhone 15'}",
                    owner_uid=uid,
                    platform=DevicePlatform.ANDROID if android else DevicePlatform.IOS,
                    rng=rng,
                    online=enabled,
                )
                if person.get("byod"):
                    self.scalefusion_devices[device_id]["ownership"] = "byod"

        # Give Laura (idx 0) User Administrator + Intune Administrator
        laura = manager_ids.get(0)
        if laura:
            for role_name in ("User Administrator", "Intune Administrator"):
                rid = _DIRECTORY_ROLES[role_name]
                self.directory_roles[rid]["members"].append(laura)

        # Orphan: Bea stays enabled everywhere with a leave date in the past.
        for uid, u in self.users.items():
            if u["employee_id"] == "EMP-1006":
                u["employee_leave_date_time"] = (_utcnow() - timedelta(days=40)).isoformat()
                u["account_enabled"] = True  # the bug the drift detector must find

        # A stale device with no owner at all.
        self._add_action1_endpoint(
            name="OLD-WS-07",
            owner_uid=None,
            os_name="Windows 10 Pro",
            os_version="22H2",
            platform=DevicePlatform.WINDOWS,
            online=False,
            missing_updates=63,
            asset_tag="LT-0007",
            rng=rng,
        )

        self.organizations[0]["endpoints_count"] = len(self.action1_endpoints)

    # ---- helpers --------------------------------------------------------- #

    def _add_action1_endpoint(
        self,
        *,
        name: str,
        owner_uid: str | None,
        os_name: str,
        os_version: str,
        platform: DevicePlatform,
        online: bool,
        missing_updates: int,
        asset_tag: str,
        rng: random.Random | None = None,
    ) -> str:
        rng = rng or random.Random()
        eid = _oid()
        owner = self.users.get(owner_uid or "", {})
        self.action1_endpoints[eid] = {
            "id": eid,
            "name": name,
            "organization_id": "org_contoso",
            "asset_tag": asset_tag,
            "serial_number": f"SN-{rng.randint(100000, 999999)}",
            "os_name": os_name,
            "os_version": os_version,
            "platform": platform.value,
            "online": online,
            "last_seen": (_utcnow() - timedelta(minutes=rng.randint(1, 4320))).isoformat(),
            "owner_id": owner_uid or "",
            "owner_email": owner.get("mail", ""),
            "owner_name": owner.get("display_name", ""),
            "missing_updates": missing_updates,
            "critical_vulnerabilities": rng.randint(0, 3) if missing_updates else 0,
            "agent_version": "3.2.19",
            "groups": [self.group_id_by_name("All Endpoints", store="action1") or ""],
            "compliance": "compliant" if missing_updates < 5 else "non_compliant",
            "bitlocker_enabled": platform == DevicePlatform.WINDOWS,
            "quarantined": False,
        }
        gid = self.group_id_by_name("All Endpoints", store="action1")
        if gid:
            self.action1_groups[gid]["endpoints"].append(eid)
        for _ in range(min(missing_updates, 5)):
            uid = _oid()
            self.action1_updates[uid] = {
                "id": uid,
                "endpoint_id": eid,
                "kb": f"KB{rng.randint(5000000, 5099999)}",
                "title": "Security Update for Windows",
                "severity": rng.choice(["critical", "important", "moderate"]),
                "installed": False,
            }
        return eid

    def _add_scalefusion_device(
        self,
        *,
        name: str,
        owner_uid: str | None,
        platform: DevicePlatform,
        rng: random.Random | None = None,
        online: bool = True,
    ) -> str:
        rng = rng or random.Random()
        did = _oid()
        owner = self.users.get(owner_uid or "", {})
        profile_id = next(iter(self.scalefusion_profiles), "")
        group_id = next(iter(self.scalefusion_groups), "")
        self.scalefusion_devices[did] = {
            "id": did,
            "device_name": name,
            "imei": f"{rng.randint(10**14, 10**15 - 1)}",
            "serial_number": f"SF-{rng.randint(100000, 999999)}",
            "asset_tag": "",
            "os": platform.value,
            "os_version": "14" if platform == DevicePlatform.ANDROID else "17.5",
            "manufacturer": "Samsung" if platform == DevicePlatform.ANDROID else "Apple",
            "model": "SM-S921B" if platform == DevicePlatform.ANDROID else "iPhone15,4",
            "ownership": "corporate" if rng.random() < 0.8 else "byod",
            "status": "active" if online else "inactive",
            "enrolled_at": (_utcnow() - timedelta(days=rng.randint(10, 400))).isoformat(),
            "last_seen": (_utcnow() - timedelta(minutes=rng.randint(1, 2880))).isoformat(),
            "battery_level": rng.randint(15, 100),
            "user_id": owner_uid or "",
            "user_email": owner.get("mail", ""),
            "user_name": owner.get("display_name", ""),
            "device_profile_id": profile_id,
            "device_group_id": group_id,
            "compliance": "compliant",
            "locked": False,
            "wiped": False,
            "retired": False,
            "mdm_mode": "android_enterprise" if platform == DevicePlatform.ANDROID else "supervised",
            "location": {"lat": 39.5696, "lng": 2.6502, "label": "Palma"},
        }
        if group_id:
            self.scalefusion_groups[group_id]["devices"].append(did)
        return did

    def group_id_by_name(self, name: str, store: str = "graph") -> str | None:
        if store == "graph":
            for gid, g in self.groups.items():
                if g["display_name"].lower() == name.lower():
                    return gid
            return None
        if store == "action1":
            for gid, g in self.action1_groups.items():
                if g["name"].lower() == name.lower():
                    return gid
        if store == "scalefusion":
            for gid, g in self.scalefusion_groups.items():
                if g["name"].lower() == name.lower():
                    return gid
        return None

    def team_id_by_name(self, name: str) -> str | None:
        for tid, t in self.teams.items():
            if t["display_name"].lower() == name.lower():
                return tid
        return None

    def profile_id_by_name(self, name: str) -> str | None:
        for pid, p in self.scalefusion_profiles.items():
            if p["name"].lower() == name.lower():
                return pid
        return None

    def automation_id_by_name(self, name: str) -> str | None:
        for aid, a in self.action1_automations.items():
            if a["name"].lower() == name.lower():
                return aid
        return None

    def find_user(self, *, email: str = "", username: str = "", oid: str = "") -> dict[str, Any] | None:
        for u in self.users.values():
            if oid and u["id"] == oid:
                return u
            if email and (
                u["mail"].lower() == email.lower() or u["user_principal_name"].lower() == email.lower()
            ):
                return u
            if username and (
                u.get("mail_nickname", "").lower() == username.lower()
                or u.get("on_premises_sam_account_name", "").lower() == username.lower()
            ):
                return u
        return None

    def devices_for_user(self, uid: str) -> list[dict[str, Any]]:
        out = [d for d in self.scalefusion_devices.values() if d["user_id"] == uid]
        out += [e for e in self.action1_endpoints.values() if e["owner_id"] == uid]
        return out

    def log_event(self, kind: str, **data: Any) -> None:
        self.events.append({"at": _utcnow().isoformat(), "kind": kind, **data})

    # ---- persistence ----------------------------------------------------- #

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "users": self.users,
                "groups": self.groups,
                "directory_roles": self.directory_roles,
                "mailboxes": self.mailboxes,
                "license_skus": self.license_skus,
                "teams": self.teams,
                "action1_endpoints": self.action1_endpoints,
                "action1_groups": self.action1_groups,
                "action1_automations": self.action1_automations,
                "scalefusion_devices": self.scalefusion_devices,
                "scalefusion_profiles": self.scalefusion_profiles,
                "scalefusion_groups": self.scalefusion_groups,
                "lifecycle_workflows": self.lifecycle_workflows,
                "organizations": self.organizations,
                # These four were missing, which silently lost state across
                # processes: `deleted_users` is where offboarding parks accounts
                # and where deferred_deletion looks for them, so dropping it made
                # a leaver vanish between the CLI invocation that offboarded them
                # and the one that was supposed to purge them.
                "action1_updates": self.action1_updates,
                "deleted_users": self.deleted_users,
                "workflow_runs": self.workflow_runs,
                "events": self.events,
            }

    def _autosave(self) -> None:
        """Write-through hook used by :class:`_PersistingDict`."""
        if self._suppress_autosave or not self.persist_path:
            return
        self.save()

    def save(self) -> None:
        if not self.persist_path:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic: a crash mid-write must not leave a truncated estate that the
        # next process silently loads as "everything is gone".
        tmp = self.persist_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.snapshot(), indent=2, default=str), encoding="utf-8")
        tmp.replace(self.persist_path)

    def load(self) -> bool:
        """Restore a previously persisted estate. Returns False if there is none."""
        if not self.persist_path or not self.persist_path.exists():
            return False
        try:
            data = json.loads(self.persist_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        with self._lock:
            for key, value in data.items():
                current = getattr(self, key, None)
                if isinstance(current, dict) and isinstance(value, dict):
                    # Update in place: setattr would discard the _PersistingDict
                    # wrapper and silently disable write-through from then on.
                    current.clear()
                    current.update(value)
                elif isinstance(current, list) and isinstance(value, list):
                    current.clear()
                    current.extend(value)
                elif hasattr(self, key):
                    setattr(self, key, value)
        return True

    def stats(self) -> dict[str, int]:
        return {
            "entra_users": len(self.users),
            "entra_groups": len(self.groups),
            "mailboxes": len(self.mailboxes),
            "teams": len(self.teams),
            "action1_endpoints": len(self.action1_endpoints),
            "scalefusion_devices": len(self.scalefusion_devices),
            "deleted_users": len(self.deleted_users),
            "simulated_events": len(self.events),
        }


#: Process-wide singleton so all mock connectors share one estate.
_DEFAULT_STORE: MockStore | None = None
_STORE_LOCK = threading.Lock()


def get_mock_store(*, reseed: bool = False, persist_path: str | Path | None = None) -> MockStore:
    """Process-wide simulator estate.

    Resolution order:

    1. ``reseed=True`` always builds a pristine estate (tests rely on this).
    2. Otherwise, if a persisted estate exists on disk it is *loaded*, so a
       second process sees the users the first one created.
    3. Otherwise a fresh estate is seeded and persisted for the next process.
    """
    global _DEFAULT_STORE
    with _STORE_LOCK:
        if _DEFAULT_STORE is not None and not reseed:
            return _DEFAULT_STORE

        if persist_path is None and not reseed:
            persist_path = _configured_persist_path()

        store = MockStore(seed=False, persist_path=persist_path)
        restored = False if reseed else store.load()
        if reseed or not restored:
            store._seed()
        store._suppress_autosave = False
        store.save()
        _DEFAULT_STORE = store
        return _DEFAULT_STORE


def _configured_persist_path() -> str | None:
    """Where the simulator keeps its estate, if persistence is enabled at all."""
    try:
        from iam_agent.config import get_settings

        mock_settings = get_settings().mock
    except Exception:  # noqa: BLE001 - settings may be mid-construction
        return None
    if not mock_settings.persist:
        return None
    return mock_settings.persist_path
