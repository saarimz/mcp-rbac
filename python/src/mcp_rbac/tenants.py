"""Multi-account organisations: org-level roles over accounts, and custom roles from permission sets."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, TypeVar

from .roles import Assignment, Permission, Role

R = TypeVar("R", bound=str)


@dataclass(frozen=True)
class OrgDirectory:
    """``accounts``: account ids in the org. ``groups``: group name -> account ids."""

    accounts: Sequence[str]
    groups: Mapping[str, Sequence[str]] = field(default_factory=dict)


AccountAccess = Literal["all"] | Mapping[Literal["group", "accounts"], str | Sequence[str]]


@dataclass(frozen=True)
class OrgRole:
    role: str
    access: AccountAccess = "all"


def org_assignments(directory: OrgDirectory, roles: Sequence[OrgRole], tenant_key: str = "tenant") -> tuple[Assignment[str], ...]:
    """Expand org roles ("all accounts" / "by group" / "specific accounts") into per-account assignments.
    Accounts not in the directory are dropped (a stale token can't name an account outside the org)."""
    known = set(directory.accounts)
    out: list[Assignment[str]] = []
    for r in roles:
        if r.access == "all":
            accts: Sequence[str] = directory.accounts
        elif isinstance(r.access, Mapping) and "group" in r.access:
            accts = directory.groups.get(str(r.access["group"]), ())
        elif isinstance(r.access, Mapping) and "accounts" in r.access:
            v = r.access["accounts"]
            accts = [v] if isinstance(v, str) else list(v)
        else:
            raise TypeError(f"bad account access for role {r.role!r}")
        for a in accts:
            if a in known and not any(x.role == r.role and x.scope.get(tenant_key) == a for x in out):
                out.append(Assignment(r.role, {tenant_key: a}))
    return tuple(out)


PermissionSets = Mapping[str, Mapping[str, Sequence[str]]]
"""Permission set name -> level ("read"/"write"/"manage"...) -> tool patterns ("resource:" / "prompt:" prefixes allowed)."""


def custom_role(sets: PermissionSets, levels: Mapping[str, str], description: str = "") -> Role:
    """Build a custom role from permission sets, e.g. ``{"campaigns": "write", "profiles": "read"}``."""
    perms: list[Permission] = []
    for name, level in levels.items():
        if name not in sets or level not in sets[name]:
            raise KeyError(f"unknown permission set level {name}:{level}")
        for p in sets[name][level]:
            if p.startswith("resource:"):
                perms.append(Permission(p[9:], "resource"))
            elif p.startswith("prompt:"):
                perms.append(Permission(p[7:], "prompt"))
            else:
                perms.append(Permission(p))
    return Role(tuple(perms), description)
