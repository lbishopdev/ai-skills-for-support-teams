"""Roles and permissions.

Three roles, deliberately small:

  viewer   can look at pending/approved outputs
  author   can run skills and ask for outputs to be written to pending_review/
  approver can approve outputs (and nothing else)

A person may hold more than one role, but separation of duties still applies:
nobody can approve an output they created (see approval.py).

The user list here is a plain file of invented names. In a real deployment this
is the job of your identity provider, not a TOML file.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROLES = frozenset({"viewer", "author", "approver"})

PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"view"}),
    "author": frozenset({"view", "run", "write"}),
    "approver": frozenset({"view", "approve"}),
}


@dataclass(frozen=True)
class Actor:
    name: str
    roles: frozenset[str]


def safe_actor_name(name: str | None) -> str:
    """Only plain identifiers are trusted enough to be logged or looked up."""
    if name and re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name):
        return name
    return "invalid-id"


def load_actor(users_file: Path, name: str) -> Actor | None:
    """Return the actor, or None if unknown or misconfigured (fail closed)."""
    name = safe_actor_name(name)
    try:
        data = tomllib.loads(Path(users_file).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    entry = data.get("users", {}).get(name)
    if not isinstance(entry, dict):
        return None
    roles = entry.get("roles")
    if not isinstance(roles, list) or not roles or not set(roles) <= ROLES:
        return None
    return Actor(name=name, roles=frozenset(roles))


def can(actor: Actor, permission: str) -> bool:
    return any(permission in PERMISSIONS[role] for role in actor.roles)
