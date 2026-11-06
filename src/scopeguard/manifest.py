"""Scope manifest: one TOML file per skill that says exactly what it may touch.

DEFAULT DENY: a skill with no manifest has no permissions. A manifest with an
empty `allowed_inputs` list grants no data. Anything malformed, unknown or
contradictory makes the manifest invalid, and an invalid manifest means deny.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ManifestError, NoManifest
from .roles import ROLES
from .scrubber import KNOWN_CLASSES

# The only place this demo can write to. Anything else in a manifest is rejected.
KNOWN_WRITE_TARGETS = frozenset({"pending_review"})

_SCHEMA: dict[str, frozenset[str]] = {
    "skill": frozenset({"name", "purpose"}),
    "access": frozenset({"allowed_roles", "allowed_inputs"}),
    "forbidden": frozenset({"redact", "reject", "deny_terms"}),
    "writes": frozenset({"targets", "forbidden", "requires_approval"}),
    "output": frozenset({"template"}),
    "audit": frozenset({"logging"}),
}


@dataclass(frozen=True)
class Manifest:
    name: str
    purpose: str
    allowed_roles: tuple[str, ...]  # who may run this skill
    allowed_inputs: tuple[str, ...]  # field paths the skill may see
    redact_classes: tuple[str, ...]  # sensitive classes replaced with a marker
    deny_terms: tuple[str, ...]  # literal terms that cause rejection
    write_targets: tuple[str, ...]  # where output may be written
    forbidden_writes: tuple[str, ...]  # things this skill must never write to (documented intent)
    requires_approval: bool
    output_template: str
    logging: bool


def _table(raw: dict[str, Any], section: str) -> dict[str, Any]:
    table = raw.get(section, {})
    if not isinstance(table, dict):
        raise ManifestError(f"[{section}] must be a table")
    unknown = set(table) - _SCHEMA[section]
    if unknown:
        raise ManifestError(f"[{section}] has unknown keys: {sorted(unknown)}")
    return table


def _strings(table: dict[str, Any], key: str) -> tuple[str, ...]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestError(f"'{key}' must be a list of strings")
    return tuple(value)


def load_manifest(skill_name: str, manifests_dir: Path) -> Manifest:
    """Load and validate manifests/<skill_name>.toml. Raises NoManifest or ManifestError."""
    if not re.fullmatch(r"[a-z0-9_]+", skill_name):
        raise NoManifest()
    path = Path(manifests_dir) / f"{skill_name}.toml"
    if not path.is_file():
        raise NoManifest()
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {type(exc).__name__}") from exc

    unknown_sections = set(raw) - set(_SCHEMA)
    if unknown_sections:
        raise ManifestError(f"unknown sections: {sorted(unknown_sections)}")

    skill, access, forbidden = _table(raw, "skill"), _table(raw, "access"), _table(raw, "forbidden")
    writes, output, audit = _table(raw, "writes"), _table(raw, "output"), _table(raw, "audit")

    if skill.get("name") != skill_name:
        raise ManifestError("[skill].name must match the manifest file name")

    roles = _strings(access, "allowed_roles")
    if not roles or not set(roles) <= ROLES:
        raise ManifestError("allowed_roles must be a non-empty subset of the known roles")

    redact, reject = _strings(forbidden, "redact"), _strings(forbidden, "reject")
    if not (set(redact) | set(reject)) <= KNOWN_CLASSES:
        raise ManifestError("unknown data class in [forbidden]")
    if set(redact) & set(reject):
        raise ManifestError("a data class cannot be both redacted and rejected")

    targets, forbidden_writes = _strings(writes, "targets"), _strings(writes, "forbidden")
    if not set(targets) <= KNOWN_WRITE_TARGETS:
        raise ManifestError("unknown write target")
    if set(targets) & set(forbidden_writes):
        raise ManifestError("a write target is also listed as forbidden")
    requires_approval = writes.get("requires_approval", True)
    if not isinstance(requires_approval, bool):
        raise ManifestError("requires_approval must be true or false")
    if targets and not requires_approval:
        raise ManifestError("skills that write output must require approval")

    logging_on = audit.get("logging", True)
    if logging_on is not True:
        raise ManifestError("logging cannot be turned off")

    purpose = skill.get("purpose", "")
    template = output.get("template", "")
    if not isinstance(purpose, str) or not purpose.strip():
        raise ManifestError("[skill].purpose is required")
    if not isinstance(template, str) or not template:
        raise ManifestError("[output].template is required")

    return Manifest(
        name=skill_name,
        purpose=purpose,
        allowed_roles=roles,
        allowed_inputs=_strings(access, "allowed_inputs"),
        redact_classes=redact,
        deny_terms=_strings(forbidden, "deny_terms"),
        write_targets=targets,
        forbidden_writes=forbidden_writes,
        requires_approval=requires_approval,
        output_template=template,
        logging=True,
    )
