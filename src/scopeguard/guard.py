"""The guard: every skill run goes through run_skill().

The order of checks is the whole point, so it is spelled out here. Any failure
at any step stops the run (fail closed) and writes a deny entry to the audit log.

   1. Who is asking?           unknown user / wrong role            -> deny
   2. Does the skill have a    no manifest (default deny)           -> deny
      valid manifest?          malformed manifest                   -> deny
   3. Is a write allowed?      no --write flag = dry run (no files)
                               write not granted by manifest        -> deny
   4. Drop fields that are not allow-listed (before anything else sees them)
   5. Strip instruction-like sentences from untrusted text (flagged in the log)
   6. Scrub: redact or reject sensitive patterns       reject       -> deny
   7. Run the skill (a pure function) with the cleaned data only
   8. Scrub the OUTPUT too; any sensitive pattern in it             -> deny
   9. Dry run: return the text.  Write: save to pending_review/ only.

The skill never touches files, the network or other skills. Only this module
reads inputs, and only approval.py moves anything out of pending_review/.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .approval import sha256_text, write_pending
from .audit import AuditLog, sha256_json
from .fields import filter_fields
from .injection import strip_injection
from .manifest import load_manifest
from .errors import ManifestError, NoManifest
from .model import MockModel, Model
from .roles import can, load_actor, safe_actor_name
from .scrubber import scrub
from .settings import Settings


@dataclass(frozen=True)
class Skill:
    """A skill is just a name and a pure function: cleaned inputs + model -> text."""

    name: str
    run: Callable[[dict[str, Any], Model], str]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9_]+", self.name):
            raise ValueError("skill names use lowercase letters, digits and underscores")


@dataclass
class RunResult:
    decision: str  # "allow" or "deny"
    reason: str
    output: str | None = None
    artifact_id: str | None = None
    written: bool = False
    redactions: dict[str, int] = field(default_factory=dict)
    fields_dropped: list[str] = field(default_factory=list)
    injection_flags: int = 0


def run_skill(
    skill: Skill,
    inputs: dict[str, Any],
    actor_name: str,
    settings: Settings,
    *,
    write: bool = False,
    model: Model | None = None,
) -> RunResult:
    log = AuditLog(settings.audit_log)
    actor_id = safe_actor_name(actor_name)
    mode = "write" if write else "dry_run"

    redactions: dict[str, int] = {}
    dropped: list[str] = []
    flags = 0
    inputs_hash: str | None = None

    def deny(reason: str) -> RunResult:
        log.record(
            actor=actor_id, action="run", skill=skill.name, decision="deny", reason=reason, mode=mode,
            inputs_hash=inputs_hash, fields_dropped=dropped, redactions=redactions, injection_flags=flags,
        )
        return RunResult("deny", reason, redactions=redactions, fields_dropped=dropped, injection_flags=flags)

    # 1. who is asking
    actor = load_actor(settings.users_file, actor_name)
    if actor is None:
        return deny("unknown_user")
    if not can(actor, "run"):
        return deny("role_not_permitted")

    # 2. manifest (default deny)
    try:
        manifest = load_manifest(skill.name, settings.manifests_dir)
    except NoManifest:
        return deny("no_manifest")
    except ManifestError:
        return deny("invalid_manifest")
    if not set(actor.roles) & set(manifest.allowed_roles):
        return deny("role_not_permitted")
    if not manifest.allowed_inputs:
        return deny("no_inputs_granted")

    # 3. writes need the explicit flag AND a grant AND the author role
    if write:
        if not can(actor, "write"):
            return deny("role_not_permitted")
        if "pending_review" not in manifest.write_targets:
            return deny("write_not_granted")

    # 4-6. allow-list, injection stripping, scrubbing
    if not inputs or not all(isinstance(item, dict) for item in inputs.values()):
        return deny("bad_input_shape")
    allowed = frozenset(manifest.allowed_inputs)
    dropped_set: set[str] = set()
    filtered = {name: filter_fields(item, allowed, dropped_set) for name, item in inputs.items()}
    dropped = sorted(dropped_set)

    filtered, flags = strip_injection(filtered)
    clean, redactions, rejected = scrub(filtered, manifest.redact_classes, manifest.deny_terms)
    if rejected:
        return deny("forbidden_data:" + ",".join(sorted(rejected)))
    inputs_hash = sha256_json(clean)  # hash of what the skill saw, never of raw input

    # 7. run the skill
    try:
        output = skill.run(clean, model or MockModel())
    except Exception as exc:  # fail closed; log the error TYPE only, never its message
        return deny(f"skill_error:{type(exc).__name__}")

    # 8. the output must be clean too (redact set is empty, so every class is a rejection)
    _, _, leaked = scrub(output, (), manifest.deny_terms)
    if leaked:
        return deny("output_violation")

    # 9. dry run or write to pending_review/
    result = RunResult(
        "allow", "ok", output=output, redactions=redactions, fields_dropped=dropped, injection_flags=flags,
    )
    artifact_id = None
    reason = "ok"
    if write:
        artifact_id, created = write_pending(settings, skill.name, output, actor.name, inputs_hash)
        result.artifact_id, result.written = artifact_id, created
        if not created:
            reason = result.reason = "already_exists"
    log.record(
        actor=actor_id, action="run", skill=skill.name, decision="allow", reason=reason, mode=mode,
        inputs_hash=inputs_hash, output_hash=sha256_text(output), fields_dropped=dropped,
        redactions=redactions, injection_flags=flags, artifact=artifact_id,
    )
    return result
