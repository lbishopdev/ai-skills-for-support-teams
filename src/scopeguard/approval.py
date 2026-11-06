"""The approval gate: pending_review/ -> approved/.

Skills can only ever write into pending_review/. Only `approve()` moves a file
into approved/, and it refuses when:

  - the approver does not hold the approver role
  - the approver is the person who created the output (no self-approval)
  - the file changed after it was written (hash no longer matches)

Every attempt, allowed or denied, is written to the audit log.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLog
from .roles import can, load_actor, safe_actor_name
from .settings import Settings

ID_PATTERN = re.compile(r"[a-z0-9_]+-[0-9a-f]{8}")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_pending(settings: Settings, skill_name: str, output: str, author: str, inputs_hash: str) -> tuple[str, bool]:
    """Write an output into pending_review/. Returns (artifact_id, newly_created).

    The id comes from the content hash, so re-running with identical output is a
    no-op and never overwrites anything.
    """
    content_hash = sha256_text(output)
    artifact_id = f"{skill_name}-{content_hash[:8]}"
    settings.pending_dir.mkdir(parents=True, exist_ok=True)
    document = settings.pending_dir / f"{artifact_id}.md"
    approved_document = settings.approved_dir / f"{artifact_id}.md"
    if document.exists() or approved_document.exists():
        return artifact_id, False
    document.write_text(output, encoding="utf-8", newline="\n")
    _write_json(
        settings.pending_dir / f"{artifact_id}.meta.json",
        {
            "artifact_id": artifact_id,
            "skill": skill_name,
            "status": "pending",
            "created_by": author,
            "created_at": _now(),
            "content_sha256": content_hash,
            "inputs_sha256": inputs_hash,
        },
    )
    return artifact_id, True


def list_pending(settings: Settings) -> list[dict]:
    if not settings.pending_dir.exists():
        return []
    items = []
    for meta_path in sorted(settings.pending_dir.glob("*.meta.json")):
        try:
            items.append(json.loads(meta_path.read_text(encoding="utf-8")))
        except ValueError:
            continue
    return items


@dataclass
class ApprovalResult:
    decision: str  # "allow" or "deny"
    reason: str
    artifact_id: str


def approve(settings: Settings, artifact_id: str, approver_name: str) -> ApprovalResult:
    log = AuditLog(settings.audit_log)
    approver_id = safe_actor_name(approver_name)
    valid_id = bool(ID_PATTERN.fullmatch(artifact_id))
    skill_name = artifact_id.rsplit("-", 1)[0] if valid_id else "unknown"

    def finish(decision: str, reason: str) -> ApprovalResult:
        log.record(
            actor=approver_id,
            action="approve",
            skill=skill_name,
            decision=decision,
            reason=reason,
            mode="write",
            artifact=artifact_id if valid_id else None,
        )
        return ApprovalResult(decision, reason, artifact_id)

    if not valid_id:
        return finish("deny", "invalid_artifact_id")  # also blocks path tricks like ../

    actor = load_actor(settings.users_file, approver_name)
    if actor is None:
        return finish("deny", "unknown_user")
    if not can(actor, "approve"):
        return finish("deny", "role_not_permitted")

    document = settings.pending_dir / f"{artifact_id}.md"
    meta_path = settings.pending_dir / f"{artifact_id}.meta.json"
    if not document.is_file() or not meta_path.is_file():
        return finish("deny", "not_found")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except ValueError:
        return finish("deny", "metadata_unreadable")

    if meta.get("created_by") == actor.name:
        return finish("deny", "self_approval_not_allowed")
    if sha256_text(document.read_bytes().decode("utf-8")) != meta.get("content_sha256"):
        return finish("deny", "content_changed_since_creation")

    settings.approved_dir.mkdir(parents=True, exist_ok=True)
    os.replace(document, settings.approved_dir / f"{artifact_id}.md")
    meta.update(status="approved", approved_by=actor.name, approved_at=_now())
    _write_json(settings.approved_dir / f"{artifact_id}.meta.json", meta)
    meta_path.unlink()
    return finish("allow", "ok")
