"""Proves: dry-run by default, writes need an explicit flag, nothing publishes without approval."""

import json

import pytest

from helpers import INCIDENTS, SpySkill, manifest_toml, read_audit
from scopeguard.approval import approve, list_pending
from scopeguard.guard import Skill, run_skill
from scopeguard.skills import kb_article

KB = Skill(kb_article.NAME, kb_article.run)
CLEAN_INCIDENT = INCIDENTS[1]


def write_one(settings, user="alex"):
    result = run_skill(KB, {"record": CLEAN_INCIDENT}, user, settings, write=True)
    assert result.decision == "allow" and result.written
    return result.artifact_id


# ---- dry run is the default ------------------------------------------------------------------------

def test_dry_run_writes_no_output_files(settings):
    result = run_skill(KB, {"record": CLEAN_INCIDENT}, "alex", settings)  # write defaults to False
    assert result.decision == "allow" and result.output
    assert result.written is False and result.artifact_id is None
    assert not settings.pending_dir.exists()
    assert not settings.approved_dir.exists()


def test_write_is_refused_when_the_manifest_grants_no_write_target(make_settings):
    settings = make_settings(spy_skill=manifest_toml(targets="[]"))
    result = run_skill(SpySkill().skill, {"record": {"note": "hi"}}, "alex", settings, write=True)
    assert (result.decision, result.reason) == ("deny", "write_not_granted")
    assert not settings.pending_dir.exists()


def test_the_write_flag_lands_in_pending_review_only(settings):
    artifact_id = write_one(settings)
    assert (settings.pending_dir / f"{artifact_id}.md").is_file()
    assert not settings.approved_dir.exists()  # nothing is published
    meta = json.loads((settings.pending_dir / f"{artifact_id}.meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "pending" and meta["created_by"] == "alex"


def test_rerunning_with_identical_output_never_overwrites(settings):
    first = write_one(settings)
    again = run_skill(KB, {"record": CLEAN_INCIDENT}, "alex", settings, write=True)
    assert again.artifact_id == first and again.written is False and again.reason == "already_exists"
    assert len(list_pending(settings)) == 1


# ---- approval ------------------------------------------------------------------------------------

def test_approval_moves_the_file_and_records_who_approved(settings):
    artifact_id = write_one(settings)

    result = approve(settings, artifact_id, "blake")

    assert (result.decision, result.reason) == ("allow", "ok")
    assert (settings.approved_dir / f"{artifact_id}.md").is_file()
    assert not (settings.pending_dir / f"{artifact_id}.md").exists()
    meta = json.loads((settings.approved_dir / f"{artifact_id}.meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "approved" and meta["approved_by"] == "blake" and meta["created_by"] == "alex"


@pytest.mark.parametrize("user, reason", [("alex", "role_not_permitted"), ("casey", "role_not_permitted"), ("nobody", "unknown_user")])
def test_only_approvers_can_approve(settings, user, reason):
    artifact_id = write_one(settings)
    result = approve(settings, artifact_id, user)
    assert (result.decision, result.reason) == ("deny", reason)
    assert (settings.pending_dir / f"{artifact_id}.md").is_file()  # still pending
    assert not settings.approved_dir.exists()


def test_author_cannot_approve_their_own_output(settings):
    """dana holds BOTH roles. Having the approver role is not enough: she wrote it, so she cannot approve it."""
    artifact_id = write_one(settings, user="dana")

    own = approve(settings, artifact_id, "dana")
    assert (own.decision, own.reason) == ("deny", "self_approval_not_allowed")
    assert (settings.pending_dir / f"{artifact_id}.md").is_file()

    other = approve(settings, artifact_id, "blake")
    assert other.decision == "allow"


def test_a_file_edited_after_creation_cannot_be_approved(settings):
    artifact_id = write_one(settings)
    document = settings.pending_dir / f"{artifact_id}.md"
    document.write_text(document.read_text(encoding="utf-8") + "\nSneaky edit.\n", encoding="utf-8")

    result = approve(settings, artifact_id, "blake")

    assert (result.decision, result.reason) == ("deny", "content_changed_since_creation")
    assert not settings.approved_dir.exists()


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "kb_article-ZZZZZZZZ", "", "kb_article", "x/y-12345678"])
def test_artifact_ids_cannot_be_used_for_path_tricks(settings, bad_id):
    result = approve(settings, bad_id, "blake")
    assert (result.decision, result.reason) == ("deny", "invalid_artifact_id")


def test_approving_something_that_is_not_pending_is_denied(settings):
    result = approve(settings, "kb_article-deadbeef", "blake")
    assert (result.decision, result.reason) == ("deny", "not_found")


def test_a_second_approval_is_denied_because_it_is_no_longer_pending(settings):
    artifact_id = write_one(settings)
    approve(settings, artifact_id, "blake")
    again = approve(settings, artifact_id, "blake")
    assert (again.decision, again.reason) == ("deny", "not_found")


def test_every_approval_attempt_is_audited(settings):
    artifact_id = write_one(settings)
    approve(settings, artifact_id, "alex")  # denied
    approve(settings, artifact_id, "blake")  # allowed
    outcomes = [(e["actor"], e["decision"], e["reason"]) for e in read_audit(settings) if e["action"] == "approve"]
    assert outcomes == [("alex", "deny", "role_not_permitted"), ("blake", "allow", "ok")]
