"""GPO documenter: useful analysis, and provably read-only."""

import hashlib
import json
from functools import partial

import pytest

from helpers import GPO_DIR, REPO
from scopeguard.guard import Skill, run_skill
from scopeguard.manifest import load_manifest
from scopeguard.model import MockModel
from scopeguard.skills import gpo_documenter as gpo

V1 = json.loads((GPO_DIR / "acme-workstation-baseline-v1.json").read_text(encoding="utf-8"))
V2 = json.loads((GPO_DIR / "acme-workstation-baseline-v2.json").read_text(encoding="utf-8"))


def skill(mode):
    return Skill(gpo.NAME, partial(gpo.run, mode=mode))


def run_mode(settings, mode, write=False):
    return run_skill(skill(mode), {"old": V1, "new": V2}, "alex", settings, write=write)


# ---- analysis ----------------------------------------------------------------------------------

def test_diff_finds_added_removed_and_changed_settings():
    changes = {(c.kind, c.name): c for c in gpo.compute_diff(V1, V2)}
    assert set(changes) == {
        ("changed", "Minimum password length"),
        ("changed", "Interactive logon: Machine inactivity limit"),
        ("changed", "Screen saver timeout"),
        ("added", "Windows Firewall: Protect all network connections"),
        ("removed", "All Removable Storage classes: Deny all access"),
    }
    password = changes[("changed", "Minimum password length")]
    assert (password.before, password.after, password.security_relevant) == (
        "Enabled (12 characters)", "Enabled (14 characters)", True,
    )
    assert changes[("changed", "Screen saver timeout")].security_relevant is False


def test_findings_flag_duplicates_conflicts_and_stale_settings():
    findings = gpo.compute_findings(V2)
    by_kind = {kind: [name for k, name, _ in findings if k == kind] for kind in ("duplicate", "conflict", "stale")}
    assert by_kind["duplicate"] == ["Configure Automatic Updates"]
    assert by_kind["conflict"] == ["Screen saver timeout"]
    assert sorted(by_kind["stale"]) == ["Allow standby states (S1-S3) when sleeping (plugged in)", "Point and Print Restrictions"]


def test_a_bad_date_is_reported_not_crashed_on():
    broken = {"exported_on": "not-a-date", "settings": []}
    assert gpo.compute_findings(broken)[0][0] == "unreadable_date"


def test_documentation_is_plain_language_and_explains_tricky_settings(settings):
    output = run_mode(settings, "document").output
    assert "Minimum password length** is set to Enabled with value '14 characters'" in output
    assert "Defender is NOT being turned off" in output  # "Turn off X" set to Disabled is a classic trap


def test_change_request_is_a_draft_with_checklist_and_rollback(settings):
    output = run_mode(settings, "change-request").output
    for expected in ("DRAFT change request", "Nothing here has been submitted or applied", "### Test checklist",
                     "gpresult /r", "### Rollback plan", "Restore the GPO backup", "remove this setting",
                     "Approvals (to be completed by people, not by this tool)"):
        assert expected in output


@pytest.mark.parametrize("mode, heading", [
    ("document", "## Plain-language documentation"),
    ("diff", "## Differences: version 1 -> version 2"),
    ("findings", "## Findings for"),
    ("change-request", "## DRAFT change request"),
])
def test_each_mode_produces_only_its_own_section(settings, mode, heading):
    output = run_mode(settings, mode).output
    sections = [h for h in ("## Plain-language", "## Differences", "## Findings", "## DRAFT change request") if h in output]
    assert heading.startswith(sections[0]) and len(sections) == 1


def test_all_mode_includes_every_section(settings):
    output = run_mode(settings, "all").output
    for heading in ("## Plain-language", "## Differences", "## Findings", "## DRAFT change request"):
        assert heading in output


def test_diff_without_an_old_export_fails_closed(settings):
    result = run_skill(skill("diff"), {"new": V2}, "alex", settings)
    assert (result.decision, result.reason) == ("deny", "skill_error:ValueError")


def test_sensitive_fields_in_the_export_are_dropped_or_redacted(settings):
    result = run_mode(settings, "all")
    assert {"domain", "delegation", "settings.modified_by"} <= set(result.fields_dropped)
    for raw in ("acme-demo.test", "sam.sample", "Acme-GPO-Editors", "Taylor Placeholder", "CHG0010443", "ACME-WS-0042"):
        assert raw not in result.output
    assert result.redactions == {"case_number": 1, "hostname": 1, "person_name": 1}


# ---- read-only by construction -------------------------------------------------------------------

def snapshot(folder):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob("*.json"))}


def test_running_every_mode_with_write_does_not_modify_the_input_files(settings):
    before = snapshot(GPO_DIR)
    for mode in gpo.MODES:
        result = run_mode(settings, mode, write=True)
        assert result.decision == "allow"
    assert snapshot(GPO_DIR) == before  # inputs untouched, byte for byte


def test_the_only_things_ever_created_are_review_drafts_and_the_audit_log(settings):
    for mode in gpo.MODES:
        run_mode(settings, mode, write=True)
    created = {p.relative_to(settings.output_dir).parts[0] for p in settings.output_dir.rglob("*") if p.is_file()}
    assert created == {"pending_review", "audit"}  # no approved/, nothing else
    assert not settings.approved_dir.exists()


def test_the_manifest_grants_no_path_to_ad_or_dra():
    manifest = load_manifest("gpo_documenter", REPO / "manifests")
    assert manifest.write_targets == ("pending_review",)
    assert {"active_directory", "dra", "gpo_objects", "input_files"} <= set(manifest.forbidden_writes)
    assert manifest.requires_approval is True


def test_the_skill_is_a_pure_function_of_its_input():
    """Same data in, same text out, and the input dictionaries are left exactly as they were."""
    import copy
    old, new = copy.deepcopy(V1), copy.deepcopy(V2)
    first = gpo.run({"old": old, "new": new}, MockModel())
    second = gpo.run({"old": old, "new": new}, MockModel())
    assert first == second
    assert old == V1 and new == V2
