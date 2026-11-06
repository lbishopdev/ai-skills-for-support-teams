"""Proves: scope is enforced in code. Out-of-scope data never reaches a skill."""

import pytest

from helpers import SpySkill, manifest_toml
from scopeguard.fields import filter_fields
from scopeguard.guard import Skill, run_skill
from scopeguard.scrubber import KNOWN_CLASSES, scrub


def run(settings, spy, record, user="alex", write=False):
    return run_skill(spy.skill, {"record": record}, user, settings, write=write)


# ---- field allow-list ----------------------------------------------------------------------------

def test_out_of_scope_field_is_dropped_before_the_skill_sees_it(spy_settings):
    spy = SpySkill()
    record = {"note": "printer is jammed", "reporter_email": "pat@example.test", "internal_comments": "secret stuff"}

    result = run(spy_settings, spy, record)

    assert result.decision == "allow"
    assert spy.calls == [{"record": {"note": "printer is jammed"}}]  # nothing else got through
    assert result.fields_dropped == ["internal_comments", "reporter_email"]  # names only, never values


def test_nested_allow_list_uses_dotted_paths():
    dropped = set()
    data = {"name": "x", "secret_owner": "y", "settings": [{"name": "a", "modified_by": "z"}, {"name": "b"}]}
    kept = filter_fields(data, frozenset({"name", "settings.name"}), dropped)
    assert kept == {"name": "x", "settings": [{"name": "a"}, {"name": "b"}]}
    assert dropped == {"secret_owner", "settings.modified_by"}


def test_a_container_is_dropped_whole_if_nothing_inside_is_allowed():
    dropped = set()
    kept = filter_fields({"note": "ok", "extra": {"a": 1}, "more": [{"b": 2}]}, frozenset({"note"}), dropped)
    assert kept == {"note": "ok"}
    assert dropped == {"extra", "more"}


# ---- scrubbing -----------------------------------------------------------------------------------

def test_redactable_patterns_are_replaced_with_markers(spy_settings):
    spy = SpySkill()
    note = "Mail pat@example.test or call 555-0100 about host ACME-LT-0417, ticket INC0012345, ip 10.1.2.3."

    result = run(spy_settings, spy, {"note": note})

    seen = spy.calls[0]["record"]["note"]
    assert result.decision == "allow"
    for raw in ("pat@example.test", "555-0100", "ACME-LT-0417", "INC0012345", "10.1.2.3"):
        assert raw not in seen
    assert seen.count("[REDACTED:") == 5
    assert result.redactions == {"email": 1, "phone": 1, "hostname": 1, "case_number": 1, "ip_address": 1}


def test_name_after_a_trigger_phrase_is_redacted_but_the_phrase_stays(spy_settings):
    spy = SpySkill()
    run(spy_settings, spy, {"note": "Reported by Riley Example, fixed same day."})
    assert spy.calls[0]["record"]["note"] == "Reported by [REDACTED:person_name], fixed same day."


@pytest.mark.parametrize(
    "text, expected_reason",
    [
        ("Caller read out 987-65-4321.", "forbidden_data:ssn"),
        ("Use password=Winter2025Demo to join.", "forbidden_data:secret"),
        ("api_key: abc123", "forbidden_data:secret"),
    ],
)
def test_reject_class_refuses_the_whole_request(spy_settings, text, expected_reason):
    spy = SpySkill()
    result = run(spy_settings, spy, {"note": text})
    assert (result.decision, result.reason) == ("deny", expected_reason)
    assert spy.calls == []  # the skill was never called


SAMPLES = {
    "ssn": "987-65-4321",
    "secret": "password=abc",
    "email": "pat@example.test",
    "case_number": "INC0012345",
    "hostname": "ACME-LT-0417",
    "ip_address": "10.1.2.3",
    "phone": "(555) 010-1234",
    "person_name": "Requested by Pat Example",
}


@pytest.mark.parametrize("cls", sorted(KNOWN_CLASSES))
def test_every_known_class_is_enforced(make_settings, cls):
    """With nothing marked 'redact', every class must be a rejection (default is reject)."""
    settings = make_settings(spy_skill=manifest_toml(redact="[]", reject="[]"))
    spy = SpySkill()
    result = run(settings, spy, {"note": f"text {SAMPLES[cls]} text"})
    assert result.decision == "deny"
    assert cls in result.reason
    assert spy.calls == []


def test_literal_deny_terms_reject(make_settings):
    settings = make_settings(spy_skill=manifest_toml(deny_terms='["project nightingale"]'))
    spy = SpySkill()
    result = run(settings, spy, {"note": "Related to Project Nightingale rollout."})
    assert (result.decision, result.reason) == ("deny", "forbidden_data:deny_term")
    assert spy.calls == []


def test_ordinary_gpo_and_it_wording_is_not_flagged():
    text = "User Configuration Policies apply. Computer Configuration/Administrative Templates. Set to 600 seconds on 2025-06-01."
    clean, redactions, rejected = scrub(text, KNOWN_CLASSES)
    assert clean == text and not redactions and not rejected


# ---- default deny --------------------------------------------------------------------------------

def test_skill_without_a_manifest_gets_no_data(make_settings):
    settings = make_settings()  # no manifests at all
    spy = SpySkill(name="unregistered_skill")

    result = run(settings, spy, {"note": "anything"})

    assert (result.decision, result.reason) == ("deny", "no_manifest")
    assert spy.calls == []


def test_manifest_with_empty_allow_list_grants_no_data(make_settings):
    settings = make_settings(spy_skill=manifest_toml(inputs="[]"))
    spy = SpySkill()
    result = run(settings, spy, {"note": "anything"})
    assert (result.decision, result.reason) == ("deny", "no_inputs_granted")
    assert spy.calls == []


@pytest.mark.parametrize(
    "bad_manifest",
    [
        manifest_toml(redact='["email", "made_up_class"]'),  # unknown data class
        manifest_toml(redact='["email"]', reject='["email"]'),  # contradictory
        manifest_toml(logging="false"),  # logging cannot be switched off
        manifest_toml(approval="false"),  # writing without approval is not supported
        manifest_toml(targets='["approved"]'),  # unknown write target
        manifest_toml(roles='["superuser"]'),  # unknown role
        manifest_toml(name="some_other_name"),  # name must match file
        manifest_toml(extra="[surprise]\nkey = 1"),  # unknown section (typo protection)
    ],
)
def test_malformed_manifest_means_deny(make_settings, bad_manifest):
    settings = make_settings(spy_skill=bad_manifest)
    spy = SpySkill()
    result = run(settings, spy, {"note": "hello"})
    assert (result.decision, result.reason) == ("deny", "invalid_manifest")
    assert spy.calls == []


# ---- who may run ---------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "user, reason",
    [("nobody", "unknown_user"), ("casey", "role_not_permitted"), ("blake", "role_not_permitted"), ("../etc", "unknown_user")],
)
def test_only_authors_can_run_a_skill(spy_settings, user, reason):
    spy = SpySkill()
    result = run(spy_settings, spy, {"note": "hello"}, user=user)
    assert (result.decision, result.reason) == ("deny", reason)
    assert spy.calls == []


def test_manifest_can_be_stricter_than_the_role_table(make_settings):
    settings = make_settings(spy_skill=manifest_toml(roles='["approver"]'))
    spy = SpySkill()
    result = run(settings, spy, {"note": "hello"}, user="alex")  # alex is an author, but the manifest says approvers only
    assert (result.decision, result.reason) == ("deny", "role_not_permitted")


# ---- fail closed ---------------------------------------------------------------------------------

def test_output_is_scrubbed_too_and_a_leak_is_denied(spy_settings):
    spy = SpySkill(output="Contact bob@example.test for details.")  # a misbehaving skill/model
    result = run(spy_settings, spy, {"note": "hello"}, write=True)
    assert (result.decision, result.reason) == ("deny", "output_violation")
    assert not spy_settings.pending_dir.exists()  # nothing was written


def test_a_crashing_skill_fails_closed_without_leaking_its_message(spy_settings):
    def boom(inputs, model):
        raise RuntimeError("pat@example.test exploded")

    result = run_skill(Skill("spy_skill", boom), {"record": {"note": "hi"}}, "alex", spy_settings)
    assert (result.decision, result.reason) == ("deny", "skill_error:RuntimeError")
    assert "pat@example" not in str(result)


def test_non_dict_input_is_refused(spy_settings):
    result = run_skill(SpySkill().skill, {"record": "just a string"}, "alex", spy_settings)
    assert (result.decision, result.reason) == ("deny", "bad_input_shape")
