"""Proves: the audit log records allow AND deny, and never holds raw sensitive values."""

import json

import pytest

from helpers import INCIDENTS, REPO, read_audit
from scopeguard.approval import approve
from scopeguard.audit import AuditLog
from scopeguard.guard import Skill, run_skill
from scopeguard.skills import kb_article

KB = Skill(kb_article.NAME, kb_article.run)

# Values that appear in the synthetic data and must NEVER show up in the log.
SENSITIVE = [
    "riley.example", "Riley Example", "555-0142", "555-0187", "ACME-LT-0417", "ACME-DT-0233",
    "987-65-4321", "Winter2025Demo", "INC0099001", "INC0099004", "Taylor Example",
    "avery.example", "helpdesk@", "Casey Placeholder", "Sam Sample", "Jordan Placeholder",
]


def test_audit_is_written_for_allow_and_for_deny(settings):
    run_skill(KB, {"record": INCIDENTS[1]}, "alex", settings)  # allowed
    run_skill(KB, {"record": INCIDENTS[1]}, "casey", settings)  # denied: viewer
    run_skill(KB, {"record": INCIDENTS[3]}, "alex", settings)  # denied: SSN-like text

    entries = read_audit(settings)
    assert [(e["actor"], e["decision"], e["reason"]) for e in entries] == [
        ("alex", "allow", "ok"),
        ("casey", "deny", "role_not_permitted"),
        ("alex", "deny", "forbidden_data:ssn"),
    ]
    assert all(e["skill"] == "kb_article" and e["action"] == "run" for e in entries)


def test_audit_never_contains_raw_sensitive_values(settings):
    """Run every synthetic incident (clean, redacted, rejected, injected) and then search the whole log."""
    for record in INCIDENTS:
        run_skill(KB, {"record": record}, "alex", settings, write=True)
    run_skill(KB, {"record": INCIDENTS[0]}, "casey", settings)
    approve(settings, "kb_article-deadbeef", "blake")

    log_text = settings.audit_log.read_text(encoding="utf-8")
    assert len(read_audit(settings)) >= 8
    for value in SENSITIVE:
        assert value not in log_text, f"{value!r} leaked into the audit log"
    # nor any of the ticket wording itself
    assert "VPN disconnects" not in log_text and "spooler" not in log_text


def test_entries_hold_hashes_and_counts_instead_of_content(settings):
    run_skill(KB, {"record": INCIDENTS[0]}, "alex", settings, write=True)
    entry = read_audit(settings)[0]
    assert len(entry["inputs_hash"]) == 64 and len(entry["output_hash"]) == 64
    assert entry["redactions"] == {"hostname": 1}
    assert "reporter_email" in entry["fields_dropped"]  # the NAME of a dropped field, not its value
    assert set(entry) == {
        "ts", "actor", "action", "skill", "decision", "reason", "mode", "inputs_hash", "output_hash",
        "fields_dropped", "redactions", "injection_flags", "artifact", "prev_hash", "entry_hash",
    }


def test_the_log_refuses_free_text_and_unknown_fields(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError):
        log.record(actor="alex", reason="x" * 500)  # too long to be a code
    with pytest.raises(ValueError):
        log.record(actor="alex", ticket_text="hello")  # not an allowed field
    with pytest.raises(ValueError):
        log.record(actor="alex", redactions={"email": "pat@example.test"})  # counts only
    assert not (tmp_path / "audit.jsonl").exists()


def test_log_exposes_only_record_and_verify():
    public = {name for name in dir(AuditLog) if not name.startswith("_")}
    assert public == {"record", "verify"}  # no delete, rewrite or truncate method


def test_hash_chain_detects_edits_and_deletions(settings):
    for _ in range(3):
        run_skill(KB, {"record": INCIDENTS[1]}, "alex", settings)
    log = AuditLog(settings.audit_log)
    assert log.verify() == (True, "audit chain intact")

    lines = settings.audit_log.read_text(encoding="utf-8").splitlines()

    edited = [json.loads(line) for line in lines]
    edited[1]["decision"] = "deny"
    settings.audit_log.write_text("\n".join(json.dumps(e) for e in edited) + "\n", encoding="utf-8")
    ok, message = log.verify()
    assert not ok and "line 2" in message

    settings.audit_log.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")  # middle entry removed
    ok, message = log.verify()
    assert not ok and "chain broken" in message
