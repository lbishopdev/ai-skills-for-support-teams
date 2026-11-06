"""Shared test helpers. Everything here is synthetic."""

from __future__ import annotations

import json
from pathlib import Path

from scopeguard.guard import Skill
from scopeguard.settings import Settings

REPO = Path(__file__).resolve().parents[1]
INCIDENTS = json.loads((REPO / "data" / "synthetic" / "incidents.json").read_text(encoding="utf-8"))
GPO_DIR = REPO / "data" / "synthetic" / "gpo"


def manifest_toml(
    name: str = "spy_skill",
    roles: str = '["author"]',
    inputs: str = '["note"]',
    redact: str = '["email", "phone", "case_number", "hostname", "ip_address", "person_name"]',
    reject: str = '["ssn", "secret"]',
    deny_terms: str = "[]",
    targets: str = '["pending_review"]',
    approval: str = "true",
    logging: str = "true",
    extra: str = "",
) -> str:
    """Build a manifest for a test skill, with knobs for the things tests want to break."""
    return f"""\
[skill]
name = "{name}"
purpose = "Test skill."

[access]
allowed_roles = {roles}
allowed_inputs = {inputs}

[forbidden]
redact = {redact}
reject = {reject}
deny_terms = {deny_terms}

[writes]
targets = {targets}
forbidden = ["approved"]
requires_approval = {approval}

[output]
template = "test"

[audit]
logging = {logging}
{extra}
"""


class SpySkill:
    """A skill that records exactly what the guard handed it."""

    def __init__(self, name: str = "spy_skill", output: str = "spy output"):
        self.name = name
        self.output = output
        self.calls: list[dict] = []

    def run(self, inputs, model):
        self.calls.append(inputs)
        return self.output

    @property
    def skill(self) -> Skill:
        return Skill(self.name, self.run)


def read_audit(settings: Settings) -> list[dict]:
    if not settings.audit_log.exists():
        return []
    return [json.loads(line) for line in settings.audit_log.read_text(encoding="utf-8").splitlines()]
