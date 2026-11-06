# AI skills with hard-set scopes (demo)

> **Synthetic data only.** Every name, ticket, host, setting and "user" in this repository is invented.
> This is a personal learning and demonstration project. It is not affiliated with, endorsed by, or
> representing any employer, agency or vendor, and it contains no real data.

## The 30-second version

AI assistants are only as safe as the limits around them. This repo shows two small "AI skills" for an
imaginary **Acme Service Desk**, each wrapped in rules that are **enforced by code, not by asking the AI nicely**:

| Rule | What it means in plain terms |
|---|---|
| **Least privilege** | Each skill has a one-page *scope manifest* listing the only fields it may see and the only place it may write. |
| **Default deny** | A skill with no manifest, or an empty one, gets no data at all. |
| **Fields it can't see are never sent** | Anything not on the allow-list is removed *before* the AI (or the code around it) ever receives it. |
| **Sensitive data stops at the door** | Emails, phone numbers, ticket numbers, hostnames, names are redacted. SSN-like text and pasted passwords cause the whole request to be refused. |
| **Dry run by default** | Nothing is saved unless you pass `--write`. |
| **A human approves** | Output lands in `pending_review/`. A *different* person with the approver role must move it to `approved/`. Authors can't approve their own work. |
| **Everything is logged** | An append-only audit log records who did what and the decision, with no ticket content in it. |
| **Tickets are data, not orders** | Text inside a ticket that says "ignore your rules and..." is stripped, logged, and could not have worked anyway. |

Everything runs **offline** with a deterministic stand-in for the AI model, so results are identical every time.

## 2-minute quickstart

Needs Python 3.12 or newer. One-time setup, from the repo folder:

```bash
python -m venv .venv && . .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Then one command each:

**1. Run the tests** (they prove the rules above):

```bash
python -m pytest
```

**2. Run the KB article demo** (a dry run: prints articles, writes nothing):

```bash
python -m scopeguard kb --user alex
```

**3. Run the GPO documenter demo** (read-only: documents, compares, reviews, drafts a change request):

```bash
python -m scopeguard gpo --user alex
```

**4. Approve an output.** First save drafts for review, then approve one as a different person:

```bash
python -m scopeguard kb --user alex --write
```

```bash
python -m scopeguard approve kb_article-1b6d69ae --user blake
```

(The id is printed by the previous command; it is derived from the content, so it is the same every time.)
Try approving as `alex` instead and watch it get refused. List what is waiting with `python -m scopeguard pending`.
Check the log has not been tampered with: `python -m scopeguard verify-audit`.

The invented people are in [`data/synthetic/users.toml`](data/synthetic/users.toml): `alex` (author), `blake` (approver),
`casey` (viewer), `dana` (both roles, to show nobody approves their own work).

## What you will see

The KB demo runs six made-up incidents through the same rules (summary condensed; the real command also prints each article):

```
[1/6] ALLOW  | dropped fields: asset_hostname, assigned_to, internal_comments, reporter_email, reporter_name, ...  | redacted: hostname x1
[2/6] ALLOW  | redacted: phone x1
[3/6] ALLOW  | redacted: email x1, person_name x1
[4/6] DENY   reason=forbidden_data:ssn          <- a ticket containing SSN-like text is refused outright
[5/6] ALLOW  | instruction-like sentences removed: 1   <- the fake "ignore your rules" ticket
[6/6] DENY   reason=forbidden_data:secret       <- a password pasted into a ticket is refused outright
```

### Sample of the audit log

One JSON line per decision (hashes shortened here). Note there is **no ticket text** in it, only codes, counts and field *names*:

```json
{"ts":"2026-11-06T17:23:47+00:00","actor":"alex","action":"run","skill":"kb_article","decision":"allow","reason":"ok","mode":"write",
 "inputs_hash":"fca41e99…","output_hash":"1b6d69ae…",
 "fields_dropped":["asset_hostname","assigned_to","internal_comments","reporter_email","reporter_name","reporter_phone","ticket_number"],
 "redactions":{"hostname":1},"injection_flags":0,"artifact":"kb_article-1b6d69ae","prev_hash":"0000…","entry_hash":"f5734a0c…"}

{"ts":"2026-11-06T17:23:47+00:00","actor":"alex","action":"run","skill":"kb_article","decision":"deny","reason":"forbidden_data:ssn","mode":"write",
 "inputs_hash":null,"fields_dropped":["reporter_name","ticket_number"],"redactions":{},"injection_flags":0,"prev_hash":"7029f3ab…","entry_hash":"301638c1…"}

{"ts":"2026-11-06T17:23:49+00:00","actor":"alex","action":"approve","skill":"gpo_documenter","decision":"deny","reason":"role_not_permitted",
 "mode":"write","artifact":"gpo_documenter-e245cf4b","prev_hash":"46c2bcaf…","entry_hash":"74d7db9c…"}

{"ts":"2026-11-06T17:23:49+00:00","actor":"blake","action":"approve","skill":"gpo_documenter","decision":"allow","reason":"ok",
 "mode":"write","artifact":"gpo_documenter-e245cf4b","prev_hash":"74d7db9c…","entry_hash":"fc10033a…"}
```

Each entry includes the hash of the one before it, so editing or removing a line is detectable (`verify-audit`).

## The two skills

**1. KB article generator.** Takes a resolved incident and fills a fixed article template (title, symptoms, cause, resolution
steps, notes). Only six fields are allowed in. The reporter's name, email, phone, the machine name and the ticket number are
dropped before anything else happens. Drafts wait in `pending_review/`.

**2. GPO documenter. Read-only and assist-only.** Takes simplified Group Policy exports and can:
describe a GPO in plain language, explain what changed between two exports, flag duplicate / conflicting / possibly stale
settings, and draft a change-request write-up with a test checklist and rollback plan.
**It never applies changes and has no write path to Active Directory or any admin tool.** It is a tool for the GPO owner,
not a replacement for them: every output is a draft for a person to review and edit.

## Where each rule lives, and the test that proves it

| Rule | Code | Test |
|---|---|---|
| Field allow-list | [`fields.py`](src/scopeguard/fields.py) | [`test_scope_enforcement.py`](tests/test_scope_enforcement.py) |
| Redact / reject sensitive patterns | [`scrubber.py`](src/scopeguard/scrubber.py) | [`test_scope_enforcement.py`](tests/test_scope_enforcement.py) |
| Default deny, manifest validation | [`manifest.py`](src/scopeguard/manifest.py), [`guard.py`](src/scopeguard/guard.py) | [`test_scope_enforcement.py`](tests/test_scope_enforcement.py) |
| Dry run, explicit write, approval gate, no self-approval | [`approval.py`](src/scopeguard/approval.py) | [`test_approval_gate.py`](tests/test_approval_gate.py) |
| Audit log (allow and deny, no sensitive values) | [`audit.py`](src/scopeguard/audit.py) | [`test_audit_log.py`](tests/test_audit_log.py) |
| Prompt-injection handling | [`injection.py`](src/scopeguard/injection.py) | [`test_prompt_injection.py`](tests/test_prompt_injection.py) |
| GPO tool cannot modify anything | [`skills/`](src/scopeguard/skills/) | [`test_skills_are_pure.py`](tests/test_skills_are_pure.py), [`test_gpo_documenter.py`](tests/test_gpo_documenter.py) |

The order of checks for every run is written out at the top of [`guard.py`](src/scopeguard/guard.py).
A scope manifest looks like this (full versions in [`manifests/`](manifests/)):

```toml
[access]
allowed_roles  = ["author"]
allowed_inputs = ["category", "short_description", "symptoms", "cause", "resolution_steps", "notes"]

[forbidden]
redact = ["email", "phone", "case_number", "hostname", "ip_address", "person_name"]
reject = ["ssn", "secret"]

[writes]
targets           = ["pending_review"]
requires_approval = true
```

## What this does NOT do

Being clear about limits matters more than the feature list:

- **It is a demo, not a product.** It has not been security-reviewed or pen-tested and is not production software.
- **No real AI model is used.** A deterministic template filler stands in for the model. An optional adapter file shows where a real model
  would plug in; it is switched off, contains no network code, and never reads or stores API keys.
- **The scrubber is a safety net, not a guarantee.** Pattern matching misses things, names especially. The field allow-list is the main control.
- **The injection filter is a tripwire.** A cleverly worded attack can get past it. The real protection is structural: skills can't touch files,
  the network or other skills, so text can only change words inside a fixed template, and a person reviews the result.
- **The user list is a text file.** Real deployments use a proper identity provider with sign-in, MFA and conditional rules.
- **The audit log is tamper-evident, not tamper-proof.** Anyone who controls the file can rewrite the whole chain. Real logs are shipped somewhere operators can't edit.
- **It does not connect to any real system.** No Active Directory, no ticketing system, no Microsoft 365, no cloud services. Inputs are local JSON files.
- **It makes no compliance claims.** The ideas are *inspired by* common least-privilege and audit practices. Nothing here has been assessed against any framework.
- **GPO exports here are simplified and invented.** They are not the format of real exports.

## More reading

- [`docs/scoping-checklist.md`](docs/scoping-checklist.md): a one-page checklist for scoping any AI skill before building it.
- [`docs/threat-model.md`](docs/threat-model.md): the four main risks and how each is handled (and where it isn't).
- [`docs/mapping.md`](docs/mapping.md): how these concepts line up conceptually with enterprise platforms. Unverified, labelled as such.

## Layout

```
manifests/            one scope manifest per skill (the permission sets)
src/scopeguard/       the shared core: manifest, fields, scrubber, injection, roles, approval, audit, guard, CLI
src/scopeguard/skills/  the two skills (pure functions, no I/O)
data/synthetic/       invented incidents, GPO exports and users
tests/                pytest suite proving each rule
docs/                 checklist, threat model, conceptual mapping
```

## License

MIT. See [LICENSE](LICENSE). Synthetic data only; no warranty.
