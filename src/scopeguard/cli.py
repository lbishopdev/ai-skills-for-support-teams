"""Command line for the demos.

  python -m scopeguard kb       --user alex [--write]
  python -m scopeguard gpo      --user alex [--mode all] [--write]
  python -m scopeguard pending
  python -m scopeguard approve  <id> --user blake
  python -m scopeguard verify-audit

Dry run is the default. Nothing is written to pending_review/ without --write.
(The audit log is always appended to, even on a dry run: that is the point of it.)
"""

from __future__ import annotations

import argparse
import functools
import json
import sys
from pathlib import Path
from typing import Any

from .approval import approve, list_pending
from .audit import AuditLog
from .guard import RunResult, Skill, run_skill
from .llm_adapter import LLMAdapter
from .model import MockModel
from .settings import Settings
from .skills import gpo_documenter, kb_article

MAX_INPUT_BYTES = 1_000_000
# Denials that mean "you may not use this skill", as opposed to "this record was unsafe".
SYSTEMIC_DENIALS = {"unknown_user", "role_not_permitted", "no_manifest", "invalid_manifest", "write_not_granted", "no_inputs_granted"}


def load_json(path: Path) -> Any:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise SystemExit(f"error: {path.name} is larger than {MAX_INPUT_BYTES} bytes")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SystemExit(f"error: {path.name} is not valid JSON ({exc.__class__.__name__})")


def _describe(result: RunResult) -> str:
    if result.decision == "deny":
        return f"DENY   reason={result.reason}"
    bits = [f"ALLOW  {'written' if result.written else 'dry-run'}"]
    if result.fields_dropped:
        bits.append(f"dropped fields: {', '.join(result.fields_dropped)}")
    if result.redactions:
        bits.append("redacted: " + ", ".join(f"{k}x{v}" for k, v in sorted(result.redactions.items())))
    if result.injection_flags:
        bits.append(f"instruction-like sentences removed: {result.injection_flags}")
    return "  |  ".join(bits)


def _report(label: str, result: RunResult, settings: Settings) -> None:
    print(f"{label}: {_describe(result)}")
    if result.decision == "allow" and result.output and not result.written and result.reason != "already_exists":
        print("-" * 60)
        print(result.output.rstrip())
        print("-" * 60)
    if result.artifact_id:
        status = "already existed, left untouched" if not result.written else "written"
        print(f"    -> pending_review/{result.artifact_id}.md ({status})")
        print(f"    next: python -m scopeguard approve {result.artifact_id} --user blake")


def _model(name: str):
    return LLMAdapter() if name == "llm" else MockModel()


def cmd_kb(args: argparse.Namespace, settings: Settings) -> int:
    path = Path(args.input) if args.input else settings.repo_root / "data" / "synthetic" / "incidents.json"
    records = load_json(path)
    if not isinstance(records, list):
        raise SystemExit("error: incident file must contain a JSON list")
    skill = Skill(kb_article.NAME, kb_article.run)
    exit_code = 0
    for number, record in enumerate(records, start=1):
        result = run_skill(skill, {"record": record}, args.user, settings, write=args.write, model=_model(args.model))
        _report(f"[{number}/{len(records)}] incident", result, settings)
        if result.reason in SYSTEMIC_DENIALS:
            exit_code = 1
            break  # same answer for every record; do not repeat it
    return exit_code


def cmd_gpo(args: argparse.Namespace, settings: Settings) -> int:
    gpo_dir = settings.repo_root / "data" / "synthetic" / "gpo"
    old_path = Path(args.old) if args.old else gpo_dir / "acme-workstation-baseline-v1.json"
    new_path = Path(args.new) if args.new else gpo_dir / "acme-workstation-baseline-v2.json"
    inputs = {"new": load_json(new_path)}
    if args.mode in ("diff", "change-request", "all"):
        inputs["old"] = load_json(old_path)
    skill = Skill(gpo_documenter.NAME, functools.partial(gpo_documenter.run, mode=args.mode))
    result = run_skill(skill, inputs, args.user, settings, write=args.write, model=_model(args.model))
    _report(f"gpo ({args.mode})", result, settings)
    return 1 if result.reason in SYSTEMIC_DENIALS else 0


def cmd_pending(args: argparse.Namespace, settings: Settings) -> int:
    items = list_pending(settings)
    if not items:
        print("Nothing pending.")
    for item in items:
        print(f"{item['artifact_id']}  skill={item['skill']}  created_by={item['created_by']}  at={item['created_at']}")
    return 0


def cmd_approve(args: argparse.Namespace, settings: Settings) -> int:
    result = approve(settings, args.artifact_id, args.user)
    if result.decision == "allow":
        print(f"APPROVED {result.artifact_id} -> approved/{result.artifact_id}.md (approver: {args.user})")
        return 0
    print(f"DENY   reason={result.reason}")
    return 1


def cmd_verify_audit(args: argparse.Namespace, settings: Settings) -> int:
    ok, message = AuditLog(settings.audit_log).verify()
    print(message)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopeguard", description="AI skills with hard-set scopes. Synthetic data only.")
    parser.add_argument("--output-dir", help="where pending_review/, approved/ and audit/ live (default: current folder)")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_run_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--user", required=True, help="who is running this (see data/synthetic/users.toml)")
        p.add_argument("--write", action="store_true", help="save output to pending_review/ (default is a dry run)")
        p.add_argument("--model", choices=["mock", "llm"], default="mock", help="mock is offline; llm is disabled by default")

    kb = sub.add_parser("kb", help="KB article generator demo")
    add_run_options(kb)
    kb.add_argument("--input", help="JSON list of incidents (default: the synthetic sample)")
    kb.set_defaults(func=cmd_kb)

    gpo = sub.add_parser("gpo", help="GPO documenter demo (read-only)")
    add_run_options(gpo)
    gpo.add_argument("--mode", choices=list(gpo_documenter.MODES), default="all")
    gpo.add_argument("--old", help="older GPO export (JSON)")
    gpo.add_argument("--new", help="newer GPO export (JSON)")
    gpo.set_defaults(func=cmd_gpo)

    sub.add_parser("pending", help="list outputs waiting for approval").set_defaults(func=cmd_pending)

    ap = sub.add_parser("approve", help="approve a pending output (moves it to approved/)")
    ap.add_argument("artifact_id")
    ap.add_argument("--user", required=True)
    ap.set_defaults(func=cmd_approve)

    sub.add_parser("verify-audit", help="check the audit log hash chain").set_defaults(func=cmd_verify_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # never crash on a console that cannot show a character
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    settings = Settings.default(args.output_dir)
    return args.func(args, settings)
