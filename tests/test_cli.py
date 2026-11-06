"""End-to-end through the command line, the way the README quickstart does it."""

from scopeguard.cli import main


def cli(tmp_path, *args):
    return main(["--output-dir", str(tmp_path), *args])


def test_kb_demo_is_a_dry_run_by_default(tmp_path, capsys):
    assert cli(tmp_path, "kb", "--user", "alex") == 0
    out = capsys.readouterr().out
    assert "ALLOW  dry-run" in out and "DENY   reason=forbidden_data:ssn" in out
    assert not (tmp_path / "pending_review").exists()


def test_a_viewer_is_stopped_and_the_exit_code_says_so(tmp_path, capsys):
    assert cli(tmp_path, "kb", "--user", "casey") == 1
    assert "role_not_permitted" in capsys.readouterr().out


def test_write_then_approve_walkthrough(tmp_path, capsys):
    assert cli(tmp_path, "gpo", "--user", "alex", "--mode", "document", "--write") == 0
    artifact_id = next((tmp_path / "pending_review").glob("*.md")).stem
    assert "approve" in capsys.readouterr().out

    assert cli(tmp_path, "pending") == 0
    assert artifact_id in capsys.readouterr().out

    assert cli(tmp_path, "approve", artifact_id, "--user", "alex") == 1  # author cannot approve
    assert cli(tmp_path, "approve", artifact_id, "--user", "blake") == 0
    assert (tmp_path / "approved" / f"{artifact_id}.md").is_file()

    assert cli(tmp_path, "verify-audit") == 0
    assert "intact" in capsys.readouterr().out


def test_llm_model_is_off_by_default_and_the_run_is_denied_cleanly(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("SCOPEGUARD_ENABLE_LLM", raising=False)
    cli(tmp_path, "gpo", "--user", "alex", "--mode", "document", "--model", "llm")
    assert "skill_error:AdapterDisabled" in capsys.readouterr().out
