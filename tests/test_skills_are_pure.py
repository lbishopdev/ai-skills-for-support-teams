"""Proves: skills have NO code path to files, the network, other processes, or other skills.

The check is an allow-list (default deny, like everything else here): a skill module
may import only the names below. If someone adds `import os` or `import subprocess`
to a skill, this test fails and a human has to look at why.
"""

import ast
from pathlib import Path

import pytest

SKILLS_DIR = Path(__file__).resolve().parents[1] / "src" / "scopeguard" / "skills"
SKILL_FILES = sorted(p for p in SKILLS_DIR.glob("*.py") if p.name != "__init__.py")

ALLOWED_IMPORTS = {"__future__", "collections", "dataclasses", "datetime", "typing"}
ALLOWED_RELATIVE = {"model"}  # `from ..model import ...` is the model boundary
FORBIDDEN_CALLS = {"open", "exec", "eval", "compile", "__import__", "input", "getattr", "setattr", "delattr", "globals", "locals"}
FORBIDDEN_ATTRIBUTES = {
    "write_text", "write_bytes", "read_text", "read_bytes", "open", "unlink", "rmdir", "mkdir", "rename", "replace",
    "remove", "system", "popen", "run", "call", "connect", "send", "environ", "getenv",
}


def test_there_are_skills_to_check():
    assert {p.name for p in SKILL_FILES} == {"kb_article.py", "gpo_documenter.py"}


@pytest.mark.parametrize("path", SKILL_FILES, ids=lambda p: p.name)
def test_skill_imports_only_from_the_allow_list(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in ALLOWED_IMPORTS, f"{path.name} imports {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import
                assert node.level == 2 and node.module in ALLOWED_RELATIVE, f"{path.name} imports from {'.' * node.level}{node.module}"
            else:
                assert node.module.split(".")[0] in ALLOWED_IMPORTS, f"{path.name} imports from {node.module}"


@pytest.mark.parametrize("path", SKILL_FILES, ids=lambda p: p.name)
def test_skill_makes_no_file_process_or_dynamic_calls(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS, f"{path.name} calls {node.func.id}()"
            elif isinstance(node.func, ast.Attribute):
                assert node.func.attr not in FORBIDDEN_ATTRIBUTES, f"{path.name} calls .{node.func.attr}()"


def test_the_gpo_skill_runs_no_logic_at_import_time():
    """Only imports, constants, classes and functions at the top level: no loops, try-blocks or `with` blocks."""
    tree = ast.parse((SKILLS_DIR / "gpo_documenter.py").read_text(encoding="utf-8"))
    for node in tree.body:
        assert not isinstance(node, (ast.With, ast.Try, ast.For, ast.While)), "unexpected top-level statement"
