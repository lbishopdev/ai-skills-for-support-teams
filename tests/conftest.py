import pytest

from helpers import REPO, manifest_toml
from scopeguard.settings import Settings


@pytest.fixture
def settings(tmp_path):
    """The real manifests and users, with all output going to a temp folder."""
    return Settings(
        repo_root=REPO,
        manifests_dir=REPO / "manifests",
        users_file=REPO / "data" / "synthetic" / "users.toml",
        output_dir=tmp_path / "out",
    )


@pytest.fixture
def make_settings(tmp_path):
    """Factory: Settings whose manifests folder holds ONLY the manifests you pass in.

    make_settings(spy_skill=manifest_toml(...))   -> a manifest for "spy_skill"
    make_settings()                                -> no manifests at all (default deny)
    """

    def make(**manifests: str) -> Settings:
        manifests_dir = tmp_path / "manifests"
        manifests_dir.mkdir(exist_ok=True)
        for name, text in manifests.items():
            (manifests_dir / f"{name}.toml").write_text(text, encoding="utf-8")
        return Settings(
            repo_root=REPO,
            manifests_dir=manifests_dir,
            users_file=REPO / "data" / "synthetic" / "users.toml",
            output_dir=tmp_path / "out",
        )

    return make


@pytest.fixture
def spy_settings(make_settings):
    """Settings with a standard manifest for the spy skill (allows only the 'note' field)."""
    return make_settings(spy_skill=manifest_toml())
