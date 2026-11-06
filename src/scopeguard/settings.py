"""Where things live on disk."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    repo_root: Path
    manifests_dir: Path
    users_file: Path
    output_dir: Path  # pending_review/, approved/ and audit/ are created under here

    @property
    def pending_dir(self) -> Path:
        return self.output_dir / "pending_review"

    @property
    def approved_dir(self) -> Path:
        return self.output_dir / "approved"

    @property
    def audit_log(self) -> Path:
        return self.output_dir / "audit" / "audit.jsonl"

    @classmethod
    def default(cls, output_dir: str | Path | None = None) -> "Settings":
        root = Path(__file__).resolve().parents[2]  # src/scopeguard/settings.py -> repo root
        return cls(
            repo_root=root,
            manifests_dir=root / "manifests",
            users_file=root / "data" / "synthetic" / "users.toml",
            output_dir=Path(output_dir) if output_dir else Path.cwd(),
        )
