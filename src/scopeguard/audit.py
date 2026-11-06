"""Append-only audit log (JSON Lines).

Each line records WHO did WHAT, WHEN, to WHICH skill, and the DECISION. It never
holds ticket text, GPO settings or any other content: only codes, counts, field
NAMES and hashes. `record()` refuses anything else.

Each entry also carries the hash of the previous entry, so editing or deleting
a line in the middle is detectable with `verify()`. (It is tamper-EVIDENT, not
tamper-PROOF: whoever controls the file can still rewrite the whole chain. A real
deployment ships logs to a system the skill's operators cannot edit.)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_KEYS = frozenset(
    {
        "actor",
        "action",
        "skill",
        "decision",
        "reason",
        "mode",
        "inputs_hash",
        "output_hash",
        "fields_dropped",
        "redactions",
        "injection_flags",
        "artifact",
    }
)
MAX_STRING = 120
GENESIS = "0" * 64


def _check_safe(key: str, value: Any) -> None:
    """Allow only short strings, numbers, lists of short strings, and {name: count} maps."""

    def short_str(item: Any) -> bool:
        return isinstance(item, str) and len(item) <= MAX_STRING

    ok = (
        value is None
        or isinstance(value, (bool, int))
        or short_str(value)
        or (isinstance(value, list) and len(value) <= 100 and all(short_str(i) for i in value))
        or (isinstance(value, dict) and all(short_str(k) and isinstance(v, int) for k, v in value.items()))
    )
    if not ok:
        raise ValueError(f"audit field '{key}' has an unsafe value")


def _hash_entry(entry: dict[str, Any]) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    """Stable hash of structured data (used for the inputs hash)."""
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1])["entry_hash"] if lines else GENESIS

    def record(self, **fields: Any) -> dict[str, Any]:
        unknown = set(fields) - ALLOWED_KEYS
        if unknown:
            raise ValueError(f"audit field not allowed: {sorted(unknown)}")
        for key, value in fields.items():
            _check_safe(key, value)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry: dict[str, Any] = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        entry.update(fields)
        entry["prev_hash"] = self._last_hash()
        entry["entry_hash"] = _hash_entry(entry)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:  # append only
            handle.write(json.dumps(entry) + "\n")
        return entry

    def verify(self) -> tuple[bool, str]:
        """Check the hash chain. Returns (ok, message). Message never includes content."""
        if not self.path.exists():
            return True, "no audit log yet"
        previous = GENESIS
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            try:
                entry = json.loads(line)
                claimed = entry.pop("entry_hash")
            except (ValueError, KeyError):
                return False, f"line {number}: unreadable entry"
            if entry.get("prev_hash") != previous:
                return False, f"line {number}: chain broken (entry removed or reordered)"
            if _hash_entry(entry) != claimed:
                return False, f"line {number}: entry was modified"
            previous = claimed
        return True, "audit chain intact"
