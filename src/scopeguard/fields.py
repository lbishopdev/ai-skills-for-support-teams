"""Field allow-list: the primary scope control.

Anything not named in the manifest's `allowed_inputs` is dropped here, before
the scrubber, the skill or any model can see it. Allowed paths use dots for
nesting, e.g. "settings.name" allows the `name` field inside each item of the
`settings` list.
"""

from __future__ import annotations

from typing import Any

_SCALARS = (str, int, float, bool, type(None))


def _is_scalar_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, _SCALARS) for item in value)


def filter_fields(data: dict[str, Any], allowed: frozenset[str], dropped: set[str], prefix: str = "") -> dict[str, Any]:
    """Return a copy of `data` containing only allow-listed fields.

    The path of every dropped field is added to `dropped` (names only, never values).
    """
    kept: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, _SCALARS) or _is_scalar_list(value):
            if path in allowed:
                kept[key] = value
            else:
                dropped.add(path)
        elif any(entry.startswith(path + ".") for entry in allowed):
            kept[key] = _filter_container(value, allowed, dropped, path + ".")
        else:
            dropped.add(path)
    return kept


def _filter_container(value: Any, allowed: frozenset[str], dropped: set[str], prefix: str) -> Any:
    if isinstance(value, dict):
        return filter_fields(value, allowed, dropped, prefix)
    if isinstance(value, list):
        # Only dict/list items are descended into; stray scalars in a mixed list are dropped.
        return [
            _filter_container(item, allowed, dropped, prefix)
            for item in value
            if isinstance(item, (dict, list))
        ]
    return None
