"""Pattern scrubber: finds sensitive-looking text and redacts or rejects it.

This is a safety net, NOT the main control. The main control is the field
allow-list (fields.py): data that is not allow-listed never reaches this code.
Regexes miss things (names especially), so "scrub found nothing" means "no
obvious problems", not "proven safe".

Every class below is enforced. The manifest picks which classes are REDACTED
(replaced with a marker and processing continues); every other class is
REJECTED (the whole request is refused). Default is reject.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Iterable

# Capitalised words that follow a trigger phrase such as "reported by".
_NAME = r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}"

PATTERNS: dict[str, re.Pattern[str]] = {
    # SSN-like: 3-2-4 digits. (The demo data uses 987-65-432x, a range never issued.)
    "ssn": re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"),
    # Credentials pasted into text, and private key headers.
    "secret": re.compile(
        r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*\S+"
        r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    ),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"),
    # Ticket / case numbers such as INC0012345 or CHG-100234.
    "case_number": re.compile(r"\b(?:INC|CHG|REQ|RITM|TASK|PRB|CS|CASE|TKT)[- ]?\d{4,10}\b", re.I),
    # Asset-tag style names (ACME-LT-0417) and fully qualified names.
    "hostname": re.compile(
        r"\b[A-Za-z]{2,8}-(?:LT|DT|WS|SRV|DC|FS|VM|PC)-?\d{1,5}\b"
        r"|\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|gov|mil|edu|local|internal|corp|lan|test|example|invalid)\b"
    ),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    # 10-digit numbers WITH separators, or 555-xxxx style local numbers.
    "phone": re.compile(
        r"(?<![\d-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?![\d-])"
        r"|(?<![\d-])555[-.\s]\d{4}(?![\d-])"
    ),
    # Heuristic only: a name after a trigger phrase, or after Mr/Ms/Dr.
    "person_name": re.compile(
        rf"(?:(?i:reported by|requested by|approved by|assigned to|escalated to|spoke with|spoke to|called by)\s+(?P<name>{_NAME}))"
        r"|(?:\b(?:Mr|Mrs|Ms|Dr)\.?\s+(?P<name2>[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?))"
    ),
}

# Order matters: strict classes first, then ones that can sit inside others.
ORDER = ("ssn", "secret", "email", "case_number", "hostname", "ip_address", "phone", "person_name")
KNOWN_CLASSES = frozenset(ORDER)
assert KNOWN_CLASSES == set(PATTERNS)


def _redact(match: re.Match[str], cls: str) -> str:
    marker = f"[REDACTED:{cls}]"
    groups = match.groupdict()
    for group in ("name", "name2"):  # keep the trigger phrase, hide only the name
        if groups.get(group):
            return match.group(0).replace(groups[group], marker)
    return marker


def scrub(
    value: Any,
    redact_classes: Iterable[str],
    deny_terms: Iterable[str] = (),
) -> tuple[Any, dict[str, int], set[str]]:
    """Walk `value` (dicts, lists, strings).

    Returns (clean_copy, redaction_counts, rejected_class_names).
    If rejected_class_names is non-empty the caller must refuse the request;
    the returned copy must not be used in that case.
    """
    redact = set(redact_classes)
    redactions: Counter[str] = Counter()
    rejected: set[str] = set()
    terms = [t.lower() for t in deny_terms if t]

    def scrub_text(text: str) -> str:
        for cls in ORDER:
            pattern = PATTERNS[cls]
            if cls in redact:
                text, count = pattern.subn(lambda m, c=cls: _redact(m, c), text)
                if count:
                    redactions[cls] += count
            elif pattern.search(text):
                rejected.add(cls)
        lowered = text.lower()
        if any(term in lowered for term in terms):
            rejected.add("deny_term")
        return text

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {key: walk(item) for key, item in node.items()}
        if isinstance(node, list):
            return [walk(item) for item in node]
        if isinstance(node, str):
            return scrub_text(node)
        return node

    return walk(value), dict(redactions), rejected
