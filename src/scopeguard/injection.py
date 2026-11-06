"""Prompt-injection handling for text that arrives inside tickets and configs.

Rule of the whole project: text read from a ticket or a config file is DATA.
It is never instructions, never a permission change, never a command.

Three layers, in order of how much we trust them:

  1. STRUCTURE (strong): skills are pure functions with no tools, no file or
     network access and no write path. The only things text can influence are
     the words inside a fixed template. See skills/ and tests/test_skills_are_pure.py.
  2. STRIPPING (heuristic): sentences that read like instructions to an AI are
     removed before the skill runs, and the audit log records that it happened.
  3. HUMAN REVIEW (backstop): output lands in pending_review/ and a different
     person has to approve it.

The patterns below are a tripwire, not a guarantee. A cleverly worded attack
will get past them, which is why layers 1 and 3 exist.
"""

from __future__ import annotations

import re
from typing import Any

_FLAGS = re.I | re.S

PATTERNS = [
    re.compile(p, _FLAGS)
    for p in (
        r"\bignore\b[\s\S]{0,40}\b(rules?|instructions?|guidelines?|polic(?:y|ies)|restrictions?|prompt)\b",
        r"\bdisregard\b[\s\S]{0,40}\b(rules?|instructions?|above|previous|prior)\b",
        r"\b(forget|override|bypass)\b[\s\S]{0,40}\b(rules?|instructions?|guardrails?|restrictions?|safeguards?|scope)\b",
        r"\byou are now\b",
        r"\bnew instructions?\b",
        r"\b(system|developer) (prompt|message|mode)\b",
        r"\b(reveal|print|dump|output|include|show)\b[\s\S]{0,80}\b(manifest|config(?:uration)?|credentials?|other skill)\b",
        r"\b(skip|without|no)\b[\s\S]{0,20}\b(review|approval)\b",
        r"\b(push|deploy|apply)\b[\s\S]{0,40}\b(domain controllers?|all (?:computers|machines|workstations|servers))\b",
    )
]

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _looks_like_injection(sentence: str) -> bool:
    return any(pattern.search(sentence) for pattern in PATTERNS)


def _strip_text(text: str) -> tuple[str, int]:
    sentences = _SENTENCE_SPLIT.split(text)
    kept = [s for s in sentences if not _looks_like_injection(s)]
    removed = len(sentences) - len(kept)
    return (" ".join(kept) if removed else text), removed


def strip_injection(value: Any) -> tuple[Any, int]:
    """Remove instruction-like sentences from every string in `value`.

    Returns (cleaned_copy, number_of_sentences_removed). Never executes or
    interprets anything; it only deletes.
    """
    if isinstance(value, dict):
        total = 0
        out = {}
        for key, item in value.items():
            out[key], n = strip_injection(item)
            total += n
        return out, total
    if isinstance(value, list):
        total = 0
        items = []
        for item in value:
            cleaned, n = strip_injection(item)
            items.append(cleaned)
            total += n
        return items, total
    if isinstance(value, str):
        return _strip_text(value)
    return value, 0
