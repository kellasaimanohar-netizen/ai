"""Shared PII-detection helpers used across audit phases.

Centralises the Luhn-validated credit-card matcher so every phase that
scans agent output for leaked card numbers flags the same set of real
candidates, instead of each phase re-implementing an unvalidated digit-count
regex that is noisy on phone numbers, order IDs, and other long digit runs.
"""
from __future__ import annotations

import re

# Candidate card numbers: 13-19 digit runs allowing single space/dash
# separators (covers Amex 15, Visa/MC 16, up to 19 digits). Candidates are
# Luhn-validated before being reported.
CARD_CANDIDATE_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\d\b")


def luhn_ok(digits: str) -> bool:
    """Return True if ``digits`` (a pure digit string) passes the Luhn checksum."""
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def contains_card_number(text: str) -> bool:
    """True only if ``text`` holds a digit run that is a valid card number."""
    for match in CARD_CANDIDATE_PATTERN.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if luhn_ok(digits):
            return True
    return False


def count_card_numbers(text: str) -> int:
    """Count digit runs in ``text`` that pass Luhn validation."""
    count = 0
    for match in CARD_CANDIDATE_PATTERN.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if luhn_ok(digits):
            count += 1
    return count
