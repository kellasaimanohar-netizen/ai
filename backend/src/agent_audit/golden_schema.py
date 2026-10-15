"""Golden-dataset schema — a structured JSONL format for reusable test
datasets that CI, `GND-GOLDEN-001`, and `FAIR-EQUITY-001` can all consume.

Each line is one JSON object with these fields:

    input     (str, required)  — the query/prompt sent to the agent
    expected  (str, required)  — the expected answer (keyword-matched by
                                  the groundedness/equity checks)
    category  (str, required)  — one of CATEGORIES below
    group     (str, optional)  — demographic/locale slice, used by
                                  FAIR-EQUITY-001 to compute per-group
                                  accuracy; omit for cases that aren't
                                  part of a fairness slice
    notes     (str, optional)  — why this case exists / what it probes

A real committed example lives at `backend/golden/sample_dataset.jsonl` —
wired into `targets/agentforce_agent.yaml`'s `golden_dataset:` field, so
GND-GOLDEN-001 and FAIR-EQUITY-001 exercise a real, CI-reachable dataset
rather than only their skip-path branches (see test_phase09_groundedness.py
/ test_phase10_fairness.py's TestFairEquity001, which cover the skip paths
individually with tmp_path-generated fixtures).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

CATEGORIES: tuple[str, ...] = (
    "normal", "edge", "negative", "adversarial", "bias", "groundedness",
    "accuracy", "security", "privacy", "tool_use", "freshness",
)


@dataclass(slots=True, frozen=True)
class GoldenCase:
    input: str
    expected: str
    category: str
    group: str | None = None
    notes: str = ""


class GoldenDatasetError(ValueError):
    """Raised when a golden-dataset JSONL file doesn't match the schema."""


def load_golden_cases(path: str | Path) -> list[GoldenCase]:
    """Parse and validate a golden-dataset JSONL file. Raises
    GoldenDatasetError on the first malformed/incomplete line, naming the
    line number, so a broken dataset fails loudly in CI instead of silently
    dropping cases (as the checks' own best-effort JSON parsing does)."""
    p = Path(path)
    cases: list[GoldenCase] = []
    for lineno, raw_line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GoldenDatasetError(f"{p}:{lineno}: invalid JSON — {exc}") from exc

        missing = [f for f in ("input", "expected", "category") if f not in row]
        if missing:
            raise GoldenDatasetError(f"{p}:{lineno}: missing required field(s) {missing}")
        if row["category"] not in CATEGORIES:
            raise GoldenDatasetError(
                f"{p}:{lineno}: category {row['category']!r} not in {CATEGORIES}"
            )
        cases.append(GoldenCase(
            input=row["input"], expected=row["expected"], category=row["category"],
            group=row.get("group"), notes=row.get("notes", ""),
        ))
    return cases
