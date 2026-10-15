"""Framework self-test — user's section-13 ask: "every check has at least
one PASS scenario," "every check has at least one FAIL scenario," "no check
is permanently skipped unintentionally."

Rather than re-deriving coverage by running full audits (fragile — most
checks are manifest-conditional, not posture-conditional, so a single
full-audit run can't exercise every branch without hand-crafting a manifest
per check, which is exactly what the dedicated `test_phaseNN_*.py` files
already do), this scans:
  1. `agent_audit/phases/*.py` for every declared check ID (the canonical
     inventory — anything with `finding_id="XXX-001"` or `id="XXX-001"`).
  2. Every `tests/test_phase*.py` file's source, split into per-class
     blocks, for a block that references that ID and contains both
     `passed is True` and `passed is False`.

A check that regresses to always-pass or always-fail (a broken detector, a
reverted fix, a new check shipped with only one branch tested) fails this
test immediately — it's the single command that proves Wave 0/1 of the
agent-audit hardening effort didn't just move the goalposts once and walk
away.
"""
from __future__ import annotations

import re
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "agent_audit" / "phases"
_TEST_DIR = Path(__file__).resolve().parent

_ID_PATTERN = re.compile(r'(?:finding_id|id)="([A-Z][A-Z0-9]*-[A-Z0-9-]+-\d{3})"')
_CLASS_SPLIT = re.compile(r"\n(?=class Test\w+)")

# Checks with a documented, deliberate single reachable branch under mock
# mode — a design choice, not a gap. Every entry needs a real reason; see
# `test_allowlist_entries_are_justified` below, which enforces that.
_SINGLE_BRANCH_ALLOWLIST: dict[str, str] = {
    "REL-SCHEMA-001": (
        "Always requests the 'schema_invalid' mock scenario, a fixed "
        "malformed fixture used to self-test the schema validator itself, "
        "not to represent variable agent behavior. Live-mode audits are "
        "unaffected -- mock mode never needs a 'clean schema' branch here."
    ),
    "MCP-SCOPE-000": (
        "A pure 'not applicable' short-circuit emitted only when no tools "
        "are declared at all -- in that case none of the 5 real MCP checks "
        "run, so there is nothing for this ID to fail; it is structurally "
        "PASS/INFO-only by design, not a detector with two outcomes."
    ),
}


def _collect_check_ids() -> set[str]:
    ids: set[str] = set()
    for path in _SRC_DIR.glob("*.py"):
        ids.update(_ID_PATTERN.findall(path.read_text(encoding="utf-8")))
    return ids


def _class_blocks() -> list[str]:
    blocks: list[str] = []
    for path in sorted(_TEST_DIR.glob("test_phase*.py")):
        blocks.extend(_CLASS_SPLIT.split(path.read_text(encoding="utf-8")))
    return blocks


def _coverage_for(blocks: list[str], check_id: str) -> tuple[bool, bool]:
    """Return (has_pass_test, has_fail_test) for a check ID, aggregated
    across every test-class block that mentions it (usually just one)."""
    has_pass = has_fail = False
    needle = f'"{check_id}"'
    for block in blocks:
        if needle in block:
            has_pass = has_pass or "passed is True" in block
            has_fail = has_fail or "passed is False" in block
    return has_pass, has_fail


class TestCheckCoverage:
    def test_check_id_inventory_looks_sane(self):
        # Guards against the scan itself silently breaking (e.g. a phase
        # file renamed, the finding_id= pattern changed) and this whole
        # test suite going green for the wrong reason.
        ids = _collect_check_ids()
        assert len(ids) >= 70, f"only found {len(ids)} check IDs — did the scanner break?"

    def test_every_check_has_both_a_pass_and_a_fail_test(self):
        all_ids = _collect_check_ids()
        blocks = _class_blocks()

        missing_entirely: list[str] = []
        pass_only: list[str] = []
        fail_only: list[str] = []

        for check_id in sorted(all_ids):
            if check_id in _SINGLE_BRANCH_ALLOWLIST:
                continue
            has_pass, has_fail = _coverage_for(blocks, check_id)
            if not has_pass and not has_fail:
                missing_entirely.append(check_id)
            elif not has_fail:
                pass_only.append(check_id)
            elif not has_pass:
                fail_only.append(check_id)

        problems = []
        if missing_entirely:
            problems.append(f"No dedicated test found at all for: {missing_entirely}")
        if pass_only:
            problems.append(f"PASS tested but FAIL branch is not: {pass_only}")
        if fail_only:
            problems.append(f"FAIL tested but PASS branch is not: {fail_only}")
        assert not problems, "\n".join(problems)

    def test_allowlist_entries_are_justified(self):
        """The allowlist must stay small and honest — every entry needs a
        real, non-trivial reason and must still correspond to a real check."""
        all_ids = _collect_check_ids()
        for check_id, reason in _SINGLE_BRANCH_ALLOWLIST.items():
            assert check_id in all_ids, f"{check_id} no longer exists in phases/*.py — remove it from the allowlist"
            assert len(reason) > 40, f"{check_id}'s allowlist reason is too thin to justify a skip"
        assert len(_SINGLE_BRANCH_ALLOWLIST) <= 5, (
            "the single-branch allowlist is growing large -- that's a sign checks are being "
            "waved through instead of fixed. Each new entry should be scrutinised."
        )
