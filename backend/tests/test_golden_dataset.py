"""Wave 5 — reusable structured golden dataset.

Covers:
  * agent_audit.golden_schema's loader/validator (schema correctness,
    rejecting malformed rows).
  * The committed `golden/sample_dataset.jsonl` is well-formed and covers
    the full category taxonomy.
  * `targets/agentforce_agent.yaml`'s golden_dataset wiring is genuinely
    reachable — GND-GOLDEN-001 scores it for real instead of hitting a
    skip path.
  * `targets/customer_agent_v2_audit.yaml`'s golden_dataset is a repo-local
    vendored copy, reachable without the external machine-specific path.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit.golden_schema import CATEGORIES, GoldenDatasetError, load_golden_cases

# NOTE: no module-level `pytestmark = pytest.mark.asyncio` here — most tests
# in this file are sync (loader/schema checks); only TestTargetWiring's two
# methods are async, and `asyncio_mode = "auto"` in pyproject.toml already
# collects them correctly without the mark.

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SAMPLE_DATASET = _REPO_ROOT / "golden" / "sample_dataset.jsonl"


class TestGoldenSchemaLoader:
    def test_loads_well_formed_file(self, tmp_path):
        ds = tmp_path / "cases.jsonl"
        ds.write_text(
            '{"input": "hi", "expected": "hello", "category": "normal"}\n'
            '{"input": "bye", "expected": "goodbye", "category": "edge", "group": "us"}\n',
            encoding="utf-8",
        )
        cases = load_golden_cases(ds)
        assert len(cases) == 2
        assert cases[0].group is None
        assert cases[1].group == "us"

    def test_skips_blank_lines(self, tmp_path):
        ds = tmp_path / "cases.jsonl"
        ds.write_text(
            '{"input": "hi", "expected": "hello", "category": "normal"}\n\n   \n',
            encoding="utf-8",
        )
        assert len(load_golden_cases(ds)) == 1

    def test_rejects_invalid_json(self, tmp_path):
        ds = tmp_path / "cases.jsonl"
        ds.write_text("not json\n", encoding="utf-8")
        with pytest.raises(GoldenDatasetError, match="invalid JSON"):
            load_golden_cases(ds)

    def test_rejects_missing_required_field(self, tmp_path):
        ds = tmp_path / "cases.jsonl"
        ds.write_text('{"input": "hi", "category": "normal"}\n', encoding="utf-8")
        with pytest.raises(GoldenDatasetError, match="missing required field"):
            load_golden_cases(ds)

    def test_rejects_unknown_category(self, tmp_path):
        ds = tmp_path / "cases.jsonl"
        ds.write_text('{"input": "hi", "expected": "x", "category": "not_a_real_category"}\n', encoding="utf-8")
        with pytest.raises(GoldenDatasetError, match="not in"):
            load_golden_cases(ds)

    def test_error_message_names_the_line_number(self, tmp_path):
        ds = tmp_path / "cases.jsonl"
        ds.write_text(
            '{"input": "hi", "expected": "hello", "category": "normal"}\n'
            'not json\n',
            encoding="utf-8",
        )
        with pytest.raises(GoldenDatasetError, match=":2:"):
            load_golden_cases(ds)


class TestSampleDataset:
    def test_sample_dataset_is_well_formed(self):
        cases = load_golden_cases(_SAMPLE_DATASET)
        assert len(cases) >= 10

    def test_sample_dataset_covers_every_category(self):
        cases = load_golden_cases(_SAMPLE_DATASET)
        seen = {c.category for c in cases}
        assert seen == set(CATEGORIES)

    def test_sample_dataset_has_at_least_two_groups_for_equity_slicing(self):
        cases = load_golden_cases(_SAMPLE_DATASET)
        groups = {c.group for c in cases if c.group}
        assert len(groups) >= 2


class TestTargetWiring:
    async def test_agentforce_golden_dataset_is_reachable_and_scored(self):
        from agent_audit.runner import run_audit
        from agent_audit.sources import load_target

        m = load_target(str(_REPO_ROOT / "targets" / "agentforce_agent.yaml"))
        assert m.golden_dataset is not None
        assert m.golden_dataset.path.is_file()

        report = await run_audit(
            m, mode="validate", mock_tools=True, mock_posture="secure",
            phases=["groundedness"], variability_runs=2,
        )
        golden_finding = next(f for f in report.findings if f.id == "GND-GOLDEN-001")
        # It actually scored the real dataset — not the "no dataset declared"
        # or "file not found" skip paths.
        assert "skipped" not in golden_finding.title.lower()
        assert "not found" not in golden_finding.title.lower()

    async def test_customer_agent_v2_golden_dataset_is_repo_local(self):
        from agent_audit.sources import load_target

        m = load_target(str(_REPO_ROOT / "targets" / "customer_agent_v2_audit.yaml"))
        assert m.golden_dataset is not None
        # Must not depend on the external, machine-specific "C:/Personal/..." path.
        assert "Customer_Agent" not in str(m.golden_dataset.path)
        assert m.golden_dataset.path.is_file()
