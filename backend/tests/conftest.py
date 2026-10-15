"""Shared fixtures for agent-audit tests."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Tests that use the database or the web app must not run against the real database. Before anything is
# imported, the connection string is replaced: without TEST_DATABASE_URL those tests are skipped, and
# with it they run against that separate database only.
_TEST_DB = os.environ.get("TEST_DATABASE_URL", "").strip()
os.environ["DATABASE_URL"] = _TEST_DB
os.environ["DB_NAME"] = ""     # the DB_* settings in .env must not bring the real database back
# Report PDFs from tests go to a temporary folder, never the real storage/reports
import tempfile as _tempfile
os.environ["REPORTS_DIR"] = _tempfile.mkdtemp(prefix="certify-test-reports-")
# The live-testing tests run their fake agents on 127.0.0.1, which the server otherwise refuses to call.
# test_outbound_safety.py turns this off again to check the refusal itself.
os.environ["AA_ALLOW_PRIVATE_TARGETS"] = "1"
# Tests encrypt with a fixed throwaway key, never the one in .env
os.environ["DATA_ENCRYPTION_KEY"] = "dGVzdC1vbmx5LWtleS1kby1ub3QtdXNlLWluLXByb2Q="
if _TEST_DB:
    os.environ.setdefault("ADMIN_EMAIL", "admin@certifyai.in")
    os.environ.setdefault("ADMIN_PASSWORD", "admin")
    os.environ.setdefault("USER_EMAIL", "user@certifyai.in")
    os.environ.setdefault("USER_PASSWORD", "user")

_DB_PATTERNS = ("from database", "import database", "from backend", "import backend", "TestClient", "get_db_connection", "init_db")


def _uses_database(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    if "no-real-database" in text:      # the test replaces the database with a fake
        return False
    return any(p in text for p in _DB_PATTERNS)


collect_ignore = [] if _TEST_DB else [
    p.name for p in sorted(Path(__file__).parent.glob("test_*.py")) if _uses_database(p)
]

# Ensure src/ and backend/ are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _find_target_yaml() -> Path:
    # 1. Check environment variable
    env_target = os.getenv("AGENT_AUDIT_TARGET")
    if env_target:
        p = Path(env_target).resolve()
        if p.is_file():
            return p

    # 2. Check targets/ directory. Prefer a target that declares a top-level
    #    runtime endpoint (the shape the v3-compat smoke tests assert against);
    #    provider-based targets (e.g. agentforce) legitimately have no endpoint.
    workspace_root = Path(__file__).resolve().parent.parent
    targets_dir = workspace_root / "targets"
    if targets_dir.is_dir():
        yamls = sorted(targets_dir.glob("*.yaml")) + sorted(targets_dir.glob("*.yml"))
        if yamls:
            import yaml as _yaml

            def _has_endpoint(p: Path) -> bool:
                try:
                    raw = _yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                except Exception:
                    return False
                # flat v3 endpoint, or nested under sources[].runtime
                if isinstance(raw, dict) and raw.get("endpoint"):
                    return True
                for src in (raw.get("sources") or []):
                    rt = (src or {}).get("runtime") or {}
                    if rt.get("endpoint"):
                        return True
                return False

            with_endpoint = [p for p in yamls if _has_endpoint(p)]
            if with_endpoint:
                return with_endpoint[0]
            # No endpoint-based target here — fall through to the root search
            # below rather than returning a provider-only target the smoke tests
            # can't assert an endpoint against.

    # 3. Check workspace root
    root_yamls = list(workspace_root.glob("*.yaml")) + list(workspace_root.glob("*.yml"))
    if root_yamls:
        return root_yamls[0]

    # 4. Check Customer_Agent 2 folder
    cust_path = Path("C:/Personal/Customer_Agent 2/customer_agent_v2_audit.yaml")
    if cust_path.is_file():
        return cust_path

    raise FileNotFoundError(
        "No agent target YAML file found. Please set the AGENT_AUDIT_TARGET environment variable."
    )


@pytest.fixture
def v3_target_path() -> Path:
    return _find_target_yaml()


@pytest.fixture
def v4_target_path() -> Path:
    return _find_target_yaml()


# ── Wave-0 harness: shared by per-check pytest coverage (test_phaseNN_*.py) ──
#
# `build_manifest(...)` builds a TargetManifest from convenient flat kwargs
# instead of hand-nesting every dataclass. `mock_ctx(...)` builds a
# PhaseContext wired to MockAgentClient with an explicit posture
# ("secure" | "vulnerable") so a check's PASS and FAIL branches can both be
# exercised directly, without going through a full run_audit().

def build_manifest(
    *,
    agent_name: str = "test-agent",
    tools: list[str] | None = None,
    destructive_tools: list[str] | None = None,
    requires_hitl: bool = False,
    max_steps: int = 25,
    context_budget_tokens: int | None = 8000,
    pii_fields: list[str] | None = None,
    data_classification: list[str] | None = None,
    allowed_data_regions: list[str] | None = None,
    dependencies: list[tuple[str, str | None]] | None = None,
    models: list[tuple[str, str]] | None = None,
    prompts: list[tuple[str, str]] | None = None,
    runbooks_dir: Path | None = None,
    golden_dataset_path: Path | None = None,
    p95_latency_ms: int = 10_000,
    max_cost_per_task_usd: float = 0.10,
    endpoint: str | None = "https://example.test/agent",
    provider_name: str = "generic",
    target_env: str | None = "sandbox",
    provenance_trail: dict[str, list[str]] | None = None,
):
    from agent_audit.manifest import (
        CapabilitiesSpec,
        DependencySpec,
        GoldenDatasetSpec,
        ModelSpec,
        ProviderSpec,
        PromptSpec,
        RuntimeSpec,
        SecuritySpec,
        SLOSpec,
        TargetManifest,
        ToolSpec,
    )

    destructive_set = set(destructive_tools or [])
    tool_specs = [
        ToolSpec(name=t, destructive=t in destructive_set, declared_in=["yaml"])
        for t in (tools or [])
    ]

    dep_specs = [
        DependencySpec(name=name, version=version, source="pypi")
        for name, version in (dependencies or [])
    ]
    model_specs = [
        ModelSpec(provider=provider, model_id=model_id)
        for provider, model_id in (models or [])
    ]
    prompt_specs = [
        PromptSpec(name=name, content=content) for name, content in (prompts or [])
    ]

    golden_dataset = None
    if golden_dataset_path is not None:
        golden_dataset = GoldenDatasetSpec(path=golden_dataset_path)

    return TargetManifest(
        agent_name=agent_name,
        runtime=RuntimeSpec(
            endpoint=endpoint,
            provider=ProviderSpec(name=provider_name),
            target_env=target_env,
        ),
        capabilities=CapabilitiesSpec(
            max_steps=max_steps,
            context_budget_tokens=context_budget_tokens,
            tools=tool_specs,
            destructive_tool_names=list(destructive_set),
            requires_hitl=requires_hitl,
        ),
        slos=SLOSpec(p95_latency_ms=p95_latency_ms, max_cost_per_task_usd=max_cost_per_task_usd),
        security=SecuritySpec(
            pii_fields=pii_fields or [],
            allowed_data_regions=allowed_data_regions or [],
            data_classification=data_classification or [],
        ),
        prompts=prompt_specs,
        models=model_specs,
        dependencies=dep_specs,
        runbooks_dir=runbooks_dir,
        golden_dataset=golden_dataset,
        provenance_trail=provenance_trail or {"yaml": ["runtime", "capabilities"]},
    )


def mock_ctx(manifest, *, posture: str = "secure", variability_runs: int = 5, **kw):
    from agent_audit.phases import PhaseContext

    return PhaseContext(
        manifest=manifest,
        mock_tools=True,
        mock_posture=posture,
        variability_runs=variability_runs,
        **kw,
    )


@pytest.fixture
def manifest_factory():
    return build_manifest


@pytest.fixture
def ctx_factory():
    return mock_ctx

