import sys
import uuid
import os
import glob
import tempfile
import shutil
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import yaml  # type: ignore
import logging
import asyncio
from contextlib import asynccontextmanager
from typing import Any
import json as _json
import contextvars
import re

from security import is_safe_url, get_current_user, require_admin, outbound_problem

# The audit a log line belongs to. Each request sets its own value, so concurrent audits never see each other's logs.
_current_audit: contextvars.ContextVar[object | None] = contextvars.ContextVar("current_audit", default=None)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_GIT_CLONE_TIMEOUT = int(os.environ.get("AA_GIT_CLONE_TIMEOUT", "120"))


class QueueLogHandler(logging.Handler):
    """Streams one audit's log records to its own queue. Records from other audits running at the same time are ignored."""
    def __init__(self, queue: asyncio.Queue[str], run_token: object, formatter: logging.Formatter | None = None) -> None:
        super().__init__()
        self.queue = queue
        self.run_token = run_token
        self.loop = asyncio.get_running_loop()   # emit can be called from a worker thread, which has no loop
        if formatter:
            self.setFormatter(formatter)

    def filter(self, record: logging.LogRecord) -> bool:
        return _current_audit.get() is self.run_token

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = _ANSI.sub("", self.format(record))
            self.loop.call_soon_threadsafe(self.queue.put_nowait, msg)
        except Exception:
            pass

# Add backend and src folders to PYTHONPATH dynamically
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "src"))

from agent_audit.sources import load_target
from agent_audit.runner import run_audit
from agent_audit.certificate import issue_certificate

from dotenv import load_dotenv
load_dotenv()

# ── Security configuration (env-driven; safe defaults) ──────────────────────
# Lock CORS to explicit origins instead of "*". Override with a comma-separated
# AA_ALLOWED_ORIGINS. allow_credentials + "*" is an invalid, unsafe combination.
_ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get(
        "AA_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174,http://localhost:3000"
    ).split(",") if o.strip()
]
# Optional bearer token. If AA_API_TOKEN is set, every audit call must present it.
_API_TOKEN = os.environ.get("AA_API_TOKEN")
# Repo scans are confined to this base dir. Defaults to the project root; set
# AA_REPO_BASE to widen/narrow. Prevents arbitrary server-side path reads.
from live_testing.scans import allowed_repo_base
_REPO_BASE = allowed_repo_base()

# Temp targets carry this prefix so they can be excluded from listings + cleaned.
_TEMP_PREFIX = "temp_ui_"


def check_docker_available() -> bool:
    """Helper to detect if docker is installed and running on the host system."""
    import shutil
    import subprocess
    if not shutil.which("docker"):
        return False
    try:
        # Run a quick lightweight command to check if docker daemon is accessible
        res = subprocess.run(["docker", "info"], capture_output=True, timeout=2)
        return res.returncode == 0
    except Exception:
        return False


# Sandbox configuration. Set AA_USE_DOCKER_SANDBOX=1 to force Docker sandboxing.
# By default, runs locally for low latency.
_USE_DOCKER_SANDBOX = os.environ.get("AA_USE_DOCKER_SANDBOX") == "1"


def _resolve_audit_user(authorization: str | None) -> dict[str, Any]:
    """Enforces JWT authentication or API token for audit executions."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if _API_TOKEN and token == _API_TOKEN:
            return {"id": 1, "email": "system@certifyai.in", "name": "System Admin", "role": "ADMIN", "system": True}
        # The account must still exist and be active, as for every other signed-in request
        return get_current_user(authorization)
    if _API_TOKEN is not None:
        raise HTTPException(status_code=401, detail="Missing or invalid API token")
    # No credentials at all — never fall back to a fixed identity. Doing so
    # made audits anonymous-by-default and attributed every run to a real
    # user's account regardless of who actually triggered it.
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide 'Authorization: Bearer <token>'.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# Clean up any leftover temporary files from previous runs
def cleanup_temp_files():
    temp_files = glob.glob(str(root_dir / "targets" / f"{_TEMP_PREFIX}*.yaml"))
    for f in temp_files:
        try:
            os.remove(f)
        except Exception:
            pass

# Step 1: Dynamic History Database
_AUDIT_HISTORY = {}

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Startup: bring the database up to date, then start monitoring. Shutdown: stop monitoring cleanly."""
    await _apply_migrations()
    monitor = _start_live_scheduler()
    yield
    if monitor:
        monitor.cancel()


app = FastAPI(title="Agent Audit V10 Dashboard API", lifespan=_lifespan)


@app.middleware("http")
async def _remember_client_ip(request: Request, call_next):
    """Makes the caller's address available to the activity log for this request."""
    # X-Forwarded-For can be typed by anyone, so it is used only behind a proxy you control (TRUST_PROXY_HEADERS=1)
    forwarded = request.headers.get("x-forwarded-for", "") if os.getenv("TRUST_PROXY_HEADERS") == "1" else ""
    client_ip.set(forwarded.split(",")[0].strip() or (request.client.host if request.client else None))
    return await call_next(request)

from versioning import normalize_agent_name, compute_agent_versions, enrich_test_runs_with_versions, group_agents_with_versions

@app.get("/api/agents")
async def get_agents(admin: dict = Depends(require_admin)):
    """Returns the unified history of all tested agents grouped by instance with versions."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM all_agents ORDER BY id ASC")
        agent_rows = [dict(r) for r in cursor.fetchall()]
        cursor.execute("""
        SELECT id, audit_id, user_id, agent_name, live_agent_id, tested_by_email, tested_by_name, user_role, mode,
               runs_count, concurrency, phases_selected, trust_score, tier, enterprise_ready,
               critical_count, warning_count, pass_count, info_count, duration_ms, created_at, notes
        FROM all_agent_tests
        ORDER BY created_at ASC, id ASC
        """)
        all_runs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return group_agents_with_versions(agent_rows, all_runs)
    except Exception as e:
        logging.error(f"Failed to fetch grouped agents: {e}")
        return list(_AUDIT_HISTORY.values())


# Configure CORS with strict allowed origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from routers.targets import router as targets_router
from routers.admin import router as admin_router
from routers.auth import router as auth_router
from routers.user_api import router as user_router
from routers.live_monitor import router as live_monitor_router
from database import get_db_connection, generate_and_store_pdf
from database.test_runs import certify_source, record_certify_details, record_certify_findings
from database.activity import client_ip, log_activity

app.include_router(auth_router)
app.include_router(user_router)
app.include_router(live_monitor_router)
app.include_router(admin_router)
app.include_router(targets_router)

from routers.user_api import (
    execute_live_agent_test,
    execute_live_agent_batch_test,
    get_live_agent_presets,
    discover_live_agent,
    LiveAgentTestRequest,
    LiveAgentBatchTestRequest,
    LiveDiscoverRequest
)

async def _apply_migrations():
    """Bring the database schema up to date before serving. A failure is logged, not hidden, and the app still starts
    so /health answers; run `python -m database.migrate` to see the full error."""
    from database.migrate import migrate
    try:
        applied = await asyncio.get_running_loop().run_in_executor(None, migrate)
        if applied:
            logging.info("Database migrations applied: %s", ", ".join(applied))
    except Exception as e:
        logging.error("Database migrations failed: %s", e)


def _start_live_scheduler() -> "asyncio.Task | None":
    """Monitoring (health checks every few minutes and scheduled full tests) runs in a background loop on any
    long-running server, so it keeps working while nobody has the page open. It is off on serverless hosts, which
    cannot keep a loop alive: call POST /api/user/live/schedules/run-due from a cron there. Set LIVE_SCHEDULER=0 to turn it off."""
    on_serverless = bool(os.environ.get("VERCEL"))
    flag = os.environ.get("LIVE_SCHEDULER")
    if flag == "1" or (flag is None and not on_serverless):
        from live_testing import scheduler as _sched
        from routers.live_monitor import _run_test
        return asyncio.create_task(_sched.loop(get_db_connection, _run_test))
    return None


@app.post("/api/live-agent/test")
async def live_agent_test_alias(req: LiveAgentTestRequest, authorization: str | None = Header(default=None)):
    return await execute_live_agent_test(req, authorization)

@app.post("/api/live-agent/batch-test")
async def live_agent_batch_test_alias(req: LiveAgentBatchTestRequest, authorization: str | None = Header(default=None)):
    return await execute_live_agent_batch_test(req, authorization)

@app.get("/api/live-agent/presets")
def live_agent_presets_alias():
    return get_live_agent_presets()

@app.post("/api/live-agent/discover")
async def live_agent_discover_alias(req: LiveDiscoverRequest, current_user: dict = Depends(get_current_user)):
    return await discover_live_agent(req, current_user)

@app.get("/")
@app.get("/health")
@app.get("/api/health")
def health_check():
    """Answers only when the database does too. Open to everyone (uptime monitors use it), so it says whether the
    database works and how up to date its schema is, but never error text, names or addresses."""
    import platform
    import time as _time
    import fastapi
    from fastapi.responses import JSONResponse
    from database.migrate import MIGRATIONS_DIR

    files = sorted(p.name[:4] for p in MIGRATIONS_DIR.iterdir() if p.suffix in (".sql", ".py") and p.name[:4].isdigit())
    db: dict[str, Any] = {"status": "error", "latency_ms": None, "schema_version": None, "pending_migrations": None}
    try:
        t0 = _time.perf_counter()
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT version FROM schema_migrations")
            applied = {r[0] for r in cur.fetchall()}
        finally:
            conn.close()
        db.update(status="ok", latency_ms=round((_time.perf_counter() - t0) * 1000, 1),
                  schema_version=max(applied) if applied else None,
                  pending_migrations=len([f for f in files if f not in applied]))
    except Exception as e:
        logging.error("Health check: the database did not answer: %s", e)

    healthy = db["status"] == "ok" and db["pending_migrations"] == 0
    host = "Vercel serverless" if os.environ.get("VERCEL") else "long-running server"
    body = {
        "status": "healthy" if healthy else "degraded",
        "service": "CertifyAI Enterprise Governance API",
        "version": "10.3.0",
        "engine": f"FastAPI {fastapi.__version__} on Python {platform.python_version()} ({host})",
        "database": db,
    }
    return JSONResponse(body, status_code=200 if healthy else 503)

class AuditRequest(BaseModel):
    yaml_content: str | None = None
    repo_path: str | None = None
    openapi_url: str | None = None
    mode: str = "validate"
    runs: int = 1
    concurrency: int = 10
    selected_phases: list[str] | None = None
    # A saved agent: its address and login settings are taken from its last real audit
    agent_id: int | None = None
    agent_kind: str | None = None          # "certify" or "live"
    # Ignored: the run always belongs to the signed-in account. Kept so older clients that send them still work.
    user_id: int | None = None
    tested_by_email: str | None = None
    tested_by_name: str | None = None
    user_role: str | None = None





def _notify_result(conn, user_id: Any, agent_name: str, result: dict) -> None:
    from live_testing.scheduler import notify_test_result
    notify_test_result(conn, user_id, agent_name, result.get("tier"), result.get("trust_score"),
                       result.get("critical_count"), result.get("audit_id"), live=False)


def _audit_target_name(req: "AuditRequest") -> str:
    """A readable name for a test that failed before it produced a result."""
    if req.yaml_content:
        try:
            data = yaml.safe_load(req.yaml_content) or {}
            agent = data.get("agent") if isinstance(data, dict) else None
            name = agent.get("name") if isinstance(agent, dict) else (data.get("name") if isinstance(data, dict) else None)
            if name:
                return str(name)
        except Exception:
            pass
    return req.repo_path or req.openapi_url or "Agent"


@app.post("/api/audit")
async def run_ui_audit(req: AuditRequest, authorization: str | None = Header(default=None)):
    """Runs a target audit and streams logs + final results back to the client using SSE."""
    auth_user = _resolve_audit_user(authorization)
    if auth_user.get("role") == "ADMIN" and not auth_user.get("system"):
        raise HTTPException(status_code=403, detail="Admins can view tests but cannot run them. Sign in as a user to test an agent.")

    # Validate target parameters upfront to return immediate HTTP error codes
    if req.openapi_url:
        safe, reason = is_safe_url(req.openapi_url)
        if not safe:
            raise HTTPException(status_code=400, detail=f"Disallowed openapi_url: {reason}")
    
    cloned: list[str] = []   # temporary clone folders, removed whatever happens to the stream

    def _notify_error(error: str) -> None:
        """A test that crashed after it started is a notification, so it is not missed after the page is closed."""
        try:
            conn = get_db_connection()
            try:
                from live_testing.scheduler import notify_test_error
                notify_test_error(conn, auth_user.get("id"), _audit_target_name(req), error[:300], live=False)
            finally:
                conn.close()
        except Exception as e:
            logging.warning("could not add notification: %s", e)

    async def audit_stream_generator():
        try:
            async for chunk in _audit_stream():
                yield chunk
        finally:
            for d in cloned:
                shutil.rmtree(d, ignore_errors=True)

    async def _audit_stream():
        # Setup target content
        rp = None
        try:
            # Determine the source content
            if req.yaml_content:
                yaml_content_str = req.yaml_content
            elif req.repo_path:
                clean_path = req.repo_path.strip().strip('"').strip("'")
                if clean_path.startswith(("http://", "https://", "git@")):
                    temp_repo_dir = tempfile.mkdtemp(prefix="agent_audit_git_")
                    cloned.append(temp_repo_dir)
                    await _clone_repo(clean_path, temp_repo_dir)
                    rp = Path(temp_repo_dir).resolve()
                else:
                    # Confine repo scans to the allowlisted base dir
                    rp = Path(clean_path).expanduser().resolve()
                    if not rp.is_relative_to(_REPO_BASE):
                        raise HTTPException(
                            status_code=403,
                            detail=f"repo_path must be inside {_REPO_BASE} (set AA_REPO_BASE to change)",
                        )
                    if not rp.exists():
                        raise HTTPException(status_code=404, detail="repo_path does not exist")
                
                # Auto-detect any YAML/YML manifest file in the repo directory
                manifest_files = list(rp.glob("*.yaml")) + list(rp.glob("*.yml"))
                # Filter out system/deployment config files
                manifest_files = [f for f in manifest_files if f.name.lower() not in ("render.yaml", "render.yml", "docker-compose.yaml", "docker-compose.yml")]
                
                if manifest_files:
                    manifest_path = manifest_files[0]
                    logging.info(f"Auto-detected manifest in repository: {manifest_path}")
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest_data = yaml.safe_load(f)
                    
                    # Fix paths inside manifest to make sure they are absolute and correct
                    if isinstance(manifest_data, dict) and "sources" in manifest_data:
                        for src in manifest_data["sources"]:
                            if isinstance(src, dict):
                                if src.get("type") == "openapi" and "path" in src:
                                    op_path_str = src["path"]
                                    if not op_path_str.startswith(("http://", "https://")):
                                        op_path = Path(op_path_str)
                                        if not op_path.is_absolute():
                                            src["path"] = str(rp / op_path)
                                elif src.get("type") == "repo" and "path" in src:
                                    src["path"] = str(rp)
                    yaml_content_str = yaml.dump(manifest_data)
                else:
                    yaml_content_str = yaml.dump({
                        "agent_name": f"Repo_{rp.name or 'scan'}",
                        "sources": [
                            {"type": "repo", "path": str(rp) if not _USE_DOCKER_SANDBOX else "/scan"}
                        ]
                    })
            elif req.openapi_url:
                safe, reason = is_safe_url(req.openapi_url)
                if not safe:
                    raise HTTPException(status_code=400, detail=f"Target OpenAPI URL is blocked by security policy: {reason}")
                # Step 2: Auto-Discovery Engine
                import httpx
                try:
                    async with httpx.AsyncClient() as client:
                        resp = await client.get(req.openapi_url, timeout=10.0)  # redirects are not followed
                        resp.raise_for_status()
                        openapi_spec = resp.json()
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"Failed to auto-discover OpenAPI spec: {str(e)}")

                # Automatically extract tools from the OpenAPI paths
                discovered_tools = []
                for path_key in openapi_spec.get("paths", {}).keys():
                    tool_name = path_key.strip("/").replace("/", "_").replace("{", "").replace("}", "")
                    if tool_name:
                        discovered_tools.append(tool_name)
                
                agent_title = openapi_spec.get("info", {}).get("title", f"API_{uuid.uuid4().hex[:4]}")
                agent_name = agent_title.replace(" ", "_").lower()
                base_url = req.openapi_url.rsplit("/", 1)[0]

                manifest_data = {
                    "agent_name": agent_name,
                    "sources": [
                        {"type": "openapi", "path": req.openapi_url}
                    ],
                    "runtime": {
                        "endpoint": base_url,
                        "ui_endpoint": base_url,
                        "protocol": "http"
                    },
                    "capabilities": {
                        "max_steps": 5,
                        "context_budget_tokens": 8000,
                        "tools": discovered_tools[:20],  # Limit to 20 discovered tools
                        "destructive_tools": [],
                        "requires_hitl": False
                    },
                    "security": {
                        "pii_fields": ["email", "phone"]
                    }
                }
                yaml_content_str = yaml.dump(manifest_data)
                logging.info(f"Auto-discovered {len(discovered_tools)} capabilities for {agent_name}")
            else:
                raise HTTPException(status_code=400, detail="No audit target provided (YAML, Repo, or OpenAPI required)")
            # A saved agent is tested at the address it was last tested at, not without one
            if req.agent_id and req.yaml_content:
                yaml_content_str = _with_saved_runtime(yaml_content_str, auth_user, req.agent_id, req.agent_kind)
            # Certify means testing the real agent: without an address (or a provider that knows how to reach
            # it, or code to scan) there is nothing real to test, so the audit is refused instead of scored.
            if req.mode != "validate":
                problem = _certify_target_problem(yaml_content_str)
                if problem:
                    raise HTTPException(status_code=400, detail=problem)
        except HTTPException as exc:
            logging.warning("Audit request rejected: %s", exc.detail)
            yield f"data: {_json.dumps({'type': 'error', 'detail': exc.detail})}\n\n"
            return
        except Exception as exc:
            logging.exception("Audit could not start: %s", exc)
            yield f"data: {_json.dumps({'type': 'error', 'detail': str(exc)})}\n\n"
            return

        # If Docker sandbox is active, route to the sandboxed execution flow
        if _USE_DOCKER_SANDBOX:
            yield f"data: {_json.dumps({'type': 'log', 'message': '[info] Starting sandboxed Docker container audit...'})}\n\n"
            with tempfile.TemporaryDirectory(prefix="agent_audit_sandbox_") as host_temp_dir:
                host_temp_path = Path(host_temp_dir)
                docker_args = ["docker", "run", "--rm", "-v", f"{host_temp_dir}:/audit_work"]
                if req.repo_path:
                    # Mount the resolved host repository path to /scan as read-only
                    docker_args.extend(["-v", f"{rp}:/scan:ro"])
                
                target_yaml_file = host_temp_path / "target.yaml"
                target_yaml_file.write_text(yaml_content_str, encoding="utf-8")
                
                container_image = os.environ.get("AA_DOCKER_IMAGE", "agent-audit:latest")
                cmd = docker_args + [
                    container_image,
                    "run",
                    "--target", "/audit_work/target.yaml",
                    "--mode", req.mode,
                    "--variability-runs", str(req.runs),
                    "--concurrency", str(req.concurrency),
                    "--output", "/audit_work/report.json",
                    "--cert-output", "/audit_work/certificate.json",
                    "--log-level", "INFO"
                ]
                try:
                    # Start Docker subprocess asynchronously
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT
                    )
                    
                    # Stream the container's stdout/stderr in real time
                    if proc.stdout is not None:
                        while True:
                            line = await proc.stdout.readline()
                            if not line:
                                break
                            line_str = line.decode("utf-8").rstrip()
                            
                            # Dynamically increment progress based on logs
                            progress_val = 0
                            if "Phase 1" in line_str: progress_val = 15
                            elif "Phase 5" in line_str: progress_val = 40
                            elif "Phase 7" in line_str: progress_val = 60
                            elif "Phase 8" in line_str: progress_val = 80
                            elif "audit complete" in line_str: progress_val = 95
                            
                            if progress_val > 0:
                                yield f"data: {_json.dumps({'type': 'progress', 'val': progress_val})}\n\n"
                            yield f"data: {_json.dumps({'type': 'log', 'message': line_str})}\n\n"
                    
                    await proc.wait()
                    if proc.returncode != 0:
                        yield f"data: {_json.dumps({'type': 'log', 'message': f'[critical] Container process exited with code {proc.returncode}'})}\n\n"
                except Exception as err:
                    _notify_error(f"Sandboxed Docker execution error: {err}")
                    yield f"data: {_json.dumps({'type': 'error', 'detail': f'Sandboxed Docker execution error: {str(err)}'})}\n\n"
                    return
                
                report_json_path = host_temp_path / "report.json"
                cert_json_path = host_temp_path / "certificate.json"
                if not report_json_path.exists() or not cert_json_path.exists():
                    yield f"data: {_json.dumps({'type': 'error', 'detail': 'Docker run completed, but audit output files were not generated.'})}\n\n"
                    return
                
                report_data = _json.loads(report_json_path.read_text(encoding="utf-8"))
                cert_data = _json.loads(cert_json_path.read_text(encoding="utf-8"))
                
                findings_json = report_data.get("findings", [])
                for f in findings_json:
                    if "standards" in f:
                        f["standards"] = [
                            {
                                "framework": s.get("framework", ""),
                                "identifier": s.get("identifier", ""),
                                "name": s.get("name", ""),
                                "url": s.get("url", "https://certifyai.in")
                            }
                            for s in f["standards"]
                        ]
                
                result_payload = {
                    "agent_name": report_data["agent_name"],
                    "started_at": report_data["started_at"],
                    "finished_at": report_data["finished_at"],
                    "audit_id": report_data["audit_id"],
                    "total_duration_ms": report_data["total_duration_ms"],
                    "trust_score": report_data["trust_score"],
                    "enterprise_ready": report_data["enterprise_ready"],
                    "tier": cert_data.get("tier", "NOT_CERTIFIED"),
                    "expires_at": cert_data.get("expires_at"),
                    "days_remaining": cert_data.get("days_remaining", 0),
                    "critical_count": report_data["summary"]["critical_failures"],
                    "warning_count": report_data["summary"]["warnings"],
                    "pass_count": report_data["summary"]["passed"],
                    "info_count": report_data["summary"].get("info", 0),
                    "suppressed_count": report_data["summary"]["suppressed"],
                    "skipped_tests_count": len([f for f in report_data.get("findings", []) if f.get("description", "").startswith("Skipped:")]),
                    "findings": findings_json,
                    "manifest_summary": report_data["manifest"],
                    "phases_run": report_data["phases_run"],
                    "audit_summary": report_data.get("audit_summary", {}),
                    "diagnostics": report_data.get("diagnostics", []),
                    "skipped_phases": report_data.get("skipped_phases", []),
                    "cert": cert_data
                }
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    eff_user_id_raw = auth_user.get("id") if auth_user else None
                    try:
                        eff_user_id = int(eff_user_id_raw) if eff_user_id_raw is not None else 1
                    except (ValueError, TypeError):
                        eff_user_id = 1

                    agent_name_str = str(result_payload.get("agent_name", ""))
                    audit_id_str = str(result_payload.get("audit_id", ""))
                    finished_at_str = str(result_payload.get("finished_at", ""))
                    trust_score_val = float(report_data.get("trust_score", 0.0))
                    duration_ms_val = float(report_data.get("total_duration_ms", 0.0))

                    # Calculate current iteration version
                    cursor.execute("SELECT COUNT(*) FROM all_agent_tests WHERE user_id = ? AND (LOWER(agent_name) = ? OR LOWER(agent_name) = ?) AND COALESCE(mode, '') <> 'validate'", (eff_user_id, agent_name_str.lower(), normalize_agent_name(agent_name_str).lower()))
                    count_row = cursor.fetchone()
                    existing_count = count_row[0] if count_row else 0
                    v_str = f"v{existing_count + 1}"
                    if req.mode == "validate":   # a simulated run is not a version of the agent
                        v_str = "simulated"
                    result_payload["version"] = v_str
                    result_payload["version_num"] = 0 if req.mode == "validate" else existing_count + 1
                    result_payload["simulated"] = req.mode == "validate"

                    # Save to dynamic history
                    _AUDIT_HISTORY[agent_name_str] = result_payload

                    # Generate and store official report PDF locally on disk
                    local_pdf_path = generate_and_store_pdf(result_payload)
                    result_payload["pdf_path"] = local_pdf_path

                    cursor.execute("""
                    INSERT INTO normal_agent_tests (
                        audit_id, user_id, agent_name, mode,
                        runs_count, concurrency, phases_selected, trust_score, tier, enterprise_ready,
                        critical_count, warning_count, pass_count, info_count, duration_ms, created_at, notes, full_result_json, pdf_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        audit_id_str, eff_user_id, agent_name_str,
                        req.mode, req.runs, req.concurrency,
                        _json.dumps(result_payload["phases_run"]), trust_score_val,
                        result_payload["tier"], 1 if result_payload["enterprise_ready"] else 0,
                        result_payload["critical_count"], result_payload["warning_count"],
                        result_payload["pass_count"], result_payload.get("info_count", 0),
                        duration_ms_val, finished_at_str,
                        f"Docker Sandboxed Test ({req.mode} mode) [{v_str}]", _json.dumps(result_payload),
                        local_pdf_path
                    ))
                    conn.commit()

                    # Determine reliable test_run_id
                    test_run_id = cursor.lastrowid
                    if not test_run_id:
                        cursor.execute("SELECT id FROM all_agent_tests WHERE audit_id = ?", (audit_id_str,))
                        tr_row = cursor.fetchone()
                        if tr_row:
                            test_run_id = tr_row["id"] if (isinstance(tr_row, dict) or hasattr(tr_row, "__getitem__")) else tr_row[0]
                    if not test_run_id:
                        test_run_id = None
                    if test_run_id:
                        record_certify_details(cursor, test_run_id,
                                               source=certify_source(req.yaml_content, req.repo_path, req.openapi_url),
                                               repo_path=req.repo_path, openapi_url=req.openapi_url)
                        record_certify_findings(cursor, test_run_id, audit_id_str,
                                                findings_json, finished_at_str)
                        log_activity(cursor, auth_user, "CERTIFY_TEST_RUN",
                                     f"Audited '{agent_name_str}' ({req.mode} mode, sandbox) -> Score: {result_payload['trust_score']}% [{result_payload['tier']}]",
                                     status="SUCCESS" if result_payload["tier"] == "CERTIFIED" else ("WARNING" if result_payload["tier"] == "CONDITIONAL" else "FAILED"),
                                     entity_type="test_run", entity_id=test_run_id)
                        conn.commit()
                    if req.mode != "validate":
                        _notify_result(conn, eff_user_id, agent_name_str, result_payload)

                    # Record or update the agent in the agents table
                    try:
                        cursor.execute("SELECT id FROM agents WHERE user_id = ? AND (LOWER(name) = ? OR LOWER(canonical_name) = ?)", (eff_user_id, agent_name_str.lower(), normalize_agent_name(agent_name_str).lower()))
                        ag_row = cursor.fetchone()
                        ag_id = ag_row["id"] if (ag_row and (isinstance(ag_row, dict) or hasattr(ag_row, "__getitem__"))) else (ag_row[0] if ag_row else None)

                        caps_raw = result_payload.get("capabilities")
                        caps_list: list[Any] = caps_raw if isinstance(caps_raw, list) else []

                        if not ag_id:
                            cursor.execute("""
                            INSERT INTO agents (
                                user_id, name, canonical_name, version, description, status,
                                capabilities, tools_count, destructive_tools, pii_fields, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                eff_user_id,
                                agent_name_str,
                                normalize_agent_name(agent_name_str),
                                v_str,
                                "Autonomous AI agent discovered and registered via CertifyAI test suite.",
                                "ACTIVE",
                                _json.dumps(caps_list),
                                len(caps_list),
                                _json.dumps(result_payload.get("destructive_tools", [])),
                                _json.dumps(result_payload.get("pii_fields", [])),
                                finished_at_str,
                                finished_at_str
                            ))
                            conn.commit()
                            ag_id = cursor.lastrowid
                            if not ag_id:
                                cursor.execute("SELECT id FROM agents WHERE user_id = ? AND (LOWER(name) = ? OR LOWER(canonical_name) = ?)", (eff_user_id, agent_name_str.lower(), normalize_agent_name(agent_name_str).lower()))
                                ag_new_row = cursor.fetchone()
                                ag_id = ag_new_row["id"] if (ag_new_row and (isinstance(ag_new_row, dict) or hasattr(ag_new_row, "__getitem__"))) else (ag_new_row[0] if ag_new_row else None)
                        else:
                            if req.mode != "validate":
                                cursor.execute("UPDATE agents SET version = ?, updated_at = ? WHERE id = ?", (v_str, finished_at_str, ag_id))
                            conn.commit()
                        if ag_id and test_run_id:
                            cursor.execute("UPDATE normal_agent_tests SET agent_id = ? WHERE id = ?", (ag_id, test_run_id))
                            conn.commit()

                    except Exception as ver_err:
                        logging.warning(f"Could not record agent: {ver_err}")
                        try:
                            conn.rollback()
                        except Exception:
                            pass

                    conn.close()
                except Exception as db_e:
                    logging.error(f"Failed to record docker test run: {db_e}")

                yield f"data: {_json.dumps({'type': 'progress', 'val': 100})}\n\n"
                yield f"data: {_json.dumps({'type': 'result', 'data': result_payload})}\n\n"
        
        else:
            # --- Local Execution Stream ---
            from agent_audit.logging_setup import _AuditFormatter, configure_logging
            queue = asyncio.Queue()
            pkg_logger = logging.getLogger("agent_audit")
            configure_logging("INFO")

            # This audit's own log stream. The token travels with the tasks and threads this request starts,
            # so lines from another user's audit running at the same time never reach this stream.
            run_token = object()
            _current_audit.set(run_token)
            queue_handler = QueueLogHandler(queue, run_token, formatter=_AuditFormatter())
            pkg_logger.addHandler(queue_handler)
            
            temp_path = None
            try:
                targets_dir = root_dir / "targets"
                targets_dir.mkdir(parents=True, exist_ok=True)
                fd, temp_name = tempfile.mkstemp(
                    prefix=_TEMP_PREFIX, suffix=".yaml", dir=str(targets_dir)
                )
                temp_path = Path(temp_name)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(yaml_content_str)
                
                manifest = await asyncio.to_thread(load_target, temp_path)
                mock_tools = (req.mode == "validate")
                
                async def run_and_certify():
                    report = await run_audit(
                        manifest,
                        phases=req.selected_phases,
                        mode=req.mode,
                        mock_tools=mock_tools,
                        variability_runs=req.runs,
                        concurrency=req.concurrency,
                        skip_inapplicable=True,
                    )
                    cert = issue_certificate(report, framework_validation_only=mock_tools)
                    return report, cert
                
                # Start audit task in the background
                audit_task = asyncio.create_task(run_and_certify())
                
                # Stream logs as they arrive in the queue
                while not audit_task.done() or not queue.empty():
                    try:
                        log_msg = await asyncio.wait_for(queue.get(), timeout=0.1)
                        progress_val = 0
                        if "Phase 1" in log_msg: progress_val = 15
                        elif "Phase 5" in log_msg: progress_val = 40
                        elif "Phase 7" in log_msg: progress_val = 60
                        elif "Phase 8" in log_msg: progress_val = 80
                        elif "audit complete" in log_msg: progress_val = 95
                        
                        if progress_val > 0:
                            yield f"data: {_json.dumps({'type': 'progress', 'val': progress_val})}\n\n"
                        yield f"data: {_json.dumps({'type': 'log', 'message': log_msg})}\n\n"
                    except asyncio.TimeoutError:
                        continue
                
                # Retrieve final objects
                report, cert = await audit_task
                
                findings_json = []
                for f in report.sorted_findings():
                    f_dict = f.to_dict()
                    if hasattr(f_dict.get("severity"), "name"):
                        f_dict["severity"] = f_dict["severity"].name
                    f_dict["standards"] = [
                        {"framework": s.framework, "identifier": s.identifier, "name": s.name, "url": getattr(s, 'url', 'https://certifyai.in')}
                        for s in getattr(f, 'standards', [])
                    ]
                    findings_json.append(f_dict)
                
                result_payload = {
                    "agent_name": report.agent_name,
                    "started_at": report.started_at,
                    "finished_at": report.finished_at,
                    "audit_id": report.audit_id,
                    "total_duration_ms": report.total_duration_ms,
                    "trust_score": report.trust_score,
                    "enterprise_ready": report.enterprise_ready,
                    "tier": cert.tier,
                    "expires_at": cert.expires_at,
                    "days_remaining": cert.days_remaining,
                    "critical_count": len(report.critical_failures),
                    "warning_count": len(report.warnings),
                    "pass_count": len(report.passes),
                    "info_count": report.info_count,
                    "suppressed_count": len(report.suppressed),
                    "skipped_tests_count": len([f for f in report.findings if f.description and f.description.startswith("Skipped:")]),
                    "findings": findings_json,
                    "manifest_summary": report.manifest_summary,
                    "phases_run": report.phases_run,
                    "audit_summary": getattr(report, "audit_summary", {}),
                    "diagnostics": getattr(report, "diagnostics", []),
                    "skipped_phases": getattr(report, "skipped_phases", []),
                    "untested_phases": getattr(report, "untested_phases", []),
                    "agent_reached": getattr(report, "agent_reached", None),
                    "cert": cert.to_dict()
                }
                # Automatically save test run to persistent database with sequential versioning
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    
                    eff_user_id_raw = auth_user.get("id") if auth_user else None
                    try:
                        eff_user_id = int(eff_user_id_raw) if eff_user_id_raw is not None else 1
                    except (ValueError, TypeError):
                        eff_user_id = 1

                    agent_name_str = str(result_payload.get("agent_name", ""))
                    audit_id_str = str(result_payload.get("audit_id", ""))
                    finished_at_str = str(result_payload.get("finished_at", ""))
                    trust_score_val = float(report.trust_score)
                    duration_ms_val = float(report.total_duration_ms)

                    # Calculate current iteration version
                    cursor.execute("SELECT COUNT(*) FROM all_agent_tests WHERE user_id = ? AND (LOWER(agent_name) = ? OR LOWER(agent_name) = ?) AND COALESCE(mode, '') <> 'validate'", (eff_user_id, agent_name_str.lower(), normalize_agent_name(agent_name_str).lower()))
                    count_row = cursor.fetchone()
                    existing_count = count_row[0] if count_row else 0
                    v_str = f"v{existing_count + 1}"
                    if req.mode == "validate":   # a simulated run is not a version of the agent
                        v_str = "simulated"
                    result_payload["version"] = v_str
                    result_payload["version_num"] = 0 if req.mode == "validate" else existing_count + 1
                    result_payload["simulated"] = req.mode == "validate"

                    # Save to dynamic history
                    _AUDIT_HISTORY[agent_name_str] = result_payload

                    # Generate and store official report PDF locally on disk
                    local_pdf_path = generate_and_store_pdf(result_payload)
                    result_payload["pdf_path"] = local_pdf_path

                    cursor.execute("""
                    INSERT INTO normal_agent_tests (
                        audit_id, user_id, agent_name, mode,
                        runs_count, concurrency, phases_selected, trust_score, tier, enterprise_ready,
                        critical_count, warning_count, pass_count, info_count, duration_ms, created_at, notes, full_result_json, pdf_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        audit_id_str,
                        eff_user_id,
                        agent_name_str,
                        req.mode,
                        req.runs,
                        req.concurrency,
                        _json.dumps(result_payload["phases_run"]),
                        trust_score_val,
                        result_payload["tier"],
                        1 if result_payload["enterprise_ready"] else 0,
                        result_payload["critical_count"],
                        result_payload["warning_count"],
                        result_payload["pass_count"],
                        result_payload.get("info_count", 0),
                        duration_ms_val,
                        finished_at_str,
                        f"UI Test run via Web Dashboard ({req.mode} mode) [{v_str}]",
                        _json.dumps(result_payload),
                        local_pdf_path
                    ))
                    conn.commit()

                    # Determine reliable test_run_id
                    ui_test_run_id = cursor.lastrowid
                    if not ui_test_run_id:
                        cursor.execute("SELECT id FROM all_agent_tests WHERE audit_id = ?", (audit_id_str,))
                        tr_row = cursor.fetchone()
                        if tr_row:
                            ui_test_run_id = tr_row["id"] if (isinstance(tr_row, dict) or hasattr(tr_row, "__getitem__")) else tr_row[0]
                    if not ui_test_run_id:
                        ui_test_run_id = None
                    if ui_test_run_id:
                        record_certify_details(cursor, ui_test_run_id,
                                               source=certify_source(req.yaml_content, req.repo_path, req.openapi_url),
                                               repo_path=req.repo_path, openapi_url=req.openapi_url)
                        record_certify_findings(cursor, ui_test_run_id, audit_id_str,
                                                findings_json, finished_at_str)
                        conn.commit()

                    # Record or update the agent in the agents table
                    try:
                        cursor.execute("SELECT id FROM agents WHERE user_id = ? AND (LOWER(name) = ? OR LOWER(canonical_name) = ?)", (eff_user_id, agent_name_str.lower(), normalize_agent_name(agent_name_str).lower()))
                        ag_row = cursor.fetchone()
                        ag_id = ag_row["id"] if (ag_row and (isinstance(ag_row, dict) or hasattr(ag_row, "__getitem__"))) else (ag_row[0] if ag_row else None)

                        caps_raw = result_payload.get("capabilities")
                        caps_list: list[Any] = caps_raw if isinstance(caps_raw, list) else []

                        if not ag_id:
                            cursor.execute("""
                            INSERT INTO agents (
                                user_id, name, canonical_name, version, description, status,
                                capabilities, tools_count, destructive_tools, pii_fields, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                eff_user_id,
                                agent_name_str,
                                normalize_agent_name(agent_name_str),
                                v_str,
                                "Autonomous AI agent discovered and registered via CertifyAI test suite.",
                                "ACTIVE",
                                _json.dumps(caps_list),
                                len(caps_list),
                                _json.dumps(result_payload.get("destructive_tools", [])),
                                _json.dumps(result_payload.get("pii_fields", [])),
                                finished_at_str,
                                finished_at_str
                            ))
                            conn.commit()
                            ag_id = cursor.lastrowid
                            if not ag_id:
                                cursor.execute("SELECT id FROM agents WHERE user_id = ? AND (LOWER(name) = ? OR LOWER(canonical_name) = ?)", (eff_user_id, agent_name_str.lower(), normalize_agent_name(agent_name_str).lower()))
                                ag_new_row = cursor.fetchone()
                                ag_id = ag_new_row["id"] if (ag_new_row and (isinstance(ag_new_row, dict) or hasattr(ag_new_row, "__getitem__"))) else (ag_new_row[0] if ag_new_row else None)
                        else:
                            if req.mode != "validate":
                                cursor.execute("UPDATE agents SET version = ?, updated_at = ? WHERE id = ?", (v_str, finished_at_str, ag_id))
                            conn.commit()
                        if ag_id and ui_test_run_id:
                            cursor.execute("UPDATE normal_agent_tests SET agent_id = ? WHERE id = ?", (ag_id, ui_test_run_id))
                            conn.commit()

                    except Exception as ver_err:
                        logging.warning(f"Could not record agent: {ver_err}")
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                    
                    # Also write activity log
                    try:
                        log_status = "SUCCESS" if result_payload["tier"] == "CERTIFIED" else ("WARNING" if result_payload["tier"] == "CONDITIONAL" else "FAILED")
                        log_activity(cursor, auth_user, "CERTIFY_TEST_RUN",
                                     f"Audited '{result_payload['agent_name']}' ({req.mode} mode) -> Score: {result_payload['trust_score']}% [{result_payload['tier']}]",
                                     status=log_status, entity_type="test_run", entity_id=ui_test_run_id)
                        conn.commit()
                        if req.mode != "validate":
                            _notify_result(conn, eff_user_id, str(result_payload.get("agent_name") or agent_name_str), result_payload)
                    except Exception as act_err:
                        logging.warning(f"Could not record activity log: {act_err}")
                        try:
                            conn.rollback()
                        except Exception:
                            pass

                    conn.close()
                except Exception as log_err:
                    logging.error(f"Failed to record test run in db: {log_err}")


                yield f"data: {_json.dumps({'type': 'progress', 'val': 100})}\n\n"
                yield f"data: {_json.dumps({'type': 'result', 'data': result_payload})}\n\n"
            
            except Exception as exc:
                logging.exception("Audit failed: %s", exc)
                _notify_error(str(exc))
                yield f"data: {_json.dumps({'type': 'error', 'detail': str(exc)})}\n\n"
            finally:
                pkg_logger.removeHandler(queue_handler)
                if temp_path and temp_path.is_file():
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass

    return StreamingResponse(audit_stream_generator(), media_type="text/event-stream")


def _certify_target_problem(yaml_text: str) -> str | None:
    """Why a Certify audit of this target would test nothing real, or None when it can run."""
    try:
        data = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as e:
        return f"The YAML could not be read: {e}"
    if not isinstance(data, dict):
        return "The YAML must describe one agent."
    runtimes = [data.get("runtime")] + [s.get("runtime") for s in data.get("sources") or [] if isinstance(s, dict)]
    runtimes = [r for r in runtimes if isinstance(r, dict)]
    has_endpoint = any((r.get("endpoint") or "").strip() for r in runtimes)
    has_provider = any(isinstance(r.get("provider"), dict) and (r["provider"].get("name") or "generic") != "generic"
                       for r in runtimes)
    has_code = any(isinstance(s, dict) and s.get("type") in ("repo", "openapi") for s in data.get("sources") or [])
    if has_endpoint or has_provider or has_code:
        return None
    return ("This YAML has no runtime.endpoint, so the agent cannot be reached and Certify would test nothing real. "
            "Add the agent's address under runtime: endpoint:, or use Validate mode to check the setup with simulated answers.")


def _with_saved_runtime(yaml_text: str, user: dict, agent_id: int, agent_kind: str | None) -> str:
    """The YAML with the saved agent's runtime (address, login settings, provider) from its last real audit,
    when the YAML does not give one itself. Only the signed-in user's own agents are used."""
    try:
        data = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError:
        return yaml_text
    if not isinstance(data, dict) or (isinstance(data.get("runtime"), dict) and data["runtime"].get("endpoint")):
        return yaml_text
    runtime = None
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        if agent_kind == "live":
            cur.execute("""SELECT endpoint_url FROM live_agent_tests WHERE live_agent_id = ? AND user_id = ?
                           AND endpoint_url IS NOT NULL ORDER BY created_at DESC, id DESC LIMIT 1""", (agent_id, user.get("id")))
            row = cur.fetchone()
            if row and row["endpoint_url"]:
                runtime = {"endpoint": row["endpoint_url"], "protocol": "http"}
        else:
            cur.execute("""SELECT full_result_json FROM normal_agent_tests WHERE agent_id = ? AND user_id = ?
                           AND COALESCE(mode, '') <> 'validate' ORDER BY created_at DESC, id DESC LIMIT 20""", (agent_id, user.get("id")))
            for row in cur.fetchall():
                try:
                    saved = (_json.loads(row["full_result_json"] or "{}").get("manifest_summary") or {}).get("runtime") or {}
                except ValueError:
                    continue
                provider = saved.get("provider") or {}
                if saved.get("endpoint") or (provider.get("name") or "generic") != "generic":
                    runtime = {k: v for k, v in {
                        "endpoint": saved.get("endpoint"),
                        "protocol": saved.get("protocol") or "http",
                        "target_env": saved.get("target_env"),
                        "timeout_s": saved.get("timeout_s"),
                        "auth": saved.get("auth") if (saved.get("auth") or {}).get("type") not in (None, "none") else None,
                        "provider": provider if (provider.get("name") or "generic") != "generic" else None,
                    }.items() if v not in (None, "", {})}
                    break
    finally:
        conn.close()
    if not runtime:
        return yaml_text
    data["runtime"] = runtime
    return yaml.safe_dump(data, sort_keys=False)


async def _clone_repo(url: str, dest: str) -> None:
    """Shallow-clones a public repository. Refuses addresses on this server or a private network, and gives up
    after AA_GIT_CLONE_TIMEOUT seconds so a slow or hanging host cannot hold the server."""
    if url.startswith("git@"):
        host = url[4:].split(":", 1)[0]
        problem = await asyncio.to_thread(outbound_problem, f"https://{host}/")
    else:
        problem = await asyncio.to_thread(outbound_problem, url)
    if problem:
        raise HTTPException(status_code=400, detail=f"This repository address is not allowed: {problem}")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    proc = await asyncio.create_subprocess_exec(
        "git", "-c", "protocol.file.allow=never", "clone", "--depth", "1", "--", url, dest,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        _, err = await asyncio.wait_for(proc.communicate(), timeout=_GIT_CLONE_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise HTTPException(status_code=400, detail=f"Cloning the repository took longer than {_GIT_CLONE_TIMEOUT} seconds.")
    if proc.returncode != 0:
        raise HTTPException(status_code=400, detail=f"Failed to clone git repository: {err.decode(errors='replace')[:500]}")

if __name__ == "__main__":
    import uvicorn
    server_port = int(os.getenv("PORT", 8000))
    server_host = os.getenv("HOST", "127.0.0.1")
    uvicorn.run("backend:app", host=server_host, port=server_port, reload=True)
