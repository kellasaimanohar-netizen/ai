"""Two static scans that need no calls to the agent.

  scan_openapi   risky routes and routes with no login, read from the OpenAPI description
  scan_repo      database access, delete and drop operations, tools, and hardcoded secrets, read from the code

Both return plain dicts: the detail the page shows, and `findings` in the same shape as the live tests.
Secret values are always masked in what they return.
"""
from __future__ import annotations

import ast
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------------------------
_FINDING_FIELDS = ("category", "title", "severity", "description", "remediation")


def _finding(category: str, title: str, severity: str, description: str, remediation: str, locations: list[str] | None = None) -> dict:
    return {
        "id": f"SCAN-{uuid.uuid4().hex[:8]}", "category": category, "title": title, "severity": severity,
        "description": description, "remediation": remediation, "locations": locations or [],
    }


def mask(value: str) -> str:
    v = value.strip()
    return f"{v[:4]}{'*' * min(8, max(0, len(v) - 4))} ({len(v)} characters)" if len(v) > 4 else "****"


def allowed_repo_base() -> Path:
    """Folders outside this base are never read. Set AA_REPO_BASE to change it (default: the folder that holds this project)."""
    env = os.environ.get("AA_REPO_BASE", "").strip()
    return Path(env).resolve() if env else Path(__file__).resolve().parents[3]


def remove_clone(path) -> None:
    """Delete a temporary clone. Git makes some files read-only, which Windows refuses to delete, so clear that first."""
    import shutil
    import stat

    def _retry(func, target, _exc):
        os.chmod(target, stat.S_IWRITE)
        func(target)

    if not os.path.exists(path):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_retry)
    else:
        shutil.rmtree(path, onerror=_retry)


def _is_our_clone(p: Path) -> bool:
    """True only for a folder this backend cloned itself: directly in the temp folder, named agent_audit_git_*."""
    import tempfile
    return p.parent == Path(tempfile.gettempdir()).resolve() and p.name.startswith("agent_audit_git_")


def resolve_repo(path: str) -> tuple[Path | None, str | None]:
    """The folder to scan, or an error message in plain words. Supports local paths and git URLs."""
    raw = (path or "").strip().strip('"').strip("'")
    if not raw:
        return None, "The repository folder is required."
    if raw.lower().startswith(("http://", "https://", "git@")):
        import tempfile
        import subprocess
        import shutil
        temp_dir = tempfile.mkdtemp(prefix="agent_audit_git_")
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="")
        try:
            subprocess.run(
                ["git", "-c", "credential.helper=", "clone", "--depth", "1", raw, temp_dir],
                check=True,
                capture_output=True,
                text=True,
                env=env,
                timeout=90
            )
            return Path(temp_dir).resolve(), None
        except Exception as e:
            try:
                remove_clone(temp_dir)
            except Exception:
                pass
            err_msg = str(e)
            if hasattr(e, "stderr") and e.stderr:
                err_msg = e.stderr.strip()
            return None, f"Failed to clone repository from {raw}: {err_msg}"

    p = Path(raw).expanduser()
    try:
        p = p.resolve()
    except OSError:
        return None, "The repository folder path is not valid."
    if not p.is_dir():
        return None, f"The repository folder was not found: {raw}"
    base = allowed_repo_base()
    try:
        p.relative_to(base)
    except ValueError:
        if _is_our_clone(p):
            return p, None
        return None, f"The repository folder must be inside {base}. Move it there, or set AA_REPO_BASE on the backend."
    return p, None


# ---------------------------------------------------------------------------------------------
# 1. OpenAPI scan
# ---------------------------------------------------------------------------------------------
_HIGH_WORDS = ("delete", "drop", "truncate", "purge", "destroy", "wipe", "reset", "shell", "exec", "eval", "sql")
_MEDIUM_WORDS = ("admin", "internal", "debug", "config", "setting", "secret", "token", "password", "apikey", "api-key", "user", "account",
                 "export", "dump", "backup", "upload", "download", "database", "console", "actuator", "key")
_SENSITIVE_FIELDS = re.compile(r"(password|passwd|secret|api[_-]?key|token|ssn|aadhaar|aadhar|pan_?no|card_?number|cvv|private[_-]?key)", re.I)
_METHODS = ("get", "post", "put", "patch", "delete")


def _op_requires_login(spec: dict, op: dict) -> bool:
    sec = op.get("security", spec.get("security"))
    if not sec:
        return False
    return any(bool(req) for req in sec)


def _walk_props(spec: dict, schema: Any, depth: int = 0, seen: set | None = None) -> list[str]:
    seen = seen if seen is not None else set()
    out: list[str] = []
    if not isinstance(schema, dict) or depth > 5:
        return out
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        if ref in seen:
            return out
        seen.add(ref)
        cur: Any = spec
        for part in ref[2:].split("/"):
            cur = cur.get(part, {}) if isinstance(cur, dict) else {}
        return _walk_props(spec, cur, depth + 1, seen)
    for k, v in (schema.get("properties") or {}).items():
        out.append(k)
        out += _walk_props(spec, v, depth + 1, seen)
    if isinstance(schema.get("items"), dict):
        out += _walk_props(spec, schema["items"], depth + 1, seen)
    return out


def scan_openapi(spec: dict | None) -> dict:
    if not spec or not isinstance(spec.get("paths"), dict):
        return {"available": False, "routes": [], "findings": [], "summary": {}}
    routes: list[dict] = []
    sensitive_hits: list[str] = []
    for path, item in spec["paths"].items():
        for method in _METHODS:
            op = (item or {}).get(method)
            if not isinstance(op, dict):
                continue
            low = path.lower()
            reasons: list[str] = []
            level = "low"
            if method == "delete":
                level, reasons = "high", ["Uses DELETE"]
            elif method in ("put", "patch"):
                level, reasons = "medium", [f"Uses {method.upper()} (changes data)"]
            hw = [w for w in _HIGH_WORDS if w in low or w in (op.get("operationId") or "").lower()]
            mw = [w for w in _MEDIUM_WORDS if w in low]
            if hw:
                level = "high"
                reasons.append(f"Name suggests a destructive action ({', '.join(hw[:2])})")
            elif mw and level == "low":
                level = "medium"
                reasons.append(f"Name suggests sensitive data or admin use ({', '.join(mw[:2])})")
            if "multipart/form-data" in str(op.get("requestBody", "")):
                reasons.append("Accepts file uploads")
                level = "medium" if level == "low" else level
            body = (((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema")
            fields = _walk_props(spec, body) if body else []
            for r in (op.get("responses") or {}).values():
                fields += _walk_props(spec, (((r or {}).get("content") or {}).get("application/json") or {}).get("schema"))
            hits = sorted({f for f in fields if _SENSITIVE_FIELDS.search(f)})
            if hits:
                reasons.append(f"Handles sensitive fields ({', '.join(hits[:3])})")
                sensitive_hits += [f"{method.upper()} {path}: {h}" for h in hits]
                level = "medium" if level == "low" else level
            routes.append({"method": method.upper(), "path": path, "summary": op.get("summary") or op.get("operationId") or "",
                           "login": _op_requires_login(spec, op), "risk": level, "reasons": reasons})

    findings: list[dict] = []
    open_high = [r for r in routes if r["risk"] == "high" and not r["login"]]
    open_medium = [r for r in routes if r["risk"] == "medium" and not r["login"]]
    risky = [r for r in routes if r["risk"] == "high"]
    if open_high:
        findings.append(_finding("Missing authentication", f"{len(open_high)} risky route(s) need no login", "CRITICAL",
                                 "These routes can delete or change data, or run commands, and the API description says no login is needed.",
                                 "Require authentication on every destructive route, and check permissions for each caller.",
                                 [f"{r['method']} {r['path']}" for r in open_high[:10]]))
    elif risky:
        findings.append(_finding("Risky API", f"{len(risky)} destructive route(s) found", "WARNING",
                                 "These routes can delete data or run actions. They ask for a login, which is good. Check that only the right roles can call them.",
                                 "Limit these routes to administrators and log every call.", [f"{r['method']} {r['path']}" for r in risky[:10]]))
    if open_medium:
        findings.append(_finding("Missing authentication", f"{len(open_medium)} sensitive route(s) need no login", "HIGH",
                                 "These routes change data, handle sensitive fields, or look like admin routes, and need no login.",
                                 "Add authentication, or confirm that the route is meant to be public.",
                                 [f"{r['method']} {r['path']}" for r in open_medium[:10]]))
    if routes and not any(r["login"] for r in routes):
        sev = "WARNING" if not (open_high or open_medium) else "HIGH"
        findings.append(_finding("Missing authentication", "No route asks for a login", sev,
                                 f"None of the {len(routes)} routes declares authentication. Anyone who can reach the server can call them.",
                                 "Declare a security scheme (API key or bearer token) and apply it to the routes, unless the API is meant to be public."))
    if sensitive_hits:
        findings.append(_finding("Data exposure", "Routes handle sensitive fields", "WARNING",
                                 "Passwords, tokens, card numbers or ID numbers appear in request or response fields.",
                                 "Never return secrets in responses. Make sure these routes need a login and are sent over HTTPS.", sensitive_hits[:10]))
    for s in spec.get("servers") or []:
        url = str((s or {}).get("url", ""))
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.|0\.0\.0\.0)", url):
            findings.append(_finding("Transport security", "The API is described with plain HTTP", "WARNING",
                                     f"The server address {url} does not use HTTPS, so traffic can be read on the network.",
                                     "Serve the API over HTTPS only.", [url]))
            break
    return {
        "available": True, "routes": routes[:300], "findings": findings,
        "summary": {"routes": len(routes), "with_login": sum(1 for r in routes if r["login"]), "without_login": sum(1 for r in routes if not r["login"]),
                    "high_risk": len(risky), "medium_risk": sum(1 for r in routes if r["risk"] == "medium")},
    }


# ---------------------------------------------------------------------------------------------
# 2. Repository scan
# ---------------------------------------------------------------------------------------------
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next", ".idea", ".vscode", "site-packages",
             "vendor", ".pytest_cache", ".mypy_cache", "coverage", ".tox"}
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go", ".rb", ".php", ".cs", ".rs", ".kt", ".sh", ".bash", ".ps1", ".sql"}
CONFIG_EXT = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".txt", ".tf"}
LOW_RISK_PARTS = {"test", "tests", "__tests__", "spec", "fixtures", "fixture", "examples", "example", "samples", "sample", "docs", "mock", "mocks", "testdata"}
MAX_FILES = 4000
MAX_BYTES = 1_000_000
MAX_PER_KIND = 40

_DB_PY = re.compile(r"^\s*(?:from|import)\s+(sqlite3|psycopg2|psycopg|asyncpg|sqlalchemy|pymongo|motor|pymysql|mysql\.connector|MySQLdb|peewee|tortoise|databases|redis|prisma|cassandra|neo4j|sqlmodel|pony|django\.db|flask_sqlalchemy|aiosqlite|supabase)\b", re.M)
_DB_JS = re.compile(r"""(?:require\(\s*|from\s+)['"](pg|mysql2?|mongoose|mongodb|sequelize|typeorm|knex|@prisma/client|redis|ioredis|better-sqlite3|sqlite3|@supabase/supabase-js|firebase-admin)['"]""")
_DB_OTHER = re.compile(r"\b(database/sql|java\.sql|javax\.persistence|org\.hibernate|gorm\.io|ActiveRecord|PDO\()")
_DB_URL = re.compile(r"""\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql)://)([^\s:@/'"<>]+):([^\s@/'"<>]+)@([^\s/'"<>]+)""", re.I)
_RAW_SQL = re.compile(r"\b(?:SELECT\s+[\w\*,\s\.`\"]+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b", re.I)
_SQL_BUILT = re.compile(r"""(?:execute|executemany|query|raw)\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+)|[^)]*\.format\()""")

_DESTRUCTIVE: list[tuple[str, str, str, re.Pattern]] = [
    ("DROP", "HIGH", "SQL that drops a table, database or index", re.compile(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW|INDEX)\s+(?:IF\s+EXISTS\s+)?[\w`\"']+", re.I)),
    ("TRUNCATE", "HIGH", "SQL that empties a table", re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?\w+", re.I)),
    ("DELETE without WHERE", "HIGH", "SQL that deletes every row in a table", re.compile(r"""\bDELETE\s+FROM\s+[\w\.\"`]+\s*(?:["'`;)]|$)""", re.I)),
    ("DELETE", "WARNING", "SQL that deletes rows", re.compile(r"\bDELETE\s+FROM\b", re.I)),
    ("ORM drop", "HIGH", "Code that drops every table or the whole database", re.compile(r"\.drop_all\(|dropDatabase\(|\.dropCollection\(|\bdeleteMany\(\s*\{\s*\}\s*\)")),
    ("ORM delete", "WARNING", "Code that deletes records", re.compile(r"\.delete\(\)|session\.delete\(|\.deleteMany\(|\.destroy\(|\.deleteOne\(|\.remove_all\(|objects\.all\(\)\.delete")),
    ("Delete files", "HIGH", "Code that deletes whole folders", re.compile(r"shutil\.rmtree\(|\brm\s+-rf\b|rmdir\s+/s|fs\.rm(?:Sync)?\([^)]*recursive")),
    ("Delete file", "WARNING", "Code that deletes files", re.compile(r"\bos\.remove\(|\bos\.unlink\(|\.unlink\(|fs\.unlink(?:Sync)?\(")),
    ("Run commands", "HIGH", "Code that runs text as code or as a shell command", re.compile(r"(?<!['\"])\b(?:eval|exec)\s*\(|os\.system\(|shell\s*=\s*True|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec")),
]

_TOOL_DECORATORS = {"tool", "function_tool", "register_for_llm", "tool_function", "agent_tool", "kernel_function", "llm_tool", "structured_tool", "mcp_tool"}
_TOOL_JS = re.compile(r"""\b(?:tool|defineTool|createTool|DynamicTool|DynamicStructuredTool)\s*\(\s*\{?[^)]{0,200}?name\s*:\s*['"]([\w\-\.]+)['"]""", re.S)
_DESTRUCTIVE_TOOL = re.compile(r"(delete|drop|remove|truncate|purge|destroy|wipe|exec|shell|run_command|transfer|payment|pay_|refund|send_email|send_mail|write_file|update_|set_)", re.I)
_ROUTE_PY = re.compile(r"""@\w+\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""")
_ROUTE_JS = re.compile(r"""\b(?:app|router)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""")

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("API key (sk-)", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]
_SECRET_ASSIGN = re.compile(
    r"""(?i)\b([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|apikey|auth[_\-]?token|access[_\-]?token|private[_\-]?key|client[_\-]?secret|token)[A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']([^"'\n]{8,})["']""")
_SKIP_KEY = re.compile(r"(?i)(url|path|name|file|header|type|expire|algorithm|endpoint|label|prefix|field|description|hint|placeholder|example|schema|class|format|encoding)")
_PLACEHOLDER = re.compile(r"(?i)(example|changeme|change_me|your[_\-\s]|xxx|\*\*\*|<|>|\{\{|\$\{|\$\(|replace|placeholder|dummy|sample|todo|secret_here|token_here|not[_\-]?set|insert|enter[_\-\s]|my[_\-]?(?:secret|key|token)|\bnone\b|\bnull\b|password$)")
_ENV_NAME_KEY = re.compile(r"(?i)(?:^|_)(?:env|env_?var|var)$")   # token_env: "AGENT_API_TOKEN" names a variable, it is not the secret
_ENV_NAME_VALUE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
_ENV_LOOKUP = re.compile(r"os\.environ|getenv|process\.env|environ\.get|config\(|settings\.|import\.meta\.env|\.env\[|ENV\[")


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    return bool(_PLACEHOLDER.search(v)) or len(set(v)) <= 2 or " " in v


def _low_risk(rel: Path) -> bool:
    parts = {p.lower() for p in rel.parts}
    name = rel.name.lower()
    return bool(parts & LOW_RISK_PARTS) or ".example" in name or ".sample" in name or ".template" in name or name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".spec.ts", ".test.ts"))


def _iter_files(root: Path):
    count = 0
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git")]
        for f in sorted(files):
            fp = Path(dirpath) / f
            ext = fp.suffix.lower()
            if ext in CODE_EXT or ext in CONFIG_EXT or f.startswith(".env") or f.lower() == "dockerfile":
                try:
                    if fp.is_symlink() or fp.stat().st_size > MAX_BYTES:
                        continue
                except OSError:
                    continue
                count += 1
                if count > MAX_FILES:
                    yield None
                    return
                yield fp


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _scan_repo_dir(root: Path) -> dict:

    dbs: dict[str, set[str]] = {}
    conn_strings: list[dict] = []
    raw_sql_files: set[str] = set()
    sql_built: list[dict] = []
    destructive: list[dict] = []
    tools: list[dict] = []
    routes: list[dict] = []
    secrets: list[dict] = []
    env_files: list[str] = []
    scanned = 0
    truncated = False

    for fp in _iter_files(root):
        if fp is None:
            truncated = True
            break
        rel = fp.relative_to(root)
        rels = str(rel).replace("\\", "/")
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned += 1
        low = _low_risk(rel)
        ext = fp.suffix.lower()
        is_code = ext in CODE_EXT

        if fp.name.startswith(".env") and not any(m in fp.name.lower() for m in (".example", ".sample", ".template")):
            env_files.append(rels)

        # database access
        if is_code:
            for m in _DB_PY.finditer(text):
                dbs.setdefault(m.group(1).split(".")[0], set()).add(rels)
            for m in _DB_JS.finditer(text):
                dbs.setdefault(m.group(1), set()).add(rels)
            for m in _DB_OTHER.finditer(text):
                dbs.setdefault(m.group(1), set()).add(rels)
            if _RAW_SQL.search(text):
                raw_sql_files.add(rels)
            for m in _SQL_BUILT.finditer(text):
                if len(sql_built) < MAX_PER_KIND and not low:
                    sql_built.append({"file": rels, "line": _line_of(text, m.start())})
        for m in _DB_URL.finditer(text):
            user, pw = m.group(2), m.group(3)
            if not _is_placeholder(pw) and not _is_placeholder(user) and user.lower() not in ("user", "username") and not _ENV_LOOKUP.search(text[max(0, m.start() - 60):m.start()]):
                conn_strings.append({"file": rels, "line": _line_of(text, m.start()), "kind": m.group(1).rstrip(":/"), "password": mask(pw), "low": low})
            else:
                dbs.setdefault(m.group(1).rstrip(":/"), set()).add(rels)

        # destructive operations
        if is_code and not (low and ext not in (".py", ".js", ".ts")):
            for kind, sev, desc, rx in _DESTRUCTIVE:
                for m in rx.finditer(text):
                    line_no = _line_of(text, m.start())
                    line = text.splitlines()[line_no - 1].strip()[:140] if line_no <= text.count("\n") + 1 else ""
                    if line.startswith(("#", "//", "/*", "*")):
                        continue
                    if kind == "DELETE" and any(d["kind"] == "DELETE without WHERE" and d["file"] == rels and d["line"] == line_no for d in destructive):
                        continue
                    if len([d for d in destructive if d["kind"] == kind]) < MAX_PER_KIND:
                        destructive.append({"kind": kind, "severity": "INFO" if low else sev, "meaning": desc, "file": rels, "line": line_no, "code": line})

        # tools and routes
        if ext == ".py":
            try:
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for dec in node.decorator_list:
                            target = dec.func if isinstance(dec, ast.Call) else dec
                            nm = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
                            if nm in _TOOL_DECORATORS:
                                tools.append({"name": node.name, "file": rels, "line": node.lineno, "destructive": bool(_DESTRUCTIVE_TOOL.search(node.name))})
            except (SyntaxError, ValueError):
                pass
            for m in _ROUTE_PY.finditer(text):
                routes.append({"method": m.group(1).upper(), "path": m.group(2), "file": rels, "line": _line_of(text, m.start())})
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            for m in _TOOL_JS.finditer(text):
                tools.append({"name": m.group(1), "file": rels, "line": _line_of(text, m.start()), "destructive": bool(_DESTRUCTIVE_TOOL.search(m.group(1)))})
            for m in _ROUTE_JS.finditer(text):
                routes.append({"method": m.group(1).upper(), "path": m.group(2), "file": rels, "line": _line_of(text, m.start())})

        # hardcoded secrets
        if len(secrets) < 200:
            for label, rx in _SECRET_PATTERNS:
                for m in rx.finditer(text):
                    secrets.append({"kind": label, "file": rels, "line": _line_of(text, m.start()), "value": mask(m.group(0)), "severity": "INFO" if low else "CRITICAL"})
            for m in _SECRET_ASSIGN.finditer(text):
                key, val = m.group(1), m.group(2)
                line_text = text[text.rfind("\n", 0, m.start()) + 1:text.find("\n", m.end()) if text.find("\n", m.end()) != -1 else len(text)]
                if (_ENV_NAME_KEY.search(key) and _ENV_NAME_VALUE.match(val)) or _SKIP_KEY.search(key) or _is_placeholder(val) or _ENV_LOOKUP.search(line_text) or val.startswith(("http://", "https://", "/", "./")):
                    continue
                secrets.append({"kind": f"Hardcoded value for {key}", "file": rels, "line": _line_of(text, m.start()), "value": mask(val), "severity": "INFO" if low else "HIGH"})
    for c in conn_strings:
        secrets.append({"kind": f"{c['kind']} connection string with a password", "file": c["file"], "line": c["line"], "value": c["password"],
                        "severity": "INFO" if c["low"] else "CRITICAL"})

    # keep one entry per place
    seen = set()
    secrets = [s for s in secrets if not ((s["file"], s["line"]) in seen or seen.add((s["file"], s["line"])))]

    gitignore = ""
    try:
        gitignore = (root / ".gitignore").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pass
    env_ignored = bool(re.search(r"(?m)^\s*\.env(?:\*|\.\*)?\s*$|^\s*\*\.env\s*$|^\s*\.env\.\*", gitignore))

    # ------------------------------------------------------------------ findings
    findings: list[dict] = []
    loc = lambda items, n=8: [f"{i['file']}:{i['line']}" for i in items[:n]]  # noqa: E731

    if dbs:
        names = ", ".join(sorted(dbs))
        findings.append(_finding("Database access", f"The code accesses a database ({names})", "INFO",
                                 f"Database code was found in {len(set().union(*dbs.values()))} file(s). The agent or its API can reach stored data.",
                                 "Use a database account with only the permissions the agent needs. Do not give it permission to drop or delete everything.",
                                 sorted(set().union(*dbs.values()))[:8]))
    if sql_built:
        findings.append(_finding("Database access", "SQL is built from text", "HIGH",
                                 "SQL statements are put together with string formatting. A crafted input can change what the query does (SQL injection).",
                                 "Use parameterized queries or the ORM, and never insert user text into a query string.", loc(sql_built)))
    for kind in ("DROP", "TRUNCATE", "DELETE without WHERE", "ORM drop", "Delete files", "Run commands"):
        items = [d for d in destructive if d["kind"] == kind and d["severity"] != "INFO"]
        if items:
            findings.append(_finding("Delete and drop operations", f"{items[0]['meaning'].capitalize()} ({len(items)})", "HIGH",
                                     f"{items[0]['meaning'].capitalize()} was found in the code. If an agent or a request can trigger it, one mistake or one attack can destroy data.",
                                     "Remove it, or put it behind a human approval and an administrator-only route. Never let the agent reach it.", loc(items)))
    for kind in ("DELETE", "ORM delete", "Delete file"):
        items = [d for d in destructive if d["kind"] == kind and d["severity"] != "INFO"]
        if items:
            findings.append(_finding("Delete and drop operations", f"{items[0]['meaning'].capitalize()} ({len(items)})", "WARNING",
                                     "Delete operations exist in the code. That is normal for some apps, but check who can trigger them.",
                                     "Make sure deletes need a login and a permission check, and keep a backup.", loc(items)))
    bad_tools = [t for t in tools if t["destructive"]]
    if bad_tools:
        findings.append(_finding("Tools", f"{len(bad_tools)} tool(s) can change or delete things", "HIGH",
                                 "The agent has tools whose names suggest deleting, paying, sending or writing: " + ", ".join(t["name"] for t in bad_tools[:6]) + ".",
                                 "Require approval for these tools, and limit what they can touch.", [f"{t['name']} ({t['file']}:{t['line']})" for t in bad_tools[:8]]))
    elif tools:
        findings.append(_finding("Tools", f"{len(tools)} tool(s) found", "INFO", "Tools the agent can call: " + ", ".join(t["name"] for t in tools[:8]) + ".",
                                 "Keep each tool narrow and give it only the access it needs.", [f"{t['name']} ({t['file']}:{t['line']})" for t in tools[:8]]))
    real_secrets = [s for s in secrets if s["severity"] == "CRITICAL"]
    high_secrets = [s for s in secrets if s["severity"] == "HIGH"]
    low_secrets = [s for s in secrets if s["severity"] == "INFO"]
    for s in real_secrets[:15]:
        findings.append(_finding("Hardcoded secrets", f"{s['kind']} is written in the code", "CRITICAL",
                                 f"A secret ({s['value']}) is stored in {s['file']} line {s['line']}. Anyone who can read the repo can use it.",
                                 "Revoke and replace this secret, then load it from an environment variable or a secrets manager.", [f"{s['file']}:{s['line']}"]))
    if high_secrets:
        findings.append(_finding("Hardcoded secrets", f"{len(high_secrets)} password or token value(s) written in the code", "HIGH",
                                 "Values assigned to names like password, secret or token look like real credentials.",
                                 "Move them to environment variables and rotate any that were real.", [f"{s['file']}:{s['line']} ({s['kind']})" for s in high_secrets[:8]]))
    if low_secrets:
        findings.append(_finding("Hardcoded secrets", f"{len(low_secrets)} possible secret(s) in test or example files", "INFO",
                                 "Credential-like values were found in test, example or sample files. They are usually fake.",
                                 "Make sure none of them is a real credential.", [f"{s['file']}:{s['line']}" for s in low_secrets[:8]]))
    if env_files and not env_ignored:
        findings.append(_finding("Hardcoded secrets", "An environment file is not ignored by git", "HIGH",
                                 "A .env file exists and .gitignore does not exclude it, so it may be committed with its secrets.",
                                 "Add .env to .gitignore, and rotate any secret that was committed.", env_files[:5]))
    if truncated:
        findings.append(_finding("Scan limit", f"Only the first {MAX_FILES} files were scanned", "INFO", "The repo is large, so part of it was skipped.", "Scan a smaller folder.", []))

    return {
        "available": True, "path": str(root), "files_scanned": scanned, "truncated": truncated,
        "database": {"used": bool(dbs), "technologies": [{"name": k, "files": sorted(v)[:8]} for k, v in sorted(dbs.items())],
                     "raw_sql_files": len(raw_sql_files), "sql_built_from_text": sql_built},
        "destructive_operations": destructive, "tools": tools[:100], "routes": routes[:200],
        "secrets": secrets[:60], "env_files": env_files, "env_ignored": env_ignored, "findings": findings,
        "summary": {"database_used": bool(dbs), "destructive": len([d for d in destructive if d["severity"] != "INFO"]), "tools": len(tools),
                    "destructive_tools": len(bad_tools), "secrets": len(real_secrets) + len(high_secrets), "routes": len(routes)},
    }

def scan_repo(path: str) -> dict:
    raw = (path or "").strip().strip('"').strip("'")
    if not raw:
        return {"available": False, "error": "The repository folder is required.", "findings": [], "summary": {}}

    root, err = resolve_repo(path)
    if err or root is None:
        return {"available": False, "error": err, "findings": [], "summary": {}}

    is_cloned_here = raw.lower().startswith(("http://", "https://", "git@")) and "agent_audit_git_" in str(root)
    try:
        res = _scan_repo_dir(root)
        if is_cloned_here:
            res["path"] = raw
        return res
    finally:
        if is_cloned_here:
            remove_clone(root)


# ---------------------------------------------------------------------------------------------
# Both scans together
# ---------------------------------------------------------------------------------------------
def combine(openapi: dict, repo: dict) -> list[dict]:
    """Findings that only appear when the API description and the code are read together."""
    out: list[dict] = []
    if not (openapi.get("available") and repo.get("available")):
        return out
    open_routes = [r for r in openapi["routes"] if not r["login"]]
    if repo["database"]["used"] and open_routes:
        out.append(_finding("Database access", "Database-backed routes are open to anyone", "WARNING",
                            f"The code uses a database, and {len(open_routes)} of {len(openapi['routes'])} routes need no login.",
                            "Require a login on routes that read or change stored data.", [f"{r['method']} {r['path']}" for r in open_routes[:8]]))
    deletes = [r for r in repo["routes"] if r["method"] == "DELETE"]
    if deletes and not any(r["login"] for r in openapi["routes"]):
        out.append(_finding("Missing authentication", "The code has delete routes and the API declares no login", "CRITICAL",
                            "DELETE routes exist in the code, and the API description lists no authentication at all.",
                            "Protect every delete route with a login and an administrator permission check.", [f"{r['path']} ({r['file']}:{r['line']})" for r in deletes[:8]]))
    declared = {(r["method"], r["path"]) for r in openapi["routes"]}
    undocumented = [r for r in repo["routes"] if (r["method"], r["path"]) not in declared and r["method"] in ("DELETE", "PUT", "PATCH")]
    if undocumented:
        out.append(_finding("Risky API", "Routes in the code are missing from the API description", "WARNING",
                            "Some data-changing routes exist in the code but not in the OpenAPI description, so they are easy to overlook.",
                            "Keep the API description in step with the code.", [f"{r['method']} {r['path']} ({r['file']}:{r['line']})" for r in undocumented[:8]]))
    return out
