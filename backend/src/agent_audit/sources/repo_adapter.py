"""Repo adapter — scan a source-code folder for agent artifacts.

Discovers:
  * tool functions (any function decorated with names matching known tool
    decorators: ``@tool``, ``@function_tool``, ``@crewai_tool``, LlamaIndex
    ``@FunctionTool``, AutoGen ``@register_for_llm``, etc.)
  * prompt templates (``.j2``, ``.prompt``, ``.txt`` under ``prompts/``)
  * model references (constructor args like ``model="claude-sonnet-4-6"``)
  * dependencies (``pyproject.toml`` / ``requirements.txt``)

Uses ``ast`` from the standard library — **no regex parsing of Python**.
The optional ``libcst`` extra adds richer location info.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

from agent_audit.exceptions import SourceError
from agent_audit.manifest import (
    DependencySpec,
    ModelSpec,
    PromptSpec,
    TargetManifest,
    ToolSpec,
)
from agent_audit.sources.base import SourceAdapter

log = logging.getLogger(__name__)

# Tool decorators we recognise across common agent frameworks
_TOOL_DECORATORS = {
    "tool",                        # LangChain
    "function_tool",               # OpenAI Agents SDK
    "crewai_tool",                 # CrewAI
    "mcp_tool",                    # MCP
    "ToolBuilder",                 # Generic
    "FunctionTool",                # LlamaIndex (FunctionTool.from_defaults / @FunctionTool)
    "fn",                          # LlamaIndex FunctionAgent shorthand
    "register_for_llm",            # Microsoft AutoGen (register a callable for the LLM)
    "register_for_execution",      # Microsoft AutoGen (register a callable for execution)
    "register_function",           # Microsoft AutoGen (functional registration helper)
    "kernel_function",             # Microsoft Semantic Kernel (@kernel_function)
    "FunctionTool",                # Google ADK also uses FunctionTool (shared name)
    "agent_tool",                  # Google ADK AgentTool wrapping
    "component",                   # Haystack (@component decorates pipeline nodes)
    "Tool",                        # PydanticAI / generic Tool(...) registration
    "tool_plain",                  # PydanticAI @agent.tool_plain
}

# Keyword args that typically hold a model identifier string
_MODEL_KWARGS = {"model", "model_name", "model_id"}

# Known model-provider prefixes (rough heuristic for provider detection)
_PROVIDER_HINTS = {
    "claude": "anthropic",
    "gpt-": "openai",
    "gpt4": "openai",
    "o1-": "openai",
    "gemini": "google",
    "llama": "meta",
    "mistral": "mistral",
    "bedrock": "aws",
}

_PROMPT_EXTS = {".j2", ".jinja", ".jinja2", ".prompt", ".txt", ".md"}
_PROMPT_DIR_HINTS = {"prompts", "templates"}


class RepoAdapter(SourceAdapter):
    """Statically analyse a repo for agent artifacts."""

    source_type = "repo"
    default_confidence = 0.6   # static inference from code, not declared

    def extract(self, spec: dict[str, Any], *, agent_name: str) -> TargetManifest:
        path_str = spec.get("path")
        if not path_str:
            raise SourceError("repo source requires 'path'")

        if path_str.startswith(("http://", "https://", "git@")):
            import tempfile
            import subprocess
            temp_repo_dir = tempfile.mkdtemp(prefix="agent_audit_git_")
            try:
                subprocess.run(["git", "clone", "--depth", "1", path_str, temp_repo_dir], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                raise SourceError(f"Failed to clone git repository: {e.stderr.decode(errors='replace')}")
            root = Path(temp_repo_dir).resolve()
        else:
            root = Path(path_str).expanduser()
            if not root.is_dir():
                backend_dir = Path(__file__).resolve().parent.parent.parent.parent
                candidate = (backend_dir / path_str).resolve()
                if candidate.is_dir():
                    root = candidate
                else:
                    log.warning("repo path is not a directory or unavailable in this environment: %s. Skipping repo scan.", path_str)
                    return TargetManifest(agent_name=agent_name)
            else:
                root = root.resolve()

        log.info("RepoAdapter scanning %s", root)

        tools: list[ToolSpec] = []
        prompts: list[PromptSpec] = []
        models: list[ModelSpec] = []

        for py_file in self._iter_python_files(root):
            try:
                src = py_file.read_text(encoding="utf-8")
                tree = ast.parse(src, filename=str(py_file))
            except (SyntaxError, UnicodeDecodeError) as exc:
                log.warning("skipping %s: %s", py_file, exc)
                continue
            self._scan_ast(tree, py_file, root, tools, models)

        for prompt_file in self._iter_prompt_files(root):
            try:
                content = prompt_file.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            prompts.append(PromptSpec(
                name=prompt_file.stem,
                content=content,
                source_location=str(prompt_file.relative_to(root)),
                role="system" if "system" in prompt_file.stem.lower() else "user",
            ))

        deps = self._extract_dependencies(root)

        manifest = TargetManifest(
            agent_name=agent_name,
            prompts=prompts,
            models=models,
            dependencies=deps,
        )
        # RepoAdapter contributes tools independently of declared list
        manifest.capabilities.tools = tools
        manifest.provenance_trail["repo"] = [
            "tools_discovered", "prompts", "models", "dependencies",
        ]
        log.info(
            "RepoAdapter: %d tools, %d prompts, %d models, %d deps",
            len(tools), len(prompts), len(models), len(deps),
        )
        return manifest

    # ─── file iteration ────────────────────────────────────────────────
    @staticmethod
    def _within_root(path: Path, root: Path) -> bool:
        """True only if ``path`` (fully resolved, following symlinks) stays
        inside ``root``. Blocks a malicious repo from using a symlink to pull
        files from outside the audited tree into the scan (scope escape / path
        traversal)."""
        try:
            resolved = path.resolve()
            root_resolved = root.resolve()
        except (OSError, RuntimeError):
            return False
        return resolved == root_resolved or root_resolved in resolved.parents

    @staticmethod
    def _iter_python_files(root: Path) -> list[Path]:
        skip_dirs = {".venv", "venv", "node_modules", "__pycache__", ".git", "build", "dist"}
        out = []
        import os
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip_dirs in-place so os.walk doesn't traverse them
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for f in filenames:
                if f.endswith(".py"):
                    p = Path(dirpath) / f
                    # Reject symlinks (or any path) that resolve outside the repo root.
                    if not RepoAdapter._within_root(p, root):
                        log.warning("skipping %s: resolves outside repo root (symlink escape)", p)
                        continue
                    out.append(p)
        return out

    @staticmethod
    def _iter_prompt_files(root: Path) -> list[Path]:
        """Files under */prompts/* or */templates/* with a known prompt extension."""
        skip_dirs = {".venv", "venv", "node_modules", "__pycache__", ".git", "build", "dist"}
        results: list[Path] = []
        import os
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            parts = Path(dirpath).parts
            if not any(part.lower() in _PROMPT_DIR_HINTS for part in parts):
                continue
            for f in filenames:
                p = Path(dirpath) / f
                if p.suffix.lower() not in _PROMPT_EXTS:
                    continue
                # Don't read files that resolve outside the repo root (symlink escape
                # would exfiltrate arbitrary file contents into a PromptSpec).
                if not RepoAdapter._within_root(p, root):
                    log.warning("skipping prompt %s: resolves outside repo root", p)
                    continue
                results.append(p)
        return results

    # ─── AST scanning ──────────────────────────────────────────────────
    @classmethod
    def _scan_ast(
        cls,
        tree: ast.AST,
        path: Path,
        root: Path,
        tools: list[ToolSpec],
        models: list[ModelSpec],
    ) -> None:
        rel = str(path.relative_to(root))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if cls._is_tool_decorated(node):
                    tools.append(ToolSpec(
                        name=node.name,
                        declared_in=["repo"],
                        source_location=f"{rel}:{node.lineno}",
                    ))
            elif isinstance(node, (ast.Call,)):
                for kw in node.keywords:
                    if kw.arg in _MODEL_KWARGS and isinstance(kw.value, ast.Constant):
                        val = kw.value.value
                        if isinstance(val, str):
                            models.append(ModelSpec(
                                provider=cls._infer_provider(val),
                                model_id=val,
                                source_location=f"{rel}:{node.lineno}",
                            ))

    @staticmethod
    def _is_tool_decorated(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in func.decorator_list:
            name = _decorator_name(dec)
            if name and name in _TOOL_DECORATORS:
                return True
        return False

    @staticmethod
    def _infer_provider(model_id: str) -> str:
        lowered = model_id.lower()
        for hint, provider in _PROVIDER_HINTS.items():
            if hint in lowered:
                return provider
        return "unknown"

    # ─── dependency extraction ─────────────────────────────────────────
    @staticmethod
    def _extract_dependencies(root: Path) -> list[DependencySpec]:
        deps: list[DependencySpec] = []

        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            try:
                import tomllib  # type: ignore[unresolved-import]  # Py3.11+
            except ModuleNotFoundError:  # pragma: no cover - py3.10 fallback
                import tomli as tomllib  # type: ignore[no-redef]
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            except Exception as exc:
                log.warning("failed to parse pyproject.toml: %s", exc)
            else:
                project_deps = data.get("project", {}).get("dependencies", [])
                for dep_spec in project_deps:
                    name, version = _split_pep508(dep_spec)
                    deps.append(DependencySpec(name=name, version=version, source="pypi"))

        req_txt = root / "requirements.txt"
        if req_txt.is_file():
            for line in req_txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                name, version = _split_pep508(line)
                deps.append(DependencySpec(name=name, version=version, source="pypi"))

        return deps


def _decorator_name(dec: ast.expr) -> str | None:
    """Return the leaf name of ``@foo`` / ``@foo.bar`` / ``@foo(...)``."""
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    return None


def _split_pep508(spec: str) -> tuple[str, str | None]:
    """Split 'httpx>=0.27' -> ('httpx', '>=0.27'). No regex — char scan."""
    for i, ch in enumerate(spec):
        if ch in "<>=!~ ":
            name = spec[:i].strip()
            version = spec[i:].strip() or None
            return name, version
    return spec.strip(), None
