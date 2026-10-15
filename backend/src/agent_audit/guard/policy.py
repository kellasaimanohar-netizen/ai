"""Default policy rules for CertifyAI Guard.

Rules are pure functions ``ProposedCall -> RuleOutcome | None``. They are
argument-aware: the danger is usually in the arguments, not the verb name. Each
rule abstains (returns None) unless it has an opinion, so rules compose and the
engine takes the most-restrictive verdict.

The catalogue below is intentionally conservative and explainable — every BLOCK
carries a human-readable reason. Customers extend or override via their own rule
list; these are the safe defaults.
"""
from __future__ import annotations

import re

from agent_audit.guard import Decision, ProposedCall, RuleOutcome

# Verbs that change or destroy state. Kept in sync with the monitor/Bedrock
# destructive-hint lists so detection and enforcement agree.
DESTRUCTIVE_VERBS = (
    "delete", "remove", "drop", "wipe", "erase", "purge", "destroy", "truncate",
    "terminate", "revoke", "cancel", "refund", "transfer", "pay", "charge",
    "withdraw", "deactivate", "disable", "reset", "overwrite", "format",
    "uninstall", "shutdown", "kill", "expire",
)

# Argument values that signal a *broad* / unscoped blast radius.
_BROAD_SCOPE_PATTERNS = (
    re.compile(r"^\s*/\s*$"),                    # root path "/"
    re.compile(r"^/(etc|var|usr|bin|boot|dev|root|home)(/|$)"),  # system paths
    re.compile(r"/dev/null$"),                    # the classic footgun
    re.compile(r"[*?]"),                          # glob wildcards
    re.compile(r"--?force\b|--?recursive\b|-rf\b|-fr\b"),  # force/recursive flags
    re.compile(r"\ball\b|\beverything\b|\*"),    # "all", "everything"
)

# SQL/command shapes that delete/modify without a *real* filter = mass mutation.
# DROP/TRUNCATE are always unscoped; DELETE/UPDATE are unscoped with no WHERE.
_UNSCOPED_MUTATION = re.compile(
    r"\b(drop|truncate)\b"
    r"|\b(delete|update)\b(?!.*\bwhere\b)",
    re.IGNORECASE | re.DOTALL)

# A WHERE clause that matches every row (tautology) — a mass-mutation bypass.
_TAUTOLOGY = re.compile(
    r"\b(delete|update)\b.*\bwhere\b\s*(?:"
      r"1\s*=\s*1"
      r"|true\b"
      r"|(['\"]?)([\w]+)\2\s*=\s*(['\"]?)\3\4"       # 'a'='a', a=a, '1'='1'
    r")", re.IGNORECASE | re.DOTALL)

# Tokens that indicate a production / live target.
_PROD_HINTS = ("prod", "production", "live", "main", "master")


def _arg_values(call: ProposedCall) -> list[str]:
    """All argument values *and keys* as individual strings.

    Keys are included because a hostile or malformed call can hide a
    catastrophic token in a dictionary key (e.g. ``{"rm -rf /": {...}}``)
    rather than a value; scanning values alone would miss it. Found by
    property-based fuzzing (FINDING 7)."""
    out: list[str] = []
    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                s_k = str(k)
                if len(s_k) > 10000:
                    s_k = s_k[:5000] + s_k[-5000:]
                out.append(s_k)
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
        else:
            s_v = str(v)
            if len(s_v) > 10000:
                s_v = s_v[:5000] + s_v[-5000:]
            out.append(s_v)
    walk(call.args)
    return out


def _flat_arg_text(call: ProposedCall) -> str:
    """Flatten name + all argument values to one lowercased string for scanning."""
    return " ".join([str(call.name), *_arg_values(call)]).lower()


def _has_broad_scope(call: ProposedCall) -> bool:
    """True if the tool name OR any individual argument value signals a broad /
    unscoped blast radius. Checking values individually (not the concatenated
    blob) is what catches ``path='/'`` and ``dst='/dev/null'``."""
    candidates = [str(call.name).lower(), *(v.lower() for v in _arg_values(call))]
    # also scan the joined text for flag-style patterns like "rm -rf /"
    candidates.append(_flat_arg_text(call))
    return any(p.search(c) for c in candidates for p in _BROAD_SCOPE_PATTERNS)


def _arg_text_only(call: ProposedCall) -> str:
    """Argument values only (excludes the tool name) — for content rules that
    must not match on the verb name itself."""
    return " ".join(_arg_values(call)).lower()


def is_destructive(call: ProposedCall) -> bool:
    """Destructive if the verb name OR an argument value carries a destructive
    verb (e.g. a benign-named tool whose argument is 'DELETE FROM ...')."""
    n = (call.name or "").lower()
    if any(v in n for v in DESTRUCTIVE_VERBS):
        return True
    text = _arg_text_only(call)
    return any(re.search(rf"\b{v}\b", text) for v in DESTRUCTIVE_VERBS)


def is_major(call: ProposedCall) -> bool:
    """Is this a 'major' action (destructive verb, broad-scope arguments, OR a
    catastrophic argument pattern)? Used to key the fail-closed posture."""
    if is_destructive(call) or _has_broad_scope(call):
        return True
    text = _flat_arg_text(call)
    return any(p.search(text) for p in _DANGEROUS_ARG_PATTERNS)


# ── the default rules ────────────────────────────────────────────────────────
# Argument content that is dangerous regardless of the tool's name — the
# 'cp looked benign but cp ... /dev/null was catastrophic' lesson.
_DANGEROUS_ARG_PATTERNS = (
    re.compile(r"/dev/null\b"),
    re.compile(r"\brm\s+-[rf]{1,2}\b|\brm\s+-[a-z]*[rf]"),   # rm -rf / rm -fr
    re.compile(r":\s*>\s*/"),                                  # truncate-to-file
    re.compile(r"\bmkfs\b|\bdd\s+if=|\b>\s*/dev/sd"),         # disk wipe
    re.compile(r"\bdrop\s+(database|table|schema)\b", re.IGNORECASE),
    re.compile(r"\bformat\s+[a-z]:", re.IGNORECASE),          # format C:
)


def rule_block_destructive_broad_scope(call: ProposedCall) -> RuleOutcome | None:
    """The catastrophic combo: a destructive verb + a broad/unscoped target.
    This is the 'delete everything' / 'rm -rf /' / 'cp ... /dev/null' class."""
    if not is_destructive(call):
        return None
    if _has_broad_scope(call):
        return RuleOutcome(
            Decision.BLOCK, "destructive_broad_scope",
            f"destructive action '{call.name}' targets a broad/unscoped "
            f"resource — blocked to prevent a mass-destruction footgun")
    return None


def rule_block_dangerous_arguments(call: ProposedCall) -> RuleOutcome | None:
    """Block catastrophic argument patterns even when the VERB looks benign.

    A tool named ``copy``/``run``/``exec`` is not destructive by name, but
    ``copy(dst='/dev/null')`` or ``run(cmd='rm -rf /')`` is. This rule inspects
    argument *content* independent of the verb — the exact class of mistake a
    name-only heuristic misses (and that a real operator once made)."""
    text = _flat_arg_text(call)
    for pat in _DANGEROUS_ARG_PATTERNS:
        if pat.search(text):
            return RuleOutcome(
                Decision.BLOCK, "dangerous_arguments",
                f"'{call.name}' carries a catastrophic argument pattern "
                f"({pat.pattern}) — blocked regardless of the tool name")
    return None


def rule_block_unscoped_mutation(call: ProposedCall) -> RuleOutcome | None:
    """A DELETE/UPDATE/DROP/TRUNCATE that affects every row = mass mutation.
    Blocks when there is no WHERE clause, when the statement is DDL (DROP/TRUNCATE),
    or when the WHERE is a tautology (WHERE 1=1 / true / 'a'='a') that matches all
    rows. Scans argument VALUES only, so a tool merely *named* 'delete' isn't treated
    as an unscoped SQL statement (that path is handled by the destructive rules)."""
    text = _arg_text_only(call)
    if _UNSCOPED_MUTATION.search(text) or _TAUTOLOGY.search(text):
        return RuleOutcome(
            Decision.BLOCK, "unscoped_mutation",
            "data mutation with no effective filter (missing or tautological "
            "WHERE) would affect all rows")
    return None


def rule_approve_destructive_in_production(call: ProposedCall) -> RuleOutcome | None:
    """A (scoped) destructive action against a production target needs a human."""
    if not is_destructive(call):
        return None
    prod = call.target_env.lower() in _PROD_HINTS
    if not prod:
        text = _flat_arg_text(call)
        prod = any(h in text for h in _PROD_HINTS)
    if prod:
        return RuleOutcome(
            Decision.REQUIRE_APPROVAL, "destructive_in_production",
            f"destructive action '{call.name}' targets production — "
            "requires human approval before it runs")
    return None


def rule_approve_destructive_default(call: ProposedCall) -> RuleOutcome | None:
    """Any other destructive action is held for approval (conservative default).
    Non-destructive calls are unaffected (rule abstains)."""
    if is_destructive(call):
        return RuleOutcome(
            Decision.REQUIRE_APPROVAL, "destructive_default",
            f"'{call.name}' is a state-changing action — held for approval")
    return None


def default_rules() -> list:
    """The conservative default policy, most-specific first."""
    return [
        rule_block_destructive_broad_scope,   # BLOCK: destroy + broad scope
        rule_block_dangerous_arguments,       # BLOCK: catastrophic arg pattern (any verb)
        rule_block_unscoped_mutation,         # BLOCK: mass DB mutation
        rule_approve_destructive_in_production,  # APPROVE: prod destructive
        rule_approve_destructive_default,     # APPROVE: any other destructive
    ]
