import json
from typing import List, Dict, Any, Optional

# Validate mode runs against a built-in simulator, not the user's agent. Its runs are listed, labeled
# Simulated, but never counted in an agent's versions, scores, averages or certification counts.
SIMULATED_MODE = "validate"
REAL_RUNS_SQL = "COALESCE(mode, '') <> 'validate'"


def is_simulated(run: Dict[str, Any]) -> bool:
    return str(run.get("mode") or "").lower() == SIMULATED_MODE


def _orphan_live(run: Dict[str, Any]) -> bool:
    """A live run whose live agent was removed. It stays in the test history but is not shown as an agent."""
    return run.get("mode") == "live_probe" and "live_agent_id" in run and run.get("live_agent_id") is None


def normalize_agent_name(name: str) -> str:
    """Canonicalizes agent names like hr_compensation_agent -> HR Compensation Agent."""
    if not name:
        return "Unknown Agent"
    clean = str(name).strip()
    clean_lower = clean.lower().replace("_", " ").replace("-", " ")
    mapping = {
        "hr compensation agent": "HR Compensation Agent",
        "sales assistant agent": "Sales Assistant Agent",
        "sales assistant": "Sales Assistant Agent",
        "support dispatch agent": "Support Dispatch Agent",
        "support dispatch": "Support Dispatch Agent",
        "voice dispatch agent v7": "Voice Dispatch Agent v7",
        "voice dispatch agent": "Voice Dispatch Agent v7",
        "voice dispatch": "Voice Dispatch Agent v7",
        "data analyst agent": "Data Analyst Agent",
        "data analyst": "Data Analyst Agent",
        "test suite agent": "Test Suite Agent"
    }
    if clean_lower in mapping:
        return mapping[clean_lower]
    if "_" in clean:
        return " ".join(word.capitalize() for word in clean.split("_"))
    return clean


def compute_agent_versions(all_test_runs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Groups test runs by normalized agent name and sorts them chronologically.
    Assigns v1, v2, v3, etc. to each run, with score deltas and latest flags. Simulated runs get no version.
    """
    runs_by_agent: Dict[str, List[Dict[str, Any]]] = {}
    for r in all_test_runs:
        if is_simulated(r):
            continue
        norm_name = normalize_agent_name(r.get("agent_name", ""))
        if norm_name not in runs_by_agent:
            runs_by_agent[norm_name] = []
        runs_by_agent[norm_name].append(dict(r))

    # Sort each agent's runs chronologically by created_at, then id
    for agent_name, runs in runs_by_agent.items():
        runs.sort(key=lambda x: (str(x.get("created_at") or ""), x.get("id") or 0))
        for idx, run in enumerate(runs):
            v_num = idx + 1
            run["version"] = f"v{v_num}"
            run["version_num"] = v_num
            run["version_label"] = f"v{v_num}"
            run["is_latest"] = (idx == len(runs) - 1)
            run["canonical_agent_name"] = agent_name
            if idx > 0 and runs[idx - 1].get("trust_score") is not None and run.get("trust_score") is not None:
                prev_score = float(runs[idx - 1]["trust_score"])
                curr_score = float(run["trust_score"])
                run["score_delta"] = round(curr_score - prev_score, 1)
            else:
                run["score_delta"] = 0.0

    return runs_by_agent


def enrich_test_runs_with_versions(test_runs: List[Dict[str, Any]], all_historical_runs: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Enriches each test run in a list with its corresponding v1, v2, v3 version tag and score delta."""
    reference_runs = all_historical_runs if all_historical_runs is not None else test_runs
    version_map = compute_agent_versions(reference_runs)

    # Build lookup by id or audit_id
    lookup_by_id = {}
    for ag_name, runs in version_map.items():
        for r in runs:
            if r.get("id") is not None:
                lookup_by_id[r["id"]] = r
            if r.get("audit_id"):
                lookup_by_id[r["audit_id"]] = r

    enriched = []
    for tr in test_runs:
        tr_dict = dict(tr)
        meta = lookup_by_id.get(tr_dict.get("id")) or lookup_by_id.get(tr_dict.get("audit_id"))
        tr_dict["simulated"] = is_simulated(tr_dict)
        if tr_dict["simulated"]:
            tr_dict["version"] = "simulated"
            tr_dict["version_num"] = 0
            tr_dict["version_label"] = "Simulated"
            tr_dict["is_latest"] = False
            tr_dict["score_delta"] = 0.0
            tr_dict["canonical_agent_name"] = normalize_agent_name(tr_dict.get("agent_name", ""))
        elif meta:
            tr_dict["version"] = meta["version"]
            tr_dict["version_num"] = meta["version_num"]
            tr_dict["version_label"] = meta["version_label"]
            tr_dict["is_latest"] = meta["is_latest"]
            tr_dict["score_delta"] = meta.get("score_delta", 0.0)
            tr_dict["canonical_agent_name"] = meta.get("canonical_agent_name", normalize_agent_name(tr_dict.get("agent_name", "")))
        else:
            tr_dict["version"] = "v1"
            tr_dict["version_num"] = 1
            tr_dict["version_label"] = "v1"
            tr_dict["is_latest"] = True
            tr_dict["score_delta"] = 0.0
            tr_dict["canonical_agent_name"] = normalize_agent_name(tr_dict.get("agent_name", ""))
        enriched.append(tr_dict)

    return enriched


def group_agents_with_versions(agents: List[Dict[str, Any]], all_test_runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups all test runs for each agent into ONE unified instance with v1, v2, v3... version history.
    Scores and versions come from real runs only; simulated runs are listed apart under simulated_runs.
    """
    versioned_runs_by_agent = compute_agent_versions(all_test_runs)
    simulated_by_agent: Dict[str, List[Dict[str, Any]]] = {}
    for r in all_test_runs:
        if is_simulated(r):
            simulated_by_agent.setdefault(normalize_agent_name(r.get("agent_name", "")), []).append({
                "id": r.get("id"), "audit_id": r.get("audit_id"), "mode": r.get("mode"), "tier": r.get("tier"),
                "trust_score": r.get("trust_score"), "created_at": r.get("created_at"), "simulated": True,
            })

    result = []
    seen_agent_names = set()

    # 1. Process catalog agents
    for ag in agents:
        norm_name = normalize_agent_name(ag["name"])
        seen_agent_names.add(norm_name)
        ag_runs = versioned_runs_by_agent.get(norm_name, [])

        latest_run = ag_runs[-1] if ag_runs else None
        first_run = ag_runs[0] if ag_runs else None

        scores = [float(r["trust_score"]) for r in ag_runs if r.get("trust_score") is not None]
        first_score = float(first_run["trust_score"]) if first_run and first_run.get("trust_score") is not None else None
        latest_score = float(latest_run["trust_score"]) if latest_run and latest_run.get("trust_score") is not None else None

        score_improvement = None
        if first_score is not None and latest_score is not None:
            score_improvement = round(latest_score - first_score, 1)

        version_progression = []
        for idx, r in enumerate(ag_runs):
            prev_run = ag_runs[idx - 1] if idx > 0 else None
            prev_sc = float(prev_run["trust_score"]) if prev_run and prev_run.get("trust_score") is not None else None
            curr_sc = float(r.get("trust_score", 0.0))
            delta = round(curr_sc - prev_sc, 1) if prev_sc is not None else 0.0
            version_progression.append({
                "version": r["version"],
                "version_num": r["version_num"],
                "score": curr_sc,
                "trust_score": curr_sc,
                "tier": r.get("tier", "NOT_CERTIFIED"),
                "status": r.get("tier", "NOT_CERTIFIED"),
                "created_at": r.get("created_at"),
                "audit_id": r.get("audit_id"),
                "test_id": r.get("id"),
                "id": r.get("id"),
                "critical_count": r.get("critical_count", 0),
                "warning_count": r.get("warning_count", 0),
                "pass_count": r.get("pass_count", 0),
                "duration_ms": r.get("duration_ms", 0),
                "mode": r.get("mode", "validate"),
                "notes": r.get("notes"),
                "score_delta": delta,
                "previous_version": prev_run["version"] if prev_run else None,
                "previous_score": prev_sc
            })

        prev_run_final = ag_runs[-2] if len(ag_runs) >= 2 else None
        prev_score_final = float(prev_run_final["trust_score"]) if prev_run_final and prev_run_final.get("trust_score") is not None else None
        curr_delta_final = round(latest_score - prev_score_final, 1) if (latest_score is not None and prev_score_final is not None) else 0.0

        result.append({
            "id": ag["id"],
            "agent_kind": ag.get("agent_kind"),   # "certify" or "live": where its last address is kept
            "name": ag["name"],
            "agent_name": ag["name"],
            "canonical_name": norm_name,
            "version": ag.get("version", "1.0"),
            "description": ag.get("description", ""),
            "capabilities": json.loads(ag["capabilities"]) if isinstance(ag.get("capabilities"), str) else (ag.get("capabilities") or []),
            "tools_count": ag.get("tools_count", 0),
            "destructive_tools": json.loads(ag["destructive_tools"]) if isinstance(ag.get("destructive_tools"), str) else (ag.get("destructive_tools") or []),
            "pii_fields": json.loads(ag["pii_fields"]) if isinstance(ag.get("pii_fields"), str) else (ag.get("pii_fields") or []),
            "total_iterations": len(ag_runs),
            "total_tests": len(ag_runs),
            "user_test_count": len(ag_runs),
            "latest_version": latest_run["version"] if latest_run else "UNTESTED",
            "current_version": latest_run["version"] if latest_run else "UNTESTED",
            "latest_score": latest_score,
            "current_score": latest_score,
            "previous_version": prev_run_final["version"] if prev_run_final else None,
            "previous_score": prev_score_final,
            "score_change": curr_delta_final,
            "previous_status": prev_run_final.get("tier") if prev_run_final else None,
            "latest_status": latest_run["tier"] if latest_run else "UNTESTED",
            "current_status": latest_run["tier"] if latest_run else "UNTESTED",
            "latest_tier": latest_run["tier"] if latest_run else "UNTESTED",
            "tier": latest_run["tier"] if latest_run else "UNTESTED",
            "latest_critical_count": latest_run.get("critical_count", 0) if latest_run else 0,
            "latest_warning_count": latest_run.get("warning_count", 0) if latest_run else 0,
            "latest_pass_count": latest_run.get("pass_count", 0) if latest_run else 0,
            "previous_critical_count": prev_run_final.get("critical_count", 0) if prev_run_final else 0,
            "previous_warning_count": prev_run_final.get("warning_count", 0) if prev_run_final else 0,
            "previous_pass_count": prev_run_final.get("pass_count", 0) if prev_run_final else 0,
            "latest_audit_id": latest_run["audit_id"] if latest_run else None,
            "last_tested": latest_run["created_at"] if latest_run else None,
            "last_tested_by": latest_run.get("tested_by_name") if latest_run else None,
            "first_score": first_score,
            "score_improvement": score_improvement,
            "avg_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
            "best_score": max(scores) if scores else None,
            "lowest_score": min(scores) if scores else None,
            "version_progression": version_progression,
            "versions": ag_runs,
            "simulated_runs": simulated_by_agent.get(norm_name, []),
            "simulated_count": len(simulated_by_agent.get(norm_name, [])),
        })

    # 2. Add dynamically evaluated agents not in catalog (not ones whose live agent was removed)
    for agent_name, ag_runs in versioned_runs_by_agent.items():
        if agent_name not in seen_agent_names and ag_runs and not all(_orphan_live(r) for r in ag_runs):
            seen_agent_names.add(agent_name)
            latest_run = ag_runs[-1]
            first_run = ag_runs[0]
            scores = [float(r["trust_score"]) for r in ag_runs if r.get("trust_score") is not None]
            first_score = float(first_run["trust_score"]) if first_run and first_run.get("trust_score") is not None else None
            latest_score = float(latest_run["trust_score"]) if latest_run and latest_run.get("trust_score") is not None else None

            score_improvement = None
            if first_score is not None and latest_score is not None:
                score_improvement = round(latest_score - first_score, 1)

            version_progression = []
            for idx, r in enumerate(ag_runs):
                prev_run = ag_runs[idx - 1] if idx > 0 else None
                prev_sc = float(prev_run["trust_score"]) if prev_run and prev_run.get("trust_score") is not None else None
                curr_sc = float(r.get("trust_score", 0.0))
                delta = round(curr_sc - prev_sc, 1) if prev_sc is not None else 0.0
                version_progression.append({
                    "version": r["version"],
                    "version_num": r["version_num"],
                    "score": curr_sc,
                    "trust_score": curr_sc,
                    "tier": r.get("tier", "NOT_CERTIFIED"),
                    "status": r.get("tier", "NOT_CERTIFIED"),
                    "created_at": r.get("created_at"),
                    "audit_id": r.get("audit_id"),
                    "test_id": r.get("id"),
                    "id": r.get("id"),
                    "critical_count": r.get("critical_count", 0),
                    "warning_count": r.get("warning_count", 0),
                    "pass_count": r.get("pass_count", 0),
                    "duration_ms": r.get("duration_ms", 0),
                    "mode": r.get("mode", "validate"),
                    "notes": r.get("notes"),
                    "score_delta": delta,
                    "previous_version": prev_run["version"] if prev_run else None,
                    "previous_score": prev_sc
                })

            prev_run_final = ag_runs[-2] if len(ag_runs) >= 2 else None
            prev_score_final = float(prev_run_final["trust_score"]) if prev_run_final and prev_run_final.get("trust_score") is not None else None
            curr_delta_final = round(latest_score - prev_score_final, 1) if (latest_score is not None and prev_score_final is not None) else 0.0

            result.append({
                "id": f"dyn-{agent_name.lower().replace(' ', '-')}",
                "name": agent_name,
                "agent_name": agent_name,
                "canonical_name": agent_name,
                "version": "1.0",
                "description": f"Autonomous AI Agent evaluated in CertifyAI sandbox.",
                "capabilities": ["autonomous-action", "multi-turn-eval"],
                "tools_count": 2,
                "destructive_tools": [],
                "pii_fields": [],
                "total_iterations": len(ag_runs),
                "total_tests": len(ag_runs),
                "user_test_count": len(ag_runs),
                "latest_version": latest_run["version"],
                "current_version": latest_run["version"],
                "latest_score": latest_score,
                "current_score": latest_score,
                "previous_version": prev_run_final["version"] if prev_run_final else None,
                "previous_score": prev_score_final,
                "score_change": curr_delta_final,
                "previous_status": prev_run_final.get("tier") if prev_run_final else None,
                "latest_status": latest_run["tier"],
                "current_status": latest_run["tier"],
                "latest_tier": latest_run["tier"],
                "tier": latest_run["tier"],
                "latest_critical_count": latest_run.get("critical_count", 0) if latest_run else 0,
                "latest_warning_count": latest_run.get("warning_count", 0) if latest_run else 0,
                "latest_pass_count": latest_run.get("pass_count", 0) if latest_run else 0,
                "previous_critical_count": prev_run_final.get("critical_count", 0) if prev_run_final else 0,
                "previous_warning_count": prev_run_final.get("warning_count", 0) if prev_run_final else 0,
                "previous_pass_count": prev_run_final.get("pass_count", 0) if prev_run_final else 0,
                "latest_audit_id": latest_run["audit_id"],
                "last_tested": latest_run["created_at"],
                "last_tested_by": latest_run.get("tested_by_name"),
                "first_score": first_score,
                "score_improvement": score_improvement,
                "avg_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
                "best_score": max(scores) if scores else None,
                "lowest_score": min(scores) if scores else None,
                "version_progression": version_progression,
                "versions": ag_runs,
                "simulated_runs": simulated_by_agent.get(agent_name, []),
                "simulated_count": len(simulated_by_agent.get(agent_name, [])),
            })

    return result
