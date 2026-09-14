"""Phase 6c/7: the graph's node functions."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Literal

from src.agent.confidence import compute_confidence
from src.agent.llm_client import LLMClient
from src.agent.summary import embed_text, format_summary_prompt, select_key_evidence
from src.agent.tool_binding import build_tool_kwargs
from src.agent.tool_schemas import tool_schemas_for_alert_type
from src.tools.registry import ToolRegistry

AUTO_RESOLVE_THRESHOLD = 0.7
LATERAL_MOVEMENT_THRESHOLD = 0.4


def planner_node(state: dict, llm_client: LLMClient) -> dict:
    tool_schemas = tool_schemas_for_alert_type(state["alert_type"])
    decision = llm_client.call_planner(
        state["alert_type"], state["raw_evidence"], state["evidence"], tool_schemas
    )
    return {
        "planner_decision": decision,
        "planning_count": state["planning_count"] + 1,
    }


def tool_execution_node(state: dict, registry: ToolRegistry, data_sources: dict) -> dict:
    tool_name = state["planner_decision"]["tool_name"]
    kwargs = build_tool_kwargs(tool_name, state, data_sources)
    result, new_breakers = registry.dispatch(tool_name, state["circuit_breakers"], **kwargs)

    new_evidence_entry = {
        "tool_name": result.tool_name,
        "result_summary": result.evidence,
        "status": result.status,
        "timestamp": result.timestamp,
    }
    return {
        "evidence": state["evidence"] + [new_evidence_entry],
        "circuit_breakers": new_breakers,
        "tool_call_count": state["tool_call_count"] + 1,
    }


def reflect_node(state: dict, llm_client: LLMClient) -> dict:
    decision = llm_client.call_reflect(state["alert_type"], state["raw_evidence"], state["evidence"])
    return {"reflection_decision": decision["decision"]}


def verdict_escalate_node(state: dict) -> dict:
    """Only job: force escalation_flag before rejoining the shared verdict node."""
    return {"escalation_flag": True}


def verdict_node(state: dict) -> dict:
    confidence_score, leaning = compute_confidence(state["alert_type"], state["evidence"])
    return {
        "confidence_score": confidence_score,
        "verdict": leaning,
        "verdict_timestamp": datetime.now(timezone.utc),
    }


def route_after_verdict(state: dict) -> Literal["escalate", "auto_resolve"]:
    threshold = (
        LATERAL_MOVEMENT_THRESHOLD
        if state["alert_type"] == "lateral_movement"
        else AUTO_RESOLVE_THRESHOLD
    )
    if state["escalation_flag"] or state["confidence_score"] < threshold:
        return "escalate"
    return "auto_resolve"


def escalate_node(state: dict) -> dict:
    return {"escalation_flag": True}


def auto_resolve_node(state: dict) -> dict:
    return {}


INSERT_INVESTIGATION_SQL = """
    INSERT INTO investigations
        (alert_id, alert_type, source, source_ip, dest_ip, user_id, sender_domain,
         verdict, confidence_score, escalation_flag, planning_count, tool_call_count,
         start_timestamp, verdict_timestamp, evidence, is_synthetic, true_label,
         summary_text, embedding)
    VALUES
        (%(alert_id)s, %(alert_type)s, %(source)s, %(source_ip)s, %(dest_ip)s,
         %(user_id)s, %(sender_domain)s, %(verdict)s, %(confidence_score)s,
         %(escalation_flag)s, %(planning_count)s, %(tool_call_count)s,
         %(start_timestamp)s, %(verdict_timestamp)s, %(evidence)s::jsonb,
         %(is_synthetic)s, %(true_label)s, %(summary_text)s, %(embedding)s)
"""


def feedback_memory_node(state, conn, llm_client, true_label_lookup=None):
    from pgvector.psycopg import register_vector
    register_vector(conn)

    key_evidence = select_key_evidence(state["alert_type"], state["evidence"])
    prompt = format_summary_prompt(
        state["alert_type"], key_evidence, state["escalation_flag"], state["verdict"]
    )
    summary_text = llm_client.summarize(prompt)
    embedding = embed_text(summary_text)

    alert = state["raw_evidence"]
    true_label = (true_label_lookup or {}).get(state["alert_id"])

    try:
        with conn.cursor() as cur:
            cur.execute(INSERT_INVESTIGATION_SQL, {
                "alert_id": state["alert_id"],
                "alert_type": state["alert_type"],
                "source": alert.get("source", "unknown"),
                "source_ip": alert.get("source_ip"),
                "dest_ip": alert.get("dest_ip"),
                "user_id": alert.get("user_id"),
                "sender_domain": alert.get("sender_domain"),
                "verdict": state["verdict"],
                "confidence_score": state["confidence_score"],
                "escalation_flag": state["escalation_flag"],
                "planning_count": state["planning_count"],
                "tool_call_count": state["tool_call_count"],
                "start_timestamp": state["start_timestamp"],
                "verdict_timestamp": state["verdict_timestamp"],
                "evidence": json.dumps(state["evidence"], default=str),
                "is_synthetic": state["is_synthetic"],
                "true_label": true_label,
                "summary_text": summary_text,
                "embedding": embedding,
            })
        conn.commit()
    except Exception as e:
        conn.rollback()  # critical — clears the aborted transaction state
        raise  # re-raise so the consumer loop sees the failure
    return {}