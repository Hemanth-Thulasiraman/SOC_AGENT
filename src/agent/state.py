"""Phase 6c: the LangGraph state object (Phase 2's state shape)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, TypedDict

# Fields genuinely visible at ingestion, before any tool call -- per Phase
# 3's schema. Deliberately excludes anything tool-gated (click_action,
# click_timestamp -- behind click_history_lookup; reputation_signal /
# ip_reputation_signal -- behind reputation_lookup / ip_reputation_lookup)
# and anything eval-only (true_label, scenario_type, is_synthetic --
# is_synthetic is a separate top-level state field, not agent-visible
# evidence).
#
# This lives here, not just in whichever script happens to construct
# state, because new_investigation_state is the one shared ingestion
# boundary every caller (demo script, Phase 8 eval harness, anything
# else) goes through. A single caller remembering to filter correctly is
# a convention that can silently lapse; the boundary itself enforcing it
# is not.
ALLOWED_RAW_EVIDENCE_FIELDS = {
    "phishing": {"alert_id", "alert_type", "timestamp", "source", "sender_domain", "sender_email", "url", "user_id"},
    "lateral_movement": {
        "alert_id", "alert_type", "timestamp", "source", "source_ip", "dest_ip", "source_port", "dest_port",
        "protocol", "flow_duration", "total_fwd_packets", "total_bwd_packets",
        "syn_flag_count", "fin_flag_count", "avg_packet_size",
    },
}


class InvestigationState(TypedDict):
    alert_id: str
    alert_type: str  # "phishing" | "lateral_movement"
    raw_evidence: dict
    is_synthetic: bool

    start_timestamp: datetime
    verdict_timestamp: datetime | None

    evidence: list[dict]  # [{tool_name, result_summary, status, timestamp}]
    circuit_breakers: dict

    planning_count: int
    tool_call_count: int

    planner_decision: dict[str, Any] | None      # {"action": "call_tool", "tool_name": ...} | {"action": "no_tool_needed"}
    reflection_decision: str | None               # "continue" | "verdict"

    confidence_score: float
    verdict: str | None                           # "malicious" | "benign" | "inconclusive"
    escalation_flag: bool


def new_investigation_state(alert_id: str, alert_type: str, raw_evidence: dict, is_synthetic: bool) -> InvestigationState:
    allowed = ALLOWED_RAW_EVIDENCE_FIELDS[alert_type]
    leaked = set(raw_evidence) - allowed
    if leaked:
        raise ValueError(
            f"raw_evidence for alert_type={alert_type!r} contains fields the agent must not "
            f"see (tool-gated or eval-only): {sorted(leaked)}. Only {sorted(allowed)} are allowed."
        )

    return {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "raw_evidence": raw_evidence,
        "is_synthetic": is_synthetic,
        "start_timestamp": datetime.now(timezone.utc),
        "verdict_timestamp": None,
        "evidence": [],
        "circuit_breakers": {},
        "planning_count": 0,
        "tool_call_count": 0,
        "planner_decision": None,
        "reflection_decision": None,
        "confidence_score": 0.0,
        "verdict": None,
        "escalation_flag": False,
    }
