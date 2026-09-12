"""
Phase 6c: binds a chosen tool name to the actual keyword arguments it
needs, pulled deterministically from state -- never from the model. The
model's tool-use output only ever names a tool; this function is what
turns that into a real dispatch() call.

Deliberately does not validate or raise on missing fields (e.g. a None
sender_domain). Phase 3: a missing raw_evidence field must flow through
the same mechanism as a real tool failure, not a separate one -- so
values, including None, are passed straight through. If build_tool_kwargs
raised instead, that would happen before registry.dispatch() is ever
called, bypassing retry/circuit-breaker handling entirely and creating a
second failure path the planner/reflect nodes would have to interpret
differently from an ordinary tool failure. Each tool is responsible for
raising on a value it can't use (see the explicit None-guards in
phishing_tools.py / lateral_movement_tools.py) so that failure happens
*inside* the retry-wrapped call and comes out as a normal
ToolResult(status="failure").
"""
from __future__ import annotations


def build_tool_kwargs(tool_name: str, state: dict, data_sources: dict) -> dict:
    """
    data_sources: the DataFrame/connection handles (click_history,
    reputation_records, ip_reputation_records, conn -- the real Postgres
    connection sql_correlation queries) -- owned by the orchestration
    layer, never by the model or the state object itself.
    """
    alert = state["raw_evidence"]
    alert_id = state["alert_id"]

    if tool_name == "click_history_lookup":
        return {
            "alert_id": alert_id,
            "click_history": data_sources["click_history"],
        }

    if tool_name == "reputation_lookup":
        return {
            "alert_id": alert_id,
            "sender_domain": alert.get("sender_domain"),
            "is_synthetic": state["is_synthetic"],
            "reputation_records": data_sources["reputation_records"],
        }

    if tool_name == "ip_reputation_lookup":
        return {
            "alert_id": alert_id,
            "dest_ip": alert.get("dest_ip"),
            "reputation_records": data_sources["ip_reputation_records"],
        }

    if tool_name == "sql_correlation":
        return {
            "alert_id": alert_id,
            "source_ip": alert.get("source_ip"),
            "dest_ip": alert.get("dest_ip"),
            "alert_timestamp": alert.get("timestamp"),
            "conn": data_sources["conn"],
        }

    if tool_name == "user_behavior_lookup":
        return {
            "alert_id": alert_id,
            "user_id": alert.get("user_id"),
            "behavior_records": data_sources["behavior_records"],
        }

    if tool_name == "data_access_logs":
        return {
            "alert_id": alert_id,
            "user_id": alert.get("user_id"),
            "resource_id": alert.get("resource_id"),
            "access_records": data_sources["access_records"],
        }

    raise ValueError(f"unknown tool_name: {tool_name!r}")
