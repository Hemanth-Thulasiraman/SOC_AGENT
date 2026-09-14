"""
Phase 6c: tool schemas exposed to the API for the `planner` node.
No argument fields -- every tool's real arguments are facts already
in state, bound deterministically by build_tool_kwargs, never supplied
by the model. The model's only decision is which tool (if any) to call.
"""

TOOL_SCHEMAS = [
    {
        "name": "click_history_lookup",
        "description": "Check what the user actually did with a phishing email -- viewed only, clicked the link, or entered credentials. Use for phishing alerts when user behavior hasn't been checked yet.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "reputation_lookup",
        "description": "Check the sender domain/link's threat-intel reputation. 'No history' is a normal result, not a failure -- common for newly-registered malicious infrastructure. Use for phishing alerts when reputation hasn't been checked yet.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "ip_reputation_lookup",
        "description": "Check the destination IP's threat-intel reputation. 'No history' is a normal result. Use for lateral-movement alerts when reputation hasn't been checked yet.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "sql_correlation",
        "description": "Check whether this source/destination IP pair has appeared in prior investigations, and what those prior investigations concluded. This is the only source of historical/repeat-behavior evidence. Use for lateral-movement alerts, especially when the flow's own raw stats look unremarkable on their own.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "user_behavior_lookup",
        "description": "Check whether this user's action fits their normal behavior baseline -- hours, data volume, typical patterns. Use for insider threat alerts when user behavior hasn't been checked yet.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "data_access_logs",
        "description": "Check whether this user normally accesses this specific resource. First-time access to sensitive resources is a strong signal. Use for insider threat alerts when resource access history hasn't been checked yet.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "flow_analysis",
        "description": "Assess the raw network flow stats — packet counts, SYN/FIN flags, port — to determine if the traffic pattern looks like a port scan, data exfiltration, or normal internal traffic. Use for lateral-movement alerts when reputation and correlation haven't produced a clear signal.",
        "input_schema": {"type": "object", "properties": {}},
    },
]

TOOLS_BY_ALERT_TYPE = {
    "phishing": ["click_history_lookup", "reputation_lookup"],
    "lateral_movement": ["ip_reputation_lookup", "sql_correlation"],
    "insider_threat": ["user_behavior_lookup", "data_access_logs"],
    "lateral_movement": ["ip_reputation_lookup", "sql_correlation", "flow_analysis"],
}


def tool_schemas_for_alert_type(alert_type: str) -> list[dict]:
    """Only offer the model tools that are actually relevant to this alert type."""
    if alert_type not in TOOLS_BY_ALERT_TYPE:
        raise ValueError(f"unknown alert_type: {alert_type!r}")
    allowed = set(TOOLS_BY_ALERT_TYPE[alert_type])
    return [schema for schema in TOOL_SCHEMAS if schema["name"] in allowed]