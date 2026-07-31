"""
Phase 6c: tool schemas exposed to the Anthropic API for the `planner`
node. No argument fields -- every tool's real arguments are facts already
in state (alert_id, sender_domain, dest_ip, ...), bound deterministically
by build_tool_kwargs, never supplied by the model. The model's only
decision is which tool (if any) to call.
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
]

TOOLS_BY_ALERT_TYPE = {
    "phishing": ["click_history_lookup", "reputation_lookup"],
    "lateral_movement": ["ip_reputation_lookup", "sql_correlation"],
}


def tool_schemas_for_alert_type(alert_type: str) -> list[dict]:
    """Only offer the model tools that are actually relevant to this alert type."""
    allowed = set(TOOLS_BY_ALERT_TYPE[alert_type])
    return [schema for schema in TOOL_SCHEMAS if schema["name"] in allowed]
