"""
Phase 6c: system prompts for `planner` and `reflect`.

Neither prompt is ever given planning_count, tool_call_count, either cap,
or whether planner declined a tool call on a prior cycle -- locked in
routing.py. Both only ever see: the alert's own fields, and the evidence
gathered so far.
"""

PLANNER_SYSTEM_PROMPT = """You are a SOC analyst investigating a single security alert.

You will be shown the alert's own fields and any evidence already
gathered. Decide whether calling one more tool would add useful evidence
that isn't already in hand.

- If a tool would tell you something you don't already know, call it.
- If every tool relevant to this alert type has already been used, or the
  evidence you have already makes further checks pointless, do not call a
  tool -- just respond normally.
- Call at most one tool per turn.
- Do not repeat a tool that has already been called for this alert.
"""

REFLECT_SYSTEM_PROMPT = """You are a SOC analyst reviewing the evidence gathered so far for one
security alert, deciding whether it's enough to conclude the investigation.

You will be shown the alert's own fields and the full evidence trail
gathered so far, most recent result included.

Call submit_reflection_decision with:
- decision: "verdict" if the evidence gathered is sufficient to reach a
  conclusion (whether that conclusion is confident or uncertain -- your
  job here is only to judge whether more evidence-gathering would
  actually help, not to compute the final verdict yourself).
- decision: "continue" if there is a specific, concrete gap in the
  evidence that more investigation could plausibly close.
- reasoning: one or two sentences on why.
"""

REFLECTION_DECISION_TOOL = {
    "name": "submit_reflection_decision",
    "description": "Submit your continue-vs-verdict judgment on the evidence gathered so far.",
    "input_schema": {
        "type": "object",
        "properties": {
            "decision": {"type": "string", "enum": ["continue", "verdict"]},
            "reasoning": {"type": "string"},
        },
        "required": ["decision", "reasoning"],
    },
}


def format_alert_and_evidence(alert_type: str, raw_evidence: dict, evidence: list[dict]) -> str:
    lines = [f"Alert type: {alert_type}", "Alert fields:"]
    for key, value in raw_evidence.items():
        lines.append(f"  {key}: {value}")

    if not evidence:
        lines.append("\nNo evidence gathered yet.")
    else:
        lines.append("\nEvidence gathered so far:")
        for entry in evidence:
            lines.append(
                f"  - {entry['tool_name']} [{entry['status']}]: "
                f"{entry.get('result_summary') or '(no result)'}"
            )

    return "\n".join(lines)
