"""
Phase 7: post-verdict summary generation and embedding (Phase 4's design).

key_evidence selection is deterministic code, not another LLM judgment --
reuses the same per-alert-type weights confidence.py already uses, so
"what mattered most" stays auditable and consistent across investigations
instead of being a second, unreviewable model opinion.
"""
from __future__ import annotations

from src.agent.confidence import EVIDENCE_WEIGHTS

ALERT_TYPE_LABEL = {
    "phishing": "Phishing",
    "lateral_movement": "Lateral movement",
    "insider_threat": "Insider threat",
}

SUMMARY_PROMPT_TEMPLATE = """You write one-line investigation summaries for episodic memory retrieval.

Rules:
- Output exactly one sentence, under 30 words.
- Use this structure, filling brackets from the investigation record:
  "[alert_type] alert, [key_signal], [outcome], [verdict_label]."
- alert_type: "Lateral movement" or "Phishing" or "Insider threat"
- key_signal: copy {key_evidence} as-is (already selected; do not re-rank evidence)
- outcome: "auto-resolved" if escalation_flag is false; "escalated to analyst" if true
- verdict_label: from agent verdict only --
    malicious -> "agent assessed malicious"
    benign -> "agent assessed benign"
    inconclusive -> "agent assessed inconclusive"
- No speculation. Use only the fields provided. No paragraph, no bullet list.

Fields:
- alert_type: {alert_type_label}
- key_evidence: {key_evidence}
- escalation_flag: {escalation_flag}
- verdict: {verdict}

Summary:"""


def select_key_evidence(alert_type: str, evidence: list[dict]) -> str:
    """
    Highest-weighted successful evidence entry for this alert_type. Falls
    through to the next-highest weight if that entry's result is empty;
    "insufficient evidence" if nothing usable remains.
    """
    weights = EVIDENCE_WEIGHTS[alert_type]
    by_tool = {}
    for entry in evidence:
        if entry["status"] == "success" and entry.get("result_summary"):
            by_tool[entry["tool_name"]] = entry["result_summary"]

    for tool_name in sorted(weights, key=weights.get, reverse=True):
        if tool_name in by_tool:
            return by_tool[tool_name]

    return "insufficient evidence"


def format_summary_prompt(alert_type: str, key_evidence: str, escalation_flag: bool, verdict: str) -> str:
    return SUMMARY_PROMPT_TEMPLATE.format(
        alert_type_label=ALERT_TYPE_LABEL[alert_type],
        key_evidence=key_evidence,
        escalation_flag=escalation_flag,
        verdict=verdict,
    )


def embed_text(text: str) -> list[float]:
    """Always OpenAI text-embedding-3-small, regardless of which provider
    drives planner/reflect reasoning -- Claude has no embeddings endpoint,
    so a second provider is required either way (Phase 4)."""
    import openai

    client = openai.OpenAI()
    response = client.embeddings.create(model="text-embedding-3-small", input=text)
    return response.data[0].embedding
