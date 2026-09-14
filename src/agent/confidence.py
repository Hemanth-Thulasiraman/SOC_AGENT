"""
Phase 6c: deterministic per-evidence-source confidence scoring (Phase 2).

Not an LLM call. Weights are reasoned per evidence source per alert type
-- click history (phishing) is weighted higher than reputation because
it's this system's own internal log (always available, damning when
present) rather than a third-party lookup that can legitimately come back
empty (Phase 2's worked example). A failed tool (status="failure") lowers
confidence proportional to that source's weight rather than being treated
as a neutral non-event -- a tripped circuit breaker on a high-weight
source should cost more confidence than one on a low-weight source.
"""
from __future__ import annotations

# (weight, malicious_keywords) -- keywords are matched against the
# evidence's own result_summary string, not a separate hidden label.
EVIDENCE_WEIGHTS = {
    "phishing": {
        "click_history_lookup": 0.7,
        "reputation_lookup": 0.3,
    },
    "lateral_movement": {
        "sql_correlation": 0.4,        # was 0.6 — redistributed to make room
        "ip_reputation_lookup": 0.2,   # was 0.4
        "flow_analysis": 0.4,          # new
    },
    "insider_threat": {
        "user_behavior_lookup": 0.6,
        "data_access_logs": 0.4,
    },
}

MALICIOUS_MARKERS = [
    "entered credentials",
    "known-malicious",
    "verdicts:",
    "anomalous",
    "never previously accessed",
    "port scan or brute-force",     # flow_analysis
    "data staging or exfiltration", # flow_analysis
    "warrants review",              # flow_analysis ambiguous-but-suspicious
]
BENIGN_MARKERS = [
    "viewed only",
    "clean, established",
    "fits normal baseline",    
]

def _direction(tool_name: str, result_summary: str | None) -> float:
    if not result_summary:
        return 0.0
    text = result_summary.lower()

    if tool_name == "sql_correlation":
        if "verdicts:" not in text:
            return 0.0
        malicious_n = _count_verdict(text, "malicious")
        benign_n = _count_verdict(text, "benign")
        if malicious_n == benign_n:
            return 0.0
        return 1.0 if malicious_n > benign_n else -1.0

    if tool_name == "flow_analysis":
        if "legitimate internal traffic" in text:
            return -1.0
        if "port scan or brute-force" in text:
            return 1.0
        if "data staging or exfiltration" in text:
            return 1.0
        if "warrants review" in text:
            return 0.5
        # "unremarkable flow" and "insufficient flow data" → neutral
        return 0.0

    if any(marker in text for marker in MALICIOUS_MARKERS):
        return 1.0
    if any(marker in text for marker in BENIGN_MARKERS):
        return -1.0
    if "suspicious" in text:
        return 0.0
    return 0.0


def _count_verdict(text: str, label: str) -> int:
    import re
    match = re.search(rf"{label}=(\d+)", text)
    return int(match.group(1)) if match else 0


def compute_confidence(alert_type: str, evidence: list[dict]) -> tuple[float, str]:
    """
    Returns (confidence_score in [0, 1], leaning) where leaning is
    "malicious" | "benign" | "inconclusive". confidence_score is how
    strongly the weighted evidence supports `leaning` -- not a
    probability, a magnitude.
    """
    weights = EVIDENCE_WEIGHTS[alert_type]
    net = 0.0
    weight_seen = 0.0

    for entry in evidence:
        tool_name = entry["tool_name"]
        weight = weights.get(tool_name)
        if weight is None:
            continue

        if entry["status"] == "failure":
            # Missing/failed evidence costs confidence proportional to how
            # load-bearing this source is -- same mechanism as a genuine
            # evidentiary gap, not a separate override path (Phase 2).
            weight_seen += weight
            continue

        direction = _direction(tool_name, entry.get("result_summary"))
        net += weight * direction
        weight_seen += weight

    if weight_seen == 0.0:
        return 0.0, "inconclusive"

    magnitude = min(abs(net) / weight_seen, 1.0) if weight_seen else 0.0
    if net > 0:
        leaning = "malicious"
    elif net < 0:
        leaning = "benign"
    else:
        leaning = "inconclusive"

    return round(magnitude, 4), leaning
