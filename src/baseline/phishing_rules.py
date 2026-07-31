"""
Phase 5 baseline: deterministic threshold/rule scorer for phishing alerts.

Uses only the evidence fields the agent itself will see at inference time
(reputation_signal, click_action) -- never true_label. The rule is
reputation-centric, the way a real correlation rule keyed off threat-intel
match status would be: verdict and confidence are read straight off
reputation_signal. click_action is accepted as an input (it's part of the
alert's visible evidence) but never enters the decision -- a fixed rule
has no mechanism to fuse "no reputation history" with "user entered
credentials" into a single verdict the way a reasoning system can.

This is not a strawman: it is exactly the "SIEM correlation rule" argument
from Phase 1 (predefined, reputation-driven, brittle to novel
infrastructure). It is expected to fail specifically on the
malicious_disagree and benign_disagree scenario cells engineered in
Phase 4, because those cells are built to require fusing reputation with
behavior -- something a fixed rule can't reason about at runtime.
"""
from __future__ import annotations

AUTO_RESOLVE_THRESHOLD = 0.7

REPUTATION_VERDICTS = {
    "known_malicious": ("malicious", 0.95),
    "known_clean": ("benign", 0.95),
    "suspicious": ("malicious", 0.55),
    "unknown": ("benign", 0.80),
}


def score_alert(reputation_signal: str, click_action: str) -> dict:
    """Score a single phishing alert using only its visible evidence fields."""
    verdict, confidence = REPUTATION_VERDICTS.get(reputation_signal, ("inconclusive", 0.0))
    escalation_flag = confidence < AUTO_RESOLVE_THRESHOLD
    return {
        "verdict": verdict,
        "confidence": confidence,
        "escalation_flag": escalation_flag,
    }
