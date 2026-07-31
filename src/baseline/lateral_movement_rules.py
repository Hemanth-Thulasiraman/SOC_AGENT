"""
Phase 5 baseline: deterministic threshold rule scorer for lateral-movement
/ infiltration alerts -- the shape of rule a SOC analyst would actually
write directly against CICFlowMeter fields: a total-packet-volume
threshold, plus an incomplete-handshake (bare SYN, no FIN) flag as a
weaker secondary signal.

It scores each flow in isolation, using only the fields present on that
one alert. It cannot correlate across time or across alerts -- e.g. "this
source_ip has made 15 quiet connections to the same destination over the
last hour" -- which is precisely the SQL-correlation capability the
agent's episodic memory (Phase 4) exists for. Its blind spot is therefore
structural, not tuned: a real infiltration flow that is both low-volume
and does not carry a bare SYN flag is indistinguishable from ordinary
benign traffic when viewed one flow at a time.
"""
from __future__ import annotations

HIGH_VOLUME_THRESHOLD = 100  # total packets (fwd+bwd); ~99th pct of real BENIGN flows
AUTO_RESOLVE_THRESHOLD = 0.7


def score_alert(
    total_fwd_packets: float,
    total_bwd_packets: float,
    syn_flag_count: float,
    fin_flag_count: float,
) -> dict:
    """Score a single lateral-movement alert using only its visible evidence fields."""
    total_packets = total_fwd_packets + total_bwd_packets

    if total_packets >= HIGH_VOLUME_THRESHOLD:
        verdict, confidence = "malicious", 0.90
    elif syn_flag_count >= 1 and fin_flag_count == 0:
        verdict, confidence = "malicious", 0.50
    else:
        verdict, confidence = "benign", 0.85

    escalation_flag = confidence < AUTO_RESOLVE_THRESHOLD
    return {
        "verdict": verdict,
        "confidence": confidence,
        "escalation_flag": escalation_flag,
    }
