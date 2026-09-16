"""
V3 confidence scoring — Bayesian updating with count-scaled evidence.

Replaces the flat additive weight system with sequential Bayesian updates.
Each tool result is modeled as a likelihood ratio: how much more (or less)
likely is a malicious alert given this tool's specific output.

P(malicious | evidence) = P(evidence | malicious) * P(malicious) / P(evidence)

Applied sequentially across tools — each tool updates the running posterior.
sql_correlation scales its likelihood by the malicious ratio in prior history,
so 12/17 malicious contributes much more than 2/17.
"""
from __future__ import annotations
import re

# ── Priors ────────────────────────────────────────────────────────────────
# Base rate of malicious alerts in each domain — set from eval data
# phishing: 60/150=0.40, lateral_movement: 180/300=0.60, insider_threat: 52/150=0.35
PRIORS = {
    "phishing": 0.40,
    "lateral_movement": 0.60,
    "insider_threat": 0.35,
}

# ── Likelihood ratios per tool result ─────────────────────────────────────
# LR > 1 means this result is more likely if alert is malicious
# LR < 1 means this result is more likely if alert is benign
# LR = 1 means this result gives no signal either way

# Phishing likelihoods
PHISHING_LIKELIHOODS = {
    "reputation_lookup": {
        "known_malicious":  10.0,   # very strong malicious signal
        "suspicious":        3.0,   # moderate malicious signal
        "known_clean":       0.1,   # strong benign signal
        "no_history":        0.8,   # slight benign lean (unknown infra)
    },
    "click_history_lookup": {
        "entered_credentials": 8.0,  # strong malicious signal
        "clicked_link":        2.0,  # moderate malicious signal
        "viewed_only":         0.3,  # strong benign signal
    },
}

# Lateral movement likelihoods
LATERAL_MOVEMENT_LIKELIHOODS = {
    "ip_reputation_lookup": {
        "known_malicious":  12.0,
        "suspicious":        4.0,
        "known_clean":       0.15,
        "no_history":        1.0,   # truly neutral — private IPs have no history
    },
    "flow_analysis": {
        "high_volume_sensitive_port":   6.0,
        "suspicious_syn_pattern":       3.0,
        "sensitive_port_low_volume":    2.0,
        "normal_traffic_pattern":       0.2,
        "insufficient_data":            1.0,
    },
    # sql_correlation is handled separately — scaled by malicious ratio
}

# Insider threat likelihoods
INSIDER_THREAT_LIKELIHOODS = {
    "user_behavior_lookup": {
        "anomalous":          8.0,
        "slightly_anomalous": 2.5,
        "normal":             0.2,
    },
    "data_access_logs": {
        "high_volume_sensitive": 9.0,
        "unusual_pattern":       4.0,
        "elevated_but_normal":   1.5,
        "normal_pattern":        0.2,
    },
}

LIKELIHOODS = {
    "phishing": PHISHING_LIKELIHOODS,
    "lateral_movement": LATERAL_MOVEMENT_LIKELIHOODS,
    "insider_threat": INSIDER_THREAT_LIKELIHOODS,
}

# ── Escalation thresholds ──────────────────────────────────────────────────
# Auto-resolve malicious above this posterior
MALICIOUS_THRESHOLD = {
    "phishing": 0.80,
    "lateral_movement": 0.75,
    "insider_threat": 0.80,
}

# Auto-resolve benign below this posterior
BENIGN_THRESHOLD = {
    "phishing": 0.20,
    "lateral_movement": 0.25,
    "insider_threat": 0.20,
}


def _bayesian_update(prior: float, likelihood_ratio: float) -> float:
    """
    Update P(malicious) given a likelihood ratio.
    Uses odds form: posterior_odds = prior_odds * LR
    """
    prior_odds = prior / (1 - prior + 1e-9)
    posterior_odds = prior_odds * likelihood_ratio
    return posterior_odds / (1 + posterior_odds)


def _sql_correlation_lr(summary: str) -> float:
    """
    Extract malicious ratio from sql_correlation result string and
    convert to a likelihood ratio.

    'no prior investigations found' → LR 1.0 (no signal)
    '17 prior investigation(s)... verdicts: benign=2, inconclusive=3, malicious=12'
    → malicious_ratio = 12/17 = 0.71 → strong malicious signal
    """
    if "no prior investigations" in summary:
        return 1.0  # no signal either way

    # Extract verdict counts from summary string
    malicious_count = 0
    benign_count = 0
    total_count = 0

    m = re.search(r"(\d+) prior investigation", summary)
    if m:
        total_count = int(m.group(1))

    m = re.search(r"malicious=(\d+)", summary)
    if m:
        malicious_count = int(m.group(1))

    m = re.search(r"benign=(\d+)", summary)
    if m:
        benign_count = int(m.group(1))

    if total_count == 0:
        return 1.0

    malicious_ratio = malicious_count / total_count

    # Scale likelihood ratio by how decisive the history is
    # 0.7+ ratio → strong malicious signal (LR 8-12)
    # 0.5-0.7    → moderate signal (LR 2-4)
    # 0.3-0.5    → weak signal (LR 0.8-1.5)
    # <0.3       → benign signal (LR 0.2-0.5)
    if malicious_ratio >= 0.70:
        return 8.0 + (malicious_ratio - 0.70) * 20  # scales to ~14 at ratio=1.0
    elif malicious_ratio >= 0.50:
        return 2.0 + (malicious_ratio - 0.50) * 30   # scales to ~8 at ratio=0.70
    elif malicious_ratio >= 0.30:
        return 0.8 + (malicious_ratio - 0.30) * 6    # scales to ~2 at ratio=0.50
    else:
        return max(0.1, 0.8 - (0.30 - malicious_ratio) * 4)


def _extract_signal(tool_name: str, result_summary: str) -> str:
    """
    Map a tool result string to a signal key for likelihood lookup.
    """
    s = result_summary.lower()

    if tool_name == "reputation_lookup" or tool_name == "ip_reputation_lookup":
        if "known-malicious" in s or "known_malicious" in s:
            return "known_malicious"
        if "suspicious" in s:
            return "suspicious"
        if "clean" in s or "established" in s:
            return "known_clean"
        return "no_history"

    if tool_name == "click_history_lookup":
        if "entered credentials" in s:
            return "entered_credentials"
        if "clicked link" in s:
            return "clicked_link"
        return "viewed_only"

    if tool_name == "flow_analysis":
        if "high" in s and ("sensitive" in s or "port" in s):
            return "high_volume_sensitive_port"
        if "syn" in s and ("bare" in s or "incomplete" in s):
            return "suspicious_syn_pattern"
        if "sensitive port" in s and "low" in s:
            return "sensitive_port_low_volume"
        if "normal" in s:
            return "normal_traffic_pattern"
        return "insufficient_data"

    if tool_name == "user_behavior_lookup":
        if "anomalous" in s and "slightly" not in s:
            return "anomalous"
        if "slightly" in s or "minor" in s:
            return "slightly_anomalous"
        return "normal"

    if tool_name == "data_access_logs":
        if "high" in s and "sensitive" in s:
            return "high_volume_sensitive"
        if "unusual" in s or "off-hours" in s or "wrong" in s:
            return "unusual_pattern"
        if "elevated" in s:
            return "elevated_but_normal"
        return "normal_pattern"

    return "unknown"


def compute_confidence(
    alert_type: str,
    evidence: list[dict],
) -> tuple[float, str, bool]:
    """
    Compute posterior P(malicious) using Bayesian updating across all
    tool results in the evidence list.

    Returns:
        posterior: float 0-1 probability of malicious
        verdict: 'malicious' | 'benign' | 'inconclusive'
        escalation_flag: bool
    """
    prior = PRIORS.get(alert_type, 0.5)
    posterior = prior
    likelihoods = LIKELIHOODS.get(alert_type, {})

    for step in evidence:
        if step.get("status") != "success":
            continue  # failed tool calls don't update the posterior

        tool_name = step.get("tool_name", "")
        result = step.get("result_summary", "") or ""

        # sql_correlation gets special count-scaled treatment
        if tool_name == "sql_correlation":
            lr = _sql_correlation_lr(result)
            posterior = _bayesian_update(posterior, lr)
            continue

        # All other tools use the likelihood table
        tool_likelihoods = likelihoods.get(tool_name, {})
        if not tool_likelihoods:
            continue

        signal = _extract_signal(tool_name, result)
        lr = tool_likelihoods.get(signal, 1.0)  # unknown signal = no update
        posterior = _bayesian_update(posterior, lr)

    # Verdict from posterior
    mal_threshold = MALICIOUS_THRESHOLD.get(alert_type, 0.75)
    ben_threshold = BENIGN_THRESHOLD.get(alert_type, 0.25)

    if posterior >= mal_threshold:
        verdict = "malicious"
        escalation_flag = False
    elif posterior <= ben_threshold:
        verdict = "benign"
        escalation_flag = False
    else:
        verdict = "inconclusive"
        escalation_flag = True

    return posterior, verdict, escalation_flag


# ── Compatibility shim for summary.py ─────────────────────────────────────
# select_key_evidence uses this to rank which tool result to include in the
# investigation summary. Higher weight = more important evidence.
EVIDENCE_WEIGHTS = {
    "phishing": {
        "reputation_lookup": 0.9,
        "click_history_lookup": 0.8,
    },
    "lateral_movement": {
        "sql_correlation": 0.9,
        "ip_reputation_lookup": 0.8,
        "flow_analysis": 0.6,
    },
    "insider_threat": {
        "user_behavior_lookup": 0.9,
        "data_access_logs": 0.8,
    },
}