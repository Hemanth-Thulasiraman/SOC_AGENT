"""
Generates fully synthetic phishing alert rows, structured around a 2x2
scenario matrix (true_label x signal-agreement), with a hidden true_label
separate from what the visible evidence would suggest.
"""
import numpy as np
import pandas as pd
from faker import Faker
from datetime import timedelta

fake = Faker()

CLICK_ACTIONS = ["viewed_only", "clicked_link", "entered_credentials"]

# Scenario cells: (true_label, agreement) -> (reputation_signal, click_action)
# reputation_signal is a MOCK field standing in for what a threat-intel tool
# would return when queried against this synthetic domain. Live VT/AbuseIPDB
# calls on Faker domains always return "unknown", so eval must mock the
# reputation tool to read this fixture for is_synthetic phishing rows.
SCENARIO_MAP = {
    ("malicious", "agree"):    {"reputation_signal": "known_malicious", "click_action": "entered_credentials"},
    ("malicious", "disagree"): {"reputation_signal": "unknown",         "click_action": "entered_credentials"},
    ("benign", "agree"):       {"reputation_signal": "known_clean",     "click_action": "viewed_only"},
    ("benign", "disagree"):    {"reputation_signal": "suspicious",      "click_action": "viewed_only"},
}


def generate_synthetic_phishing_rows(n_rows: int,
                                      malicious_rate: float = 0.4,
                                      agree_rate: float = 0.5,
                                      seed: int | None = None) -> pd.DataFrame:
    """
    n_rows: total synthetic phishing rows to generate
    malicious_rate: fraction with true_label == "malicious"
    agree_rate: within each label group, fraction where visible evidence
                agrees with the true label (vs. the harder disagreement cases)
    Returns: DataFrame with hidden true_label, mocked reputation_signal,
             and evidence fields matching the Phase 3 schema.
    """
    if n_rows < 0:
        raise ValueError("n_rows must be >= 0")
    if not (0.0 <= malicious_rate <= 1.0):
        raise ValueError("malicious_rate must be in [0, 1]")
    if not (0.0 <= agree_rate <= 1.0):
        raise ValueError("agree_rate must be in [0, 1]")

    rng = np.random.default_rng(seed)
    Faker.seed(seed)

    true_labels = rng.choice(
        ["malicious", "benign"], size=n_rows, p=[malicious_rate, 1 - malicious_rate]
    )
    agreements = rng.choice(
        ["agree", "disagree"], size=n_rows, p=[agree_rate, 1 - agree_rate]
    )

    rows = []
    for i in range(n_rows):
        label = true_labels[i]
        agreement = agreements[i]
        scenario = SCENARIO_MAP[(label, agreement)]

        domain = fake.domain_name()
        sender_email = f"{fake.user_name()}@{domain}"
        alert_ts = fake.date_time_between(start_date="-90d", end_date="now")

        click_action = scenario["click_action"]
        click_ts = (
            alert_ts + timedelta(minutes=int(rng.integers(1, 180)))
            if click_action != "viewed_only"
            else None
        )

        rows.append({
            "alert_id": f"phish_{i:05d}",
            "alert_type": "phishing",
            "timestamp": alert_ts,
            "source": "synthetic_generator",
            "sender_domain": domain,
            "sender_email": sender_email,
            "url": f"https://{domain}/{fake.uri_path()}",
            "user_id": fake.uuid4(),
            "click_timestamp": click_ts,
            "click_action": click_action,
            # Mock fixture for Phase 6 reputation tool — not a live-queryable field.
            "reputation_signal": scenario["reputation_signal"],
            "scenario_type": f"{label}_{agreement}",
            "true_label": label,  # hidden ground truth; never shown to the agent
            "is_synthetic": True,
        })

    return pd.DataFrame(rows)
