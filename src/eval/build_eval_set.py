"""
Phase 8: builds the held-out eval set for both alert types.

Uses seed=101 throughout -- deliberately distinct from demo.py's
seed=42 -- so held-out-ness from anything already exercised in Phase 6/7
doesn't depend on remembering which alert_ids got manually cleaned up.
alert_ids are also re-namespaced (eval_ph_/eval_lm_ prefixes) rather than
trusting the generators' own sequential IDs, which are seed-independent
and would otherwise collide with demo.py's phish_00004 etc. even though
the row contents differ.
"""
from __future__ import annotations

import pandas as pd

from src.baseline.lateral_movement_rules import HIGH_VOLUME_THRESHOLD
from src.data.load_infiltration import load_real_infiltration_rows, sample_real_benign_rows
from src.data.synthesize_infiltration import assign_ip_reputation_signal, generate_synthetic_infiltration_rows
from src.data.synthesize_phishing import generate_synthetic_phishing_rows

EVAL_SEED = 101

PHISHING_PER_CELL = 20  # x4 scenario cells = 80

# Deliberately weighted toward malicious_quiet_no_syn: it's ~22% of the
# real malicious population but it's the entire reason sql_correlation
# exists (Phase 5: 95/436 false negatives, 100% miss rate in that bucket
# alone). Proportional sampling would undersample the one case this
# project is supposed to fix.
LATERAL_MOVEMENT_TARGETS = {
    "malicious_quiet_no_syn": 24,
    "malicious_syn_no_fin": 24,
    "malicious_high_volume": 16,
    "benign": 16,
}  # = 80


def build_phishing_eval_set() -> pd.DataFrame:
    pool = generate_synthetic_phishing_rows(n_rows=2000, seed=EVAL_SEED)
    parts = [
        group.sample(n=PHISHING_PER_CELL, random_state=EVAL_SEED)
        for _, group in pool.groupby("scenario_type")
    ]
    eval_set = pd.concat(parts, ignore_index=True)
    eval_set["alert_id"] = [f"eval_ph_{i:05d}" for i in range(len(eval_set))]
    eval_set["alert_type"] = "phishing"
    eval_set["source"] = "phase8_eval_phishing"
    return eval_set


def _detection_bucket(row) -> str:
    if row.true_label == "benign":
        return "benign"
    total_packets = row.total_fwd_packets + row.total_bwd_packets
    if total_packets >= HIGH_VOLUME_THRESHOLD:
        return "malicious_high_volume"
    if row.syn_flag_count >= 1 and row.fin_flag_count == 0:
        return "malicious_syn_no_fin"
    return "malicious_quiet_no_syn"


def build_lateral_movement_eval_set(csv_path: str) -> pd.DataFrame:
    real = load_real_infiltration_rows(csv_path)
    malicious = generate_synthetic_infiltration_rows(real, n_rows=300, seed=EVAL_SEED)
    malicious["true_label"] = "malicious"

    benign = sample_real_benign_rows(csv_path, n_rows=300, seed=EVAL_SEED)
    benign["true_label"] = "benign"
    benign["is_synthetic"] = False

    combined = pd.concat([malicious, benign], ignore_index=True)
    combined = assign_ip_reputation_signal(combined, seed=EVAL_SEED)
    combined["source"] = "phase8_eval_lateral_movement"
    combined["alert_id"] = [f"pool_lm_{i:05d}" for i in range(len(combined))]
    combined["detection_bucket"] = combined.apply(_detection_bucket, axis=1)

    parts = []
    for bucket, target_n in LATERAL_MOVEMENT_TARGETS.items():
        candidates = combined[combined.detection_bucket == bucket]
        n = min(target_n, len(candidates))
        parts.append(candidates.sample(n=n, random_state=EVAL_SEED))
    eval_set = pd.concat(parts, ignore_index=True).drop(columns=["detection_bucket"])
    eval_set["alert_id"] = [f"eval_lm_{i:05d}" for i in range(len(eval_set))]
    eval_set["alert_type"] = "lateral_movement"
    return eval_set


def build_eval_set(csv_path: str) -> pd.DataFrame:
    """Combined, sorted by timestamp ascending -- the ordering run_eval.py
    depends on for sql_correlation's guarantee to be real, not assumed."""
    phishing = build_phishing_eval_set()
    lateral = build_lateral_movement_eval_set(csv_path)
    combined = pd.concat([phishing, lateral], ignore_index=True, sort=False)
    return combined.sort_values("timestamp").reset_index(drop=True)


if __name__ == "__main__":
    df = build_eval_set("data/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")
    print(f"total: {len(df)}")
    print(df.groupby(["alert_type"]).size())
    print("\nphishing scenario cells:")
    print(df[df.alert_type == "phishing"].groupby("scenario_type").size())
    print("\nlateral movement true_label:")
    print(df[df.alert_type == "lateral_movement"].groupby("true_label").size())
    print(f"\ntimestamp range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    dup_ids = df["alert_id"].duplicated().sum()
    print(f"duplicate alert_ids: {dup_ids}")
