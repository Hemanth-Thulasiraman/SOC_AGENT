"""
Phase 5 runner: score a lateral-movement/infiltration alert queue (real
Infiltration + template-jitter synthetic Infiltration + a real BENIGN
sample) with the rule baseline and report the five Phase 1 metrics plus a
detection-bucket breakdown.

Usage: python -m src.baseline.run_lateral_movement_baseline
"""
from __future__ import annotations

import time

import numpy as np
import pandas as pd

from src.baseline.lateral_movement_rules import HIGH_VOLUME_THRESHOLD, score_alert
from src.data.load_infiltration import load_real_infiltration_rows, sample_real_benign_rows
from src.data.synthesize_infiltration import generate_synthetic_infiltration_rows

CSV_PATH = "data/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
N_SYNTHETIC_MALICIOUS = 400
N_BENIGN_SAMPLE = 1700  # targets ~20% malicious rate, in line with Phase 1's ~22% genuine-alert figure
SEED = 42


def build_dataset() -> pd.DataFrame:
    real_infiltration = load_real_infiltration_rows(CSV_PATH)
    malicious = generate_synthetic_infiltration_rows(
        real_infiltration, n_rows=N_SYNTHETIC_MALICIOUS, seed=SEED
    )
    malicious["true_label"] = "malicious"

    benign = sample_real_benign_rows(CSV_PATH, n_rows=N_BENIGN_SAMPLE, seed=SEED)
    benign["is_synthetic"] = False
    benign["true_label"] = "benign"

    df = pd.concat([malicious, benign], ignore_index=True)
    return df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)


def _detection_bucket(row) -> str:
    if row.true_label == "benign":
        return "benign"
    total_packets = row.total_fwd_packets + row.total_bwd_packets
    if total_packets >= HIGH_VOLUME_THRESHOLD:
        return "malicious_high_volume"
    if row.syn_flag_count >= 1 and row.fin_flag_count == 0:
        return "malicious_syn_no_fin"
    return "malicious_quiet_no_syn"


def run_baseline(df: pd.DataFrame) -> pd.DataFrame:
    verdicts, confidences, escalations, latencies_s = [], [], [], []
    for row in df.itertuples():
        t0 = time.perf_counter()
        result = score_alert(
            row.total_fwd_packets, row.total_bwd_packets,
            row.syn_flag_count, row.fin_flag_count,
        )
        latencies_s.append(time.perf_counter() - t0)
        verdicts.append(result["verdict"])
        confidences.append(result["confidence"])
        escalations.append(result["escalation_flag"])

    out = df.copy()
    out["verdict"] = verdicts
    out["confidence"] = confidences
    out["escalation_flag"] = escalations
    out["latency_s"] = latencies_s
    out["detection_bucket"] = out.apply(_detection_bucket, axis=1)
    return out


def compute_metrics(results: pd.DataFrame) -> dict:
    latencies_ms = results["latency_s"] * 1000

    is_malicious = results["true_label"] == "malicious"
    is_verdict_benign = results["verdict"] == "benign"
    false_negatives = results[is_malicious & is_verdict_benign]

    escalated = results[results["escalation_flag"]]
    escalation_true_positive = escalated["true_label"] == "malicious"

    mean_latency_s = results["latency_s"].mean()

    return {
        "n_alerts": len(results),
        "time_to_verdict_median_ms": float(np.median(latencies_ms)),
        "time_to_verdict_p95_ms": float(np.percentile(latencies_ms, 95)),
        "throughput_alerts_per_hour": (
            3600.0 / mean_latency_s if mean_latency_s > 0 else float("inf")
        ),
        "escalation_precision": (
            escalation_true_positive.mean() if len(escalated) else float("nan")
        ),
        "n_escalations": len(escalated),
        "false_negative_rate": (
            len(false_negatives) / is_malicious.sum() if is_malicious.sum() else float("nan")
        ),
        "n_false_negatives": len(false_negatives),
        "n_actual_malicious": int(is_malicious.sum()),
        "cost_per_investigation_usd": 0.0,  # pure Python rules, no LLM/API calls
    }


def compute_bucket_breakdown(results: pd.DataFrame) -> pd.DataFrame:
    def cell_summary(group: pd.DataFrame) -> pd.Series:
        return pd.Series({
            "n": len(group),
            "verdict_malicious_rate": (group["verdict"] == "malicious").mean(),
            "verdict_benign_rate": (group["verdict"] == "benign").mean(),
            "escalation_rate": group["escalation_flag"].mean(),
        })

    return results.groupby("detection_bucket").apply(cell_summary, include_groups=False)


def main() -> None:
    df = build_dataset()
    results = run_baseline(df)
    metrics = compute_metrics(results)
    breakdown = compute_bucket_breakdown(results)

    print("=== Phase 5 Baseline: Lateral-Movement Rule Scorer ===")
    print(f"n_alerts: {metrics['n_alerts']}")
    print(f"time_to_verdict_median_ms: {metrics['time_to_verdict_median_ms']:.5f}")
    print(f"time_to_verdict_p95_ms: {metrics['time_to_verdict_p95_ms']:.5f}")
    print(f"throughput_alerts_per_hour: {metrics['throughput_alerts_per_hour']:,.0f}")
    print(
        f"escalation_precision: {metrics['escalation_precision']:.3f} "
        f"({metrics['n_escalations']} escalations)"
    )
    print(
        f"false_negative_rate: {metrics['false_negative_rate']:.3f} "
        f"({metrics['n_false_negatives']} / {metrics['n_actual_malicious']} actual malicious)"
    )
    print(f"cost_per_investigation_usd: {metrics['cost_per_investigation_usd']:.4f}")
    print()
    print("=== Detection bucket breakdown ===")
    print(breakdown.to_string())


if __name__ == "__main__":
    main()
