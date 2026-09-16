# src/baseline/run_fable_baseline.py
"""
Runs the Phase 5 rule-based baseline against the full Fable dataset
(combined_alerts.json) to establish a before/after comparison for V2.
"""
from __future__ import annotations
import json
from src.baseline.phishing_rules import score_alert as score_phishing
from src.baseline.lateral_movement_rules import score_alert as score_lateral

DATASET_PATH = "src/data/combined_alerts.json"


def run():
    with open(DATASET_PATH) as f:
        records = json.load(f)

    print(f"Total alerts: {len(records)}\n")

    for alert_type in ["phishing", "lateral_movement", "insider_threat"]:
        rows = [r for r in records if r["alert_type"] == alert_type]
        if not rows:
            print(f"{alert_type}: no records\n")
            continue

        results = []
        for r in rows:
            if alert_type == "phishing":
                result = score_phishing(
                    reputation_signal=r.get("reputation_signal", "unknown"),
                    click_action=r.get("click_action", "viewed_only"),
                )
            elif alert_type == "lateral_movement":
                result = score_lateral(
                    total_fwd_packets=r.get("total_fwd_packets", 0),
                    total_bwd_packets=r.get("total_bwd_packets", 0),
                    syn_flag_count=r.get("syn_flag_count", 0),
                    fin_flag_count=r.get("fin_flag_count", 0),
                )
            else:
                # No rule baseline for insider threat — too behavioral
                result = {"verdict": "inconclusive", "confidence": 0.0, "escalation_flag": True}

            result["true_label"] = r.get("true_label")
            result["alert_id"] = r.get("alert_id")
            results.append(result)

        total = len(results)
        actual_malicious = [r for r in results if r["true_label"] == "malicious"]
        actual_benign = [r for r in results if r["true_label"] == "benign"]

        missed = [r for r in actual_malicious if r["verdict"] == "benign"]
        fn_rate = len(missed) / len(actual_malicious) if actual_malicious else 0

        escalated = [r for r in results if r["escalation_flag"]]
        true_pos_esc = [r for r in escalated if r["true_label"] == "malicious"]
        esc_precision = len(true_pos_esc) / len(escalated) if escalated else 0

        benign_escalated = [r for r in actual_benign if r["escalation_flag"]]
        benign_esc_rate = len(benign_escalated) / len(actual_benign) if actual_benign else 0

        print(f"{alert_type.upper()} ({total} alerts)")
        print(f"  Malicious: {len(actual_malicious)}, Benign: {len(actual_benign)}")
        print(f"  False-negative rate:    {fn_rate:.3f} ({len(missed)} missed)")
        print(f"  Escalation precision:   {esc_precision:.3f}")
        print(f"  Benign escalation rate: {benign_esc_rate:.3f}")
        print(f"  Auto-resolved:          {total - len(escalated)}\n")


if __name__ == "__main__":
    run()