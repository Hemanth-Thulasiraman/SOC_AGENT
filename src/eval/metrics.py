"""
Phase 8: reads the real `investigations` rows an eval run wrote and
computes the same five Phase 1 metrics Phase 5's baseline reported --
same formulas, same framing (cost/latency/throughput are a budget check
against Phase 2's caps, not a contest; escalation precision and
false-negative rate are the real comparison).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import psycopg


def load_eval_results(conn: psycopg.Connection, alert_ids: list[str] | None = None) -> pd.DataFrame:
    if alert_ids is not None:
        query = """
            SELECT alert_id, alert_type, verdict, confidence_score, escalation_flag,
                   true_label, start_timestamp, verdict_timestamp
            FROM investigations WHERE alert_id = ANY(%s)
        """
        params = (alert_ids,)
    else:
        query = """
            SELECT alert_id, alert_type, verdict, confidence_score, escalation_flag,
                   true_label, start_timestamp, verdict_timestamp
            FROM investigations WHERE source LIKE 'phase8_eval%%'
        """
        params = ()
    with conn.cursor() as cur:
        cur.execute(query, params)
        cols = [d.name for d in cur.description]
        rows = cur.fetchall()
    return pd.DataFrame(rows, columns=cols)


def compute_metrics(df: pd.DataFrame, cost_per_investigation_usd: float | None = None) -> dict:
    latency_s = (df["verdict_timestamp"] - df["start_timestamp"]).dt.total_seconds()

    is_malicious = df["true_label"] == "malicious"
    is_benign = df["true_label"] == "benign"
    is_verdict_benign = df["verdict"] == "benign"
    false_negatives = df[is_malicious & is_verdict_benign]

    escalated = df[df["escalation_flag"]]
    escalation_true_positive = escalated["true_label"] == "malicious"

    mean_latency_s = latency_s.mean()

    return {
        "n_alerts": len(df),
        "time_to_verdict_median_s": float(latency_s.median()),
        "time_to_verdict_p95_s": float(np.percentile(latency_s, 95)),
        "throughput_alerts_per_hour": (
            3600.0 / mean_latency_s if mean_latency_s and mean_latency_s > 0 else float("inf")
        ),
        "escalation_precision": (
            float(escalation_true_positive.mean()) if len(escalated) else float("nan")
        ),
        "n_escalations": len(escalated),
        "false_negative_rate": (
            len(false_negatives) / is_malicious.sum() if is_malicious.sum() else float("nan")
        ),
        "n_false_negatives": len(false_negatives),
        "n_actual_malicious": int(is_malicious.sum()),
        "cost_per_investigation_usd": cost_per_investigation_usd,
        # false_negative_rate only counts verdict='benign' on a malicious
        # alert -- matches Phase 5's baseline formula, but the baseline
        # only ever emits malicious/benign, never a third option. This
        # agent can also emit verdict='inconclusive', which is a real,
        # distinct outcome (honest uncertainty -> escalated, not a
        # confident wrong call) that the baseline-matching formula alone
        # would silently fold into "not a false negative" without
        # surfacing it. Tracked separately so it isn't hidden.
        "n_inconclusive_on_malicious": int((is_malicious & (df["verdict"] == "inconclusive")).sum()),
        "n_malicious_escalated": int((is_malicious & df["escalation_flag"]).sum()),
        # Ground-truth-conditioned escalation rates -- NOT comparable to
        # another system's raw escalation count/rate when the two
        # populations have different malicious/benign composition (this
        # eval set deliberately oversamples hard/malicious cases vs. the
        # baseline's realistic ~20% malicious population). Conditioning on
        # true_label controls for that, so these two numbers are what's
        # actually comparable across differently-composed eval sets.
        "escalation_rate_malicious": (
            float((is_malicious & df["escalation_flag"]).sum() / is_malicious.sum())
            if is_malicious.sum() else float("nan")
        ),
        "escalation_rate_benign": (
            float((is_benign & df["escalation_flag"]).sum() / is_benign.sum())
            if is_benign.sum() else float("nan")
        ),
    }


def print_metrics(label: str, metrics: dict) -> None:
    print(f"\n=== {label} ===")
    print(f"n_alerts: {metrics['n_alerts']}")
    print(f"time_to_verdict_median_s: {metrics['time_to_verdict_median_s']:.2f}")
    print(f"time_to_verdict_p95_s: {metrics['time_to_verdict_p95_s']:.2f}")
    print(f"throughput_alerts_per_hour: {metrics['throughput_alerts_per_hour']:,.1f}")
    print(f"escalation_precision: {metrics['escalation_precision']:.3f} ({metrics['n_escalations']} escalations)")
    print(
        f"false_negative_rate: {metrics['false_negative_rate']:.3f} "
        f"({metrics['n_false_negatives']} / {metrics['n_actual_malicious']} actual malicious)"
    )
    if metrics["n_actual_malicious"]:
        pct_inconclusive = metrics["n_inconclusive_on_malicious"] / metrics["n_actual_malicious"]
        pct_escalated = metrics["n_malicious_escalated"] / metrics["n_actual_malicious"]
        print(
            f"  (of which inconclusive: {metrics['n_inconclusive_on_malicious']} ({pct_inconclusive:.1%}) -- "
            f"escalated as honest uncertainty, not counted as a miss but not a confident correct call either)"
        )
        print(
            f"  malicious alerts reaching a human via escalation (any verdict): "
            f"{metrics['n_malicious_escalated']}/{metrics['n_actual_malicious']} ({pct_escalated:.1%})"
        )
    print(
        f"escalation_rate_malicious: {metrics['escalation_rate_malicious']:.3f}  "
        f"escalation_rate_benign: {metrics['escalation_rate_benign']:.3f}"
    )
    if metrics["cost_per_investigation_usd"] is not None:
        print(f"cost_per_investigation_usd: {metrics['cost_per_investigation_usd']:.4f}")


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    from src.agent.demo import get_conn

    run_files = sorted(Path("eval_runs").glob("eval_run_*.json"))
    if not run_files:
        print("no eval_runs/*.json found -- run src.eval.run_eval first")
        sys.exit(1)
    run_record = json.loads(run_files[-1].read_text())
    print(f"using run record: {run_files[-1]}")

    conn = get_conn()
    df = load_eval_results(conn, alert_ids=run_record["alert_ids"])
    conn.close()

    cost_per = (
        run_record["estimated_cost_usd"] / run_record["n_alerts"]
        if run_record.get("estimated_cost_usd") is not None
        else None
    )

    overall = compute_metrics(df, cost_per)
    print_metrics("Phase 8 Eval: Overall", overall)

    for alert_type in ["phishing", "lateral_movement"]:
        subset = df[df.alert_type == alert_type]
        if len(subset):
            print_metrics(f"Phase 8 Eval: {alert_type}", compute_metrics(subset, cost_per))
