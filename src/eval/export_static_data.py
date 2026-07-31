"""
Exports the real `investigations` eval rows to static JSON for the
frontend's static-snapshot deployment -- no live backend/DB exposed to
the public internet. Reuses the exact same compute_metrics/BASELINE the
live API and the CLI reports use, so the static site can't drift from
what src/eval/metrics.py and comparison_report.py say.

Usage: python -m src.eval.export_static_data
Writes: frontend/public/data/{metrics,baseline,alerts}.json
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd

from src.agent.demo import get_conn
from src.eval.baseline_reference import BASELINE
from src.eval.metrics import compute_metrics

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "public" / "data"


def _json_safe(v):
    if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):  # NaN/inf
        return None
    if isinstance(v, (pd.Timestamp, datetime)):
        return v.isoformat() if pd.notna(v) else None
    return v


def _latest_cost_per_investigation() -> float | None:
    """Cost isn't stored on the investigations rows themselves -- only in
    the eval_runs/*.json record from the run that produced them."""
    run_files = sorted((Path(__file__).resolve().parent.parent.parent / "eval_runs").glob("eval_run_*.json"))
    if not run_files:
        return None
    record = json.loads(run_files[-1].read_text())
    cost = record.get("estimated_cost_usd")
    n = record.get("n_alerts")
    return cost / n if cost is not None and n else None


def export() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cost_per_investigation = _latest_cost_per_investigation()

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT investigation_id, alert_id, alert_type, source, source_ip, dest_ip,
                      user_id, sender_domain, verdict, confidence_score, escalation_flag,
                      planning_count, tool_call_count, start_timestamp, verdict_timestamp,
                      evidence, human_verdict, human_decided_at, is_synthetic, true_label,
                      summary_text, created_at
               FROM investigations WHERE source LIKE 'phase8_eval%'
               ORDER BY start_timestamp DESC"""
        )
        cols = [d.name for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]

    alerts = [{k: _json_safe(v) for k, v in row.items()} for row in rows]
    (OUT_DIR / "alerts.json").write_text(json.dumps(alerts, indent=2, default=str))
    print(f"wrote {len(alerts)} alerts -> {OUT_DIR / 'alerts.json'}")

    df = pd.DataFrame(rows)
    df["start_timestamp"] = pd.to_datetime(df["start_timestamp"])
    df["verdict_timestamp"] = pd.to_datetime(df["verdict_timestamp"])

    def clean_metrics(d: dict) -> dict:
        return {k: _json_safe(v) for k, v in d.items()}

    metrics = {
        "overall": clean_metrics(compute_metrics(df, cost_per_investigation)),
        "by_alert_type": {},
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    for alert_type in df["alert_type"].unique():
        subset = df[df.alert_type == alert_type]
        m = clean_metrics(compute_metrics(subset, cost_per_investigation))
        m["verdict_counts"] = subset["verdict"].value_counts().to_dict()
        metrics["by_alert_type"][alert_type] = m

    (OUT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str))
    print(f"wrote metrics -> {OUT_DIR / 'metrics.json'}")

    (OUT_DIR / "baseline.json").write_text(json.dumps(BASELINE, indent=2))
    print(f"wrote baseline -> {OUT_DIR / 'baseline.json'}")


if __name__ == "__main__":
    export()
