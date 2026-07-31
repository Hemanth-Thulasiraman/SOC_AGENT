"""
Read-only API over the real `investigations` table.

Metrics reuse src/eval/metrics.py's exact compute_metrics -- not
reimplemented here, so the dashboard can never silently drift from what
the eval report says. This is deliberately read-only: no endpoint writes
to `investigations` or triggers an investigation -- that stays the
agent's job (src/agent/graph.py), not the API's.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from backend.db import get_conn
from src.eval.baseline_reference import BASELINE
from src.eval.metrics import compute_metrics

app = FastAPI(title="SOC Agent API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _clean(d: dict) -> dict:
    def fix(v):
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            return None
        return v
    return {k: fix(v) for k, v in d.items()}


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/baseline")
def baseline():
    return BASELINE


@app.get("/api/alerts")
def list_alerts(
    alert_type: str | None = None,
    verdict: str | None = None,
    escalation_flag: bool | None = None,
    source_prefix: str | None = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
):
    conditions, params = [], {}
    if alert_type:
        conditions.append("alert_type = %(alert_type)s")
        params["alert_type"] = alert_type
    if verdict:
        conditions.append("verdict = %(verdict)s")
        params["verdict"] = verdict
    if escalation_flag is not None:
        conditions.append("escalation_flag = %(escalation_flag)s")
        params["escalation_flag"] = escalation_flag
    if source_prefix:
        conditions.append("source LIKE %(source_prefix)s")
        params["source_prefix"] = f"{source_prefix}%"

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            f"""SELECT investigation_id, alert_id, alert_type, source, verdict, confidence_score,
                       escalation_flag, planning_count, tool_call_count, start_timestamp,
                       verdict_timestamp, is_synthetic, true_label, human_verdict, summary_text
                FROM investigations {where}
                ORDER BY start_timestamp DESC
                LIMIT %(limit)s OFFSET %(offset)s""",
            {**params, "limit": limit, "offset": offset},
        )
        rows = cur.fetchall()
        cur.execute(f"SELECT count(*) AS n FROM investigations {where}", params)
        total = cur.fetchone()["n"]

    return {"total": total, "alerts": rows}


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM investigations WHERE alert_id = %s", (alert_id,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="alert not found")
    row.pop("embedding", None)
    return row


@app.get("/api/metrics")
def metrics(source_prefix: str | None = None):
    query = """SELECT alert_id, alert_type, verdict, confidence_score, escalation_flag,
                      true_label, start_timestamp, verdict_timestamp
               FROM investigations"""
    params: tuple = ()
    if source_prefix:
        query += " WHERE source LIKE %s"
        params = (f"{source_prefix}%",)

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()

    if not rows:
        return {"overall": None, "by_alert_type": {}}

    df = pd.DataFrame(rows)
    df["start_timestamp"] = pd.to_datetime(df["start_timestamp"])
    df["verdict_timestamp"] = pd.to_datetime(df["verdict_timestamp"])

    result = {"overall": _clean(compute_metrics(df)), "by_alert_type": {}}
    for alert_type in df["alert_type"].unique():
        subset = df[df.alert_type == alert_type]
        m = _clean(compute_metrics(subset))
        m["verdict_counts"] = subset["verdict"].value_counts().to_dict()
        result["by_alert_type"][alert_type] = m
    return result
