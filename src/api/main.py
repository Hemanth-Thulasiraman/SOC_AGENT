"""
SOC Agent API — V1 read-only endpoints + V2 ingestion endpoints.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
import redis
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SOC Alert Triage API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

DB_URL = "postgresql://postgres:devpassword@localhost:5433/soc_agent"
REDIS_URL = {"host": "localhost", "port": 6379}

# Simulation state — simple flag, one simulation at a time
_simulation_thread: threading.Thread | None = None
_simulation_running = False


def get_db():
    return psycopg.connect(DB_URL, row_factory=dict_row)


def get_redis():
    return redis.Redis(decode_responses=True, **REDIS_URL)


# ── V1: read-only endpoints ──────────────────────────────────────────

@app.get("/investigations")
def list_investigations(
    alert_type: str | None = None,
    verdict: str | None = None,
    escalated_only: bool = False,
    limit: int = 50,
    offset: int = 0,
):
    filters, params = [], []
    if alert_type:
        filters.append("alert_type = %s")
        params.append(alert_type)
    if verdict:
        filters.append("verdict = %s")
        params.append(verdict)
    if escalated_only:
        filters.append("escalation_flag = true")
    where = f"WHERE {' AND '.join(filters)}" if filters else ""

    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            f"""SELECT alert_id, alert_type, verdict, confidence_score,
                       escalation_flag, human_verdict, start_timestamp,
                       verdict_timestamp, summary_text
                FROM investigations {where}
                ORDER BY start_timestamp DESC LIMIT %s OFFSET %s""",
            params + [limit, offset],
        )
        return cur.fetchall()


@app.get("/investigations/{alert_id}")
def get_investigation(alert_id: str):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM investigations WHERE alert_id = %s", (alert_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "not found")
        row.pop("embedding", None)
        return row


# ── V2: ingestion endpoints ──────────────────────────────────────────

class AlertPayload(BaseModel):
    alert_type: str
    source: str
    raw_evidence: dict


@app.post("/v2/investigations/run")
def run_single_alert(payload: AlertPayload):
    """Trigger a single alert investigation via the supervisor."""
    from src.supervisor.supervisor import SupervisorAgent
    from src.agent.llm_client import StubLLMClient

    alert = {
        "alert_id": f"manual_{uuid.uuid4().hex[:8]}",
        "alert_type": payload.alert_type,
        "source": payload.source,
        "raw_evidence": payload.raw_evidence,
    }

    r = get_redis()
    supervisor = SupervisorAgent(StubLLMClient(), r)
    stream = supervisor.process(alert)

    return {
        "alert_id": alert["alert_id"],
        "routed_to": stream,
        "status": "queued",
    }


@app.post("/v2/simulation/start")
def start_simulation(speed_seconds: float = 2.0):
    """Replay the eval dataset through the pipeline at a configurable rate."""
    global _simulation_thread, _simulation_running

    if _simulation_running:
        return {"status": "already running"}

    _simulation_running = True

    def run():
        global _simulation_running
        from src.supervisor.supervisor import SupervisorAgent
        from src.agent.llm_client import StubLLMClient
        from src.data.synthesize_phishing import generate_synthetic_phishing_rows
        import pandas as pd

        r = get_redis()
        supervisor = SupervisorAgent(StubLLMClient(), r)

        # Generate a small batch of synthetic alerts to replay
        phishing_df = generate_synthetic_phishing_rows(n_rows=10, seed=99)

        for _, row in phishing_df.iterrows():
            if not _simulation_running:
                break

            alert = {
                "alert_id": f"sim_{uuid.uuid4().hex[:8]}",
                "alert_type": "phishing",
                "source": "simulation",
                "raw_evidence": {
                    "sender_domain": row.get("sender_domain", "unknown"),
                    "sender_email": row.get("sender_email", "unknown"),
                    "url": row.get("url", ""),
                    "user_id": row.get("user_id", "unknown"),
                },
                "is_synthetic": True,
            }
            supervisor.process(alert)
            time.sleep(speed_seconds)

        
        _simulation_running = False

    _simulation_thread = threading.Thread(target=run, daemon=True)
    _simulation_thread.start()

    return {"status": "started", "speed_seconds": speed_seconds}


@app.post("/v2/simulation/stop")
def stop_simulation():
    global _simulation_running
    _simulation_running = False
    return {"status": "stopped"}