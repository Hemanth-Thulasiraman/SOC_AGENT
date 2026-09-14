"""
SOC Agent API — V1 read-only endpoints + V2 ingestion endpoints.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
import psycopg
import redis as redis_lib
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from src.config import DATABASE_URL, REDIS_URL

app = FastAPI(title="SOC Alert Triage API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_simulation_thread: threading.Thread | None = None
_simulation_running = False


def get_db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def get_redis():
    return redis_lib.from_url(REDIS_URL, decode_responses=True)


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


class AlertPayload(BaseModel):
    alert_id: str | None = None  # use provided or generate new
    alert_type: str
    source: str
    raw_evidence: dict


@app.post("/v2/investigations/run")
def run_single_alert(payload: AlertPayload):
    from src.supervisor.supervisor import SupervisorAgent
    from src.agent.llm_client import StubLLMClient

    alert_id = payload.alert_id or f"manual_{uuid.uuid4().hex[:8]}"

    alert = {
        "alert_id": alert_id,
        "alert_type": payload.alert_type,
        "source": payload.source,
        "raw_evidence": payload.raw_evidence,
    }

    r = get_redis()
    supervisor = SupervisorAgent(StubLLMClient(), r)
    stream = supervisor.process(alert)

    return {
        "alert_id": alert_id,
        "routed_to": stream,
        "status": "queued",
    }


@app.post("/v2/simulation/start")
def start_simulation(speed_seconds: float = 2.0):
    global _simulation_thread, _simulation_running

    if _simulation_running:
        return {"status": "already running"}

    _simulation_running = True

    def run():
        global _simulation_running
        import random
        import json
        from src.supervisor.supervisor import SupervisorAgent
        from src.agent.llm_client import StubLLMClient

        try:
            with open("src/data/combined_alerts.json") as f:
                records = json.load(f)
        except FileNotFoundError:
            records = []

        r = get_redis()
        supervisor = SupervisorAgent(StubLLMClient(), r)
        sample = random.sample(records, min(20, len(records))) if records else []

        ALLOWED_FIELDS = {
            "phishing": {"sender_domain", "sender_email", "url", "user_id"},
            "lateral_movement": {
                "source_ip", "dest_ip", "source_port", "dest_port", "protocol",
                "flow_duration", "total_fwd_packets", "total_bwd_packets",
                "syn_flag_count", "fin_flag_count", "avg_packet_size",
            },
            "insider_threat": {
                "user_id", "event_type", "action",
                "bytes_transferred", "resource_id",
            },
        }

        for record in sample:
            if not _simulation_running:
                break

            alert_type = record.get("alert_type", "phishing")
            allowed = ALLOWED_FIELDS.get(alert_type, set())

            alert = {
                "alert_id": f"sim_{uuid.uuid4().hex[:8]}",
                "alert_type": alert_type,
                "source": "simulation",
                "raw_evidence": {
                    k: v for k, v in record.items()
                    if k in allowed
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