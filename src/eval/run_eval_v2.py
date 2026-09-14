"""
V2 evaluation harness — runs all Fable alerts through the full
supervisor → Redis → worker → Postgres pipeline and computes metrics.
"""
from __future__ import annotations
import json
import time
import redis as redis_lib
import psycopg
from psycopg.rows import dict_row
from src.config import DATABASE_URL, REDIS_URL
from src.supervisor.supervisor import SupervisorAgent
from src.agent.llm_client import StubLLMClient

DB_URL = DATABASE_URL
DATASET_PATH = "src/data/combined_alerts.json"

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


def run_eval():
    with open(DATASET_PATH) as f:
        records = json.load(f)

    phishing = [r for r in records if r["alert_type"] == "phishing"]
    lateral = [r for r in records if r["alert_type"] == "lateral_movement"]
    insider = [r for r in records if r["alert_type"] == "insider_threat"]
    records = phishing[:34] + lateral[:33] + insider[:33]

    # Skip already-processed alerts
    conn = psycopg.connect(DB_URL, row_factory=dict_row)
    with conn.cursor() as cur:
        cur.execute("SELECT alert_id FROM investigations WHERE alert_id LIKE 'fable_%'")
        already_done = {row["alert_id"] for row in cur.fetchall()}
    conn.close()

    remaining = [r for r in records if r["alert_id"] not in already_done]
    print(f"Already done: {len(already_done)}, Remaining: {len(remaining)}")

    if not remaining:
        print("All alerts already processed — computing metrics.")
        compute_metrics()
        return

    r = redis_lib.from_url(REDIS_URL, decode_responses=True)
    supervisor = SupervisorAgent(StubLLMClient(), r)

    print(f"Publishing {len(remaining)} alerts...")

    for i, record in enumerate(remaining):
        alert_type = record["alert_type"]
        allowed = ALLOWED_FIELDS[alert_type]

        safe_alert = {
            "alert_id": record["alert_id"],
            "alert_type": alert_type,
            "source": record.get("source", "fable_generated"),
            "raw_evidence": {
                k: v for k, v in record.items()
                if k in allowed
            },
            "is_synthetic": True,
        }

        supervisor.process(safe_alert)
        time.sleep(2.0)

        if (i + 1) % 10 == 0:
            print(f"  queued {i + 1}/{len(remaining)}")

    print("Waiting for workers to finish...")
    time.sleep(120)

    compute_metrics()


def compute_metrics():
    with open(DATASET_PATH) as f:
        records = json.load(f)

    true_labels = {r["alert_id"]: r["true_label"] for r in records}

    conn = psycopg.connect(DB_URL, row_factory=dict_row)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT alert_id, alert_type, verdict, confidence_score,
                   escalation_flag, human_verdict
            FROM investigations
            WHERE alert_id LIKE 'fable_%'
            ORDER BY alert_type, alert_id
        """)
        results = cur.fetchall()
    conn.close()

    print(f"\n{'='*60}")
    print(f"V2 EVAL RESULTS — {len(results)} investigations completed")
    print(f"{'='*60}")

    for alert_type in ["phishing", "lateral_movement", "insider_threat"]:
        type_results = [r for r in results if r["alert_type"] == alert_type]
        if not type_results:
            print(f"\n{alert_type}: no results yet")
            continue

        total = len(type_results)
        actual_malicious = [
            r for r in type_results
            if true_labels.get(r["alert_id"]) == "malicious"
        ]
        actual_benign = [
            r for r in type_results
            if true_labels.get(r["alert_id"]) == "benign"
        ]

        missed = [
            r for r in actual_malicious
            if r["verdict"] == "benign"
        ]
        fn_rate = len(missed) / len(actual_malicious) if actual_malicious else 0

        escalated = [r for r in type_results if r["escalation_flag"]]
        true_pos_escalations = [
            r for r in escalated
            if true_labels.get(r["alert_id"]) == "malicious"
        ]
        esc_precision = (
            len(true_pos_escalations) / len(escalated) if escalated else 0
        )

        benign_escalated = [
            r for r in actual_benign if r["escalation_flag"]
        ]
        benign_esc_rate = (
            len(benign_escalated) / len(actual_benign) if actual_benign else 0
        )

        print(f"\n{alert_type.upper()} ({total} alerts)")
        print(f"  Malicious: {len(actual_malicious)}, Benign: {len(actual_benign)}")
        print(f"  False-negative rate:      {fn_rate:.3f} ({len(missed)} missed)")
        print(f"  Escalation precision:     {esc_precision:.3f} ({len(true_pos_escalations)}/{len(escalated)} escalations correct)")
        print(f"  Benign escalation rate:   {benign_esc_rate:.3f} ({len(benign_escalated)}/{len(actual_benign)} benign cases escalated)")
        print(f"  Auto-resolved:            {total - len(escalated)}")

    total_elapsed = time.time()
    print(f"\nTotal time: {total_elapsed:.0f}s")


if __name__ == "__main__":
    run_eval()