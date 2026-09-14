"""
V2 evaluation harness — publishes Fable alerts to Railway API
using original alert_ids, workers on Railway process them,
results go to Neon, metrics computed from Neon.
Usage: python -m src.eval.run_eval_v2 [batch_start]
Example: python -m src.eval.run_eval_v2 0   (alerts 0-99)
         python -m src.eval.run_eval_v2 100  (alerts 100-199)
"""
from __future__ import annotations
import json
import sys
import time
import requests
import psycopg
from psycopg.rows import dict_row

DATASET_PATH = "src/data/combined_alerts.json"
RAILWAY_URL = "https://soc-agent-api-production-e0e4.up.railway.app"
NEON_URL = "postgresql://neondb_owner:npg_ajGNSf1E4QDB@ep-young-rain-a5zx38do-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require"

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

    batch_start = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    batch = records[batch_start:batch_start + 100]
    print(f"Running batch {batch_start}-{batch_start + len(batch)} ({len(batch)} alerts)...")

    # Skip already-processed alerts in Neon
    conn = psycopg.connect(NEON_URL, row_factory=dict_row)
    with conn.cursor() as cur:
        cur.execute("SELECT alert_id FROM investigations WHERE alert_id LIKE 'fable_%'")
        already_done = {row["alert_id"] for row in cur.fetchall()}
    conn.close()

    remaining = [r for r in batch if r["alert_id"] not in already_done]
    print(f"Already done: {len(already_done)}, Remaining in batch: {len(remaining)}")

    if not remaining:
        print("All alerts in this batch already processed — computing metrics.")
        compute_metrics()
        return

    print(f"Publishing {len(remaining)} alerts to Railway API...")

    for i, record in enumerate(remaining):
        alert_type = record["alert_type"]
        allowed = ALLOWED_FIELDS[alert_type]

        payload = {
            "alert_id": record["alert_id"],
            "alert_type": alert_type,
            "source": record.get("source", "fable_generated"),
            "raw_evidence": {
                k: v for k, v in record.items()
                if k in allowed
            },
        }

        try:
            resp = requests.post(
                f"{RAILWAY_URL}/v2/investigations/run",
                json=payload,
                timeout=10,
            )
            if resp.status_code != 200:
                print(f"  error on {record['alert_id']}: {resp.status_code} {resp.text}")
        except Exception as e:
            print(f"  error on {record['alert_id']}: {e}")

        time.sleep(3.0)

        if (i + 1) % 10 == 0:
            print(f"  queued {i + 1}/{len(remaining)}")

    print("Waiting for Railway workers to finish (3 minutes)...")
    time.sleep(180)

    compute_metrics()


def compute_metrics():
    with open(DATASET_PATH) as f:
        records = json.load(f)

    true_labels = {r["alert_id"]: r["true_label"] for r in records}

    conn = psycopg.connect(NEON_URL, row_factory=dict_row)
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

    print(f"\nDone.")


if __name__ == "__main__":
    run_eval()