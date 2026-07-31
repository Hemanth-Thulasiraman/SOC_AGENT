"""
Phase 6c/7 demo: runs the assembled graph end-to-end on real alerts,
against the real Postgres `investigations` table (sql_correlation reads
from it, feedback_memory_node writes to it).

Swap StubLLMClient for AnthropicLLMClient/OpenAILLMClient to run against
a real model -- see README for required .env keys.

Each demo function cleans up its own inserted rows on exit (both any
seeded "prior investigations" and the row the run itself writes back), so
this script stays rerunnable against the same live table without
violating the alert_id UNIQUE constraint on a second run.
"""
from __future__ import annotations

import os

import pandas as pd
import psycopg
from dotenv import load_dotenv

from src.agent.graph import build_graph
from src.agent.llm_client import StubLLMClient
from src.agent.state import ALLOWED_RAW_EVIDENCE_FIELDS, new_investigation_state
from src.data.load_infiltration import load_real_infiltration_rows, sample_real_benign_rows
from src.data.synthesize_infiltration import assign_ip_reputation_signal, generate_synthetic_infiltration_rows
from src.data.synthesize_phishing import generate_synthetic_phishing_rows
from src.tools.lateral_movement_tools import ip_reputation_lookup, sql_correlation
from src.tools.phishing_tools import click_history_lookup, reputation_lookup
from src.tools.registry import ToolRegistry

load_dotenv()


def get_conn() -> psycopg.Connection:
    return psycopg.connect(
        host=os.environ["DB_HOST"],
        port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
    )


def visible_fields(row, alert_type: str) -> dict:
    """Filters a dataset row down to state.py's enforced allow-list for this
    alert_type -- new_investigation_state raises if this is done wrong, so
    this is a convenience, not the actual safety boundary."""
    fields = ALLOWED_RAW_EVIDENCE_FIELDS[alert_type]
    return {k: row[k] for k in fields if k in row.index}


def print_trace(label: str, final_state: dict) -> None:
    print(f"\n=== {label} ===")
    print(f"alert_id: {final_state['alert_id']}  alert_type: {final_state['alert_type']}")
    print(f"planning_count={final_state['planning_count']}  tool_call_count={final_state['tool_call_count']}")
    print("evidence trail:")
    for e in final_state["evidence"]:
        print(f"  - {e['tool_name']} [{e['status']}]: {e['result_summary']}")
    print(f"confidence_score: {final_state['confidence_score']}")
    print(f"verdict: {final_state['verdict']}")
    print(f"escalation_flag: {final_state['escalation_flag']}")


def run_phishing_demo(llm_client=None) -> None:
    df = generate_synthetic_phishing_rows(n_rows=500, seed=42)
    # The exact case Phase 5's baseline got wrong: reputation says "unknown"
    # (naive rule reads this as benign), but the user entered credentials.
    row = df[df.scenario_type == "malicious_disagree"].iloc[0]
    print(f"picked alert {row.alert_id}, scenario_type={row.scenario_type}, true_label={row.true_label}")
    print(f"  (Phase 5 baseline verdict on this exact cell: benign -- a false negative, 100% miss rate)")

    registry = ToolRegistry({
        "reputation_lookup": lambda **kw: reputation_lookup(**kw),
        "click_history_lookup": lambda **kw: click_history_lookup(**kw),
    })
    data_sources = {"reputation_records": df, "click_history": df}

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM investigations WHERE alert_id = %s", (row.alert_id,))
        conn.commit()

        graph = build_graph(
            llm_client or StubLLMClient(), registry, data_sources, conn,
            true_label_lookup={row.alert_id: row.true_label},
        )
        raw_evidence = visible_fields(row, "phishing")
        state = new_investigation_state(row.alert_id, "phishing", raw_evidence, is_synthetic=True)
        final_state = graph.invoke(state)

        print_trace("Phishing: malicious_disagree case", final_state)
        print(f"agent got it right: {final_state['verdict'] == row.true_label}")

        with conn.cursor() as cur:
            cur.execute("SELECT summary_text FROM investigations WHERE alert_id = %s", (row.alert_id,))
            print(f"written to investigations, summary_text: {cur.fetchone()[0]!r}")
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM investigations WHERE alert_id = %s", (row.alert_id,))
        conn.commit()
        conn.close()


def run_lateral_movement_demo(llm_client=None) -> None:
    csv_path = "data/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
    real = load_real_infiltration_rows(csv_path)
    mal = generate_synthetic_infiltration_rows(real, n_rows=400, seed=42)
    mal["alert_id"] = [f"lm_mal_{i:05d}" for i in range(len(mal))]
    mal["true_label"] = "malicious"

    benign = sample_real_benign_rows(csv_path, n_rows=200, seed=42)
    benign["alert_id"] = [f"lm_ben_{i:05d}" for i in range(len(benign))]
    benign["true_label"] = "benign"
    benign["is_synthetic"] = False

    combined = pd.concat([mal, benign], ignore_index=True)
    combined = assign_ip_reputation_signal(combined, seed=42)
    combined["source"] = "cicids_capture"  # never added upstream; every alert needs one per Phase 3

    # Prior investigations "already on file": every occurrence of a
    # repeat-offender template except the most recent one -- seeded as
    # REAL rows in `investigations` (not a DataFrame stand-in), since
    # sql_correlation now queries the live table.
    synth_mal = combined[combined.is_synthetic].copy()
    grp_sizes = synth_mal.groupby(["source_ip", "dest_ip"])["alert_id"].transform("count")
    repeat_key = synth_mal[grp_sizes > 2].iloc[0][["source_ip", "dest_ip"]]
    occurrences = synth_mal[
        (synth_mal.source_ip == repeat_key.source_ip) & (synth_mal.dest_ip == repeat_key.dest_ip)
    ].sort_values("timestamp")

    latest = occurrences.iloc[-1]
    prior_occurrences = occurrences.iloc[:-1]
    print(f"picked alert {latest.alert_id}, host pair {repeat_key.source_ip} -> {repeat_key.dest_ip}, "
          f"{len(prior_occurrences)} prior occurrence(s) already on file, true_label={latest.true_label}")

    all_alert_ids = list(occurrences["alert_id"])

    registry = ToolRegistry({
        "ip_reputation_lookup": lambda **kw: ip_reputation_lookup(**kw),
        "sql_correlation": lambda **kw: sql_correlation(**kw),
    })
    data_sources = {"ip_reputation_records": combined, "conn": None}  # conn filled in below

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM investigations WHERE alert_id = ANY(%s)", (all_alert_ids,))
        conn.commit()

        with conn.cursor() as cur:
            for _, occ in prior_occurrences.iterrows():
                cur.execute(
                    """INSERT INTO investigations
                       (alert_id, alert_type, source, source_ip, dest_ip, verdict, confidence_score,
                        escalation_flag, planning_count, tool_call_count, start_timestamp,
                        verdict_timestamp, evidence, is_synthetic, true_label)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        occ.alert_id, "lateral_movement", occ.source, occ.source_ip, occ.dest_ip,
                        occ.true_label, 0.9, False, 1, 1,
                        occ.timestamp, occ.timestamp + pd.Timedelta(minutes=2), "[]",
                        True, occ.true_label,
                    ),
                )
        conn.commit()

        data_sources["conn"] = conn
        graph = build_graph(
            llm_client or StubLLMClient(), registry, data_sources, conn,
            true_label_lookup={latest.alert_id: latest.true_label},
        )
        raw_evidence = visible_fields(latest, "lateral_movement")
        state = new_investigation_state(latest.alert_id, "lateral_movement", raw_evidence, is_synthetic=True)
        final_state = graph.invoke(state)

        print_trace("Lateral movement: repeat-offender host, latest occurrence", final_state)
        print(f"agent got it right: {final_state['verdict'] == latest.true_label}")

        with conn.cursor() as cur:
            cur.execute("SELECT summary_text FROM investigations WHERE alert_id = %s", (latest.alert_id,))
            print(f"written to investigations, summary_text: {cur.fetchone()[0]!r}")
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM investigations WHERE alert_id = ANY(%s)", (all_alert_ids,))
        conn.commit()
        conn.close()


if __name__ == "__main__":
    run_phishing_demo()
    run_lateral_movement_demo()
