"""
Phase 8: eval runner.

Wipes `investigations` (comparable-to-baseline, from-scratch measurement
-- see docs/00-project-recap.md's Phase 8 reasoning), then processes the eval
set strictly sequentially in timestamp order: one alert's graph.invoke()
-- including its feedback_memory_node write-back commit -- fully
completes before the next one starts. That sequencing, not just sorting
the input, is what makes sql_correlation's ordering guarantee real:
running two invocations concurrently could let both start before either's
commit lands, even with a correctly-sorted list.

Usage: python -m src.eval.run_eval [--limit N]
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from src.agent.demo import get_conn, visible_fields
from src.agent.graph import build_graph
from src.agent.llm_client import OpenAILLMClient
from src.agent.state import new_investigation_state
from src.eval.build_eval_set import build_eval_set
from src.tools.lateral_movement_tools import ip_reputation_lookup, sql_correlation
from src.tools.phishing_tools import click_history_lookup, reputation_lookup
from src.tools.registry import ToolRegistry

CSV_PATH = "data/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
RUNS_DIR = Path("eval_runs")


def build_graphs(eval_set, conn, llm_client) -> dict:
    """One compiled graph per alert_type, built once and reused across
    every alert of that type in the run -- data_sources/true_label_lookup
    cover the whole eval set up front, not rebuilt per alert."""
    phishing_rows = eval_set[eval_set.alert_type == "phishing"]
    lateral_rows = eval_set[eval_set.alert_type == "lateral_movement"]

    phishing_registry = ToolRegistry({
        "reputation_lookup": lambda **kw: reputation_lookup(**kw),
        "click_history_lookup": lambda **kw: click_history_lookup(**kw),
    })
    phishing_graph = build_graph(
        llm_client, phishing_registry,
        {"reputation_records": phishing_rows, "click_history": phishing_rows},
        conn,
        true_label_lookup=dict(zip(phishing_rows.alert_id, phishing_rows.true_label)),
    )

    lateral_registry = ToolRegistry({
        "ip_reputation_lookup": lambda **kw: ip_reputation_lookup(**kw),
        "sql_correlation": lambda **kw: sql_correlation(**kw),
    })
    lateral_graph = build_graph(
        llm_client, lateral_registry,
        {"ip_reputation_records": lateral_rows, "conn": conn},
        conn,
        true_label_lookup=dict(zip(lateral_rows.alert_id, lateral_rows.true_label)),
    )

    return {"phishing": phishing_graph, "lateral_movement": lateral_graph}


def run_eval(eval_set, conn, llm_client, reset: bool = True) -> dict:
    if reset:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE investigations")
        conn.commit()

    graphs = build_graphs(eval_set, conn, llm_client)

    t_start = time.perf_counter()
    for i, (_, row) in enumerate(eval_set.iterrows()):
        alert_type = row["alert_type"]
        raw_evidence = visible_fields(row, alert_type)
        state = new_investigation_state(
            row["alert_id"], alert_type, raw_evidence, is_synthetic=bool(row["is_synthetic"])
        )
        graphs[alert_type].invoke(state)
        print(f"[{i + 1}/{len(eval_set)}] {row['alert_id']} ({alert_type}) done")

    elapsed = time.perf_counter() - t_start
    usage = getattr(llm_client, "usage", None)
    cost = llm_client.estimated_cost_usd() if hasattr(llm_client, "estimated_cost_usd") else None

    print(f"\neval run complete: {len(eval_set)} alerts in {elapsed:.1f}s")
    if usage:
        print(f"tracked usage: {usage}, estimated cost: ${cost:.4f}" if cost is not None else f"tracked usage: {usage}")

    RUNS_DIR.mkdir(exist_ok=True)
    run_record = {
        "alert_ids": list(eval_set["alert_id"]),
        "n_alerts": len(eval_set),
        "elapsed_s": elapsed,
        "usage": usage,
        "estimated_cost_usd": cost,
    }
    out_path = RUNS_DIR / f"eval_run_{int(time.time())}.json"
    out_path.write_text(json.dumps(run_record, indent=2))
    print(f"run record saved to {out_path}")
    return run_record


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="run only the first N alerts (pilot runs)")
    args = parser.parse_args()

    eval_set = build_eval_set(CSV_PATH)
    if args.limit:
        eval_set = eval_set.head(args.limit).reset_index(drop=True)

    print(f"eval set: {len(eval_set)} alerts "
          f"({(eval_set.alert_type == 'phishing').sum()} phishing, "
          f"{(eval_set.alert_type == 'lateral_movement').sum()} lateral_movement)")

    conn = get_conn()
    llm_client = OpenAILLMClient()
    try:
        run_eval(eval_set, conn, llm_client)
    finally:
        conn.close()
