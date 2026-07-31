"""
Phase 8: agent-vs-baseline comparison report.

Baseline numbers are the locked, already-published Phase 5 results
(docs/05-baseline.md) -- not re-run here, since Phase 5 is closed and
those are the fixed row the agent has to beat. Framing matches
docs/05-baseline.md exactly: cost/latency/throughput are a budget check
against Phase 2's caps, not a contest a bare rule-scorer will always win
trivially; escalation precision and false-negative rate are the real
comparison.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from src.agent.demo import get_conn
from src.eval.baseline_reference import BASELINE
from src.eval.metrics import compute_metrics, load_eval_results

AUTO_RESOLVE_THRESHOLD_LATENCY_S = 120  # Phase 2 cap: <2 min time-to-verdict
COST_CAP_USD = 0.10  # Phase 2 cap: <=$0.10/investigation


def print_comparison(alert_type: str, agent: dict) -> None:
    base = BASELINE[alert_type]
    print(f"\n=== {alert_type} : agent vs. Phase 5 baseline ===")
    print(f"{'metric':<22}{'baseline':>12}{'agent':>12}{'delta':>12}")

    ep_delta = agent["escalation_precision"] - base["escalation_precision"]
    print(f"{'escalation_precision':<22}{base['escalation_precision']:>12.3f}"
          f"{agent['escalation_precision']:>12.3f}{ep_delta:>+12.3f}")

    fn_delta = agent["false_negative_rate"] - base["false_negative_rate"]
    print(f"{'false_negative_rate':<22}{base['false_negative_rate']:>12.3f}"
          f"{agent['false_negative_rate']:>12.3f}{fn_delta:>+12.3f}")
    if agent["n_actual_malicious"] and agent["n_inconclusive_on_malicious"]:
        pct = agent["n_inconclusive_on_malicious"] / agent["n_actual_malicious"]
        print(
            f"  caveat: {agent['n_inconclusive_on_malicious']}/{agent['n_actual_malicious']} ({pct:.1%}) "
            f"of actual-malicious alerts got verdict='inconclusive' (escalated, not counted as a miss, "
            f"but also not a confident correct call -- the baseline has no third option, so this delta "
            f"understates how much of the improvement is 'escalates when unsure' vs. 'reasons to the right answer')"
        )

    print(f"\n{'metric':<28}{'baseline':>12}{'agent':>12}{'delta':>12}")
    em_delta = agent["escalation_rate_malicious"] - base["escalation_rate_malicious"]
    print(f"{'escalation_rate_malicious':<28}{base['escalation_rate_malicious']:>12.3f}"
          f"{agent['escalation_rate_malicious']:>12.3f}{em_delta:>+12.3f}")
    eb_delta = agent["escalation_rate_benign"] - base["escalation_rate_benign"]
    print(f"{'escalation_rate_benign':<28}{base['escalation_rate_benign']:>12.3f}"
          f"{agent['escalation_rate_benign']:>12.3f}{eb_delta:>+12.3f}")
    if eb_delta > 0.1:
        print(
            f"  WARNING: escalation_rate_benign increased by {eb_delta:+.1%} -- escalation_precision "
            f"staying roughly flat ({base['escalation_precision']:.3f} -> {agent['escalation_precision']:.3f}) "
            f"is masking a large increase in false-alarm volume, not just correctly redistributed escalations. "
            f"See docs/00-project-recap.md's Phase 8 section for the unconfirmed hypothesis on why."
        )

    print(f"\nbudget check (not a contest -- see docs/05-baseline.md):")
    p95 = agent["time_to_verdict_p95_s"]
    within_latency = p95 < AUTO_RESOLVE_THRESHOLD_LATENCY_S
    print(f"  time_to_verdict_p95_s: {p95:.2f}s "
          f"({'within' if within_latency else 'EXCEEDS'} the {AUTO_RESOLVE_THRESHOLD_LATENCY_S}s Phase 2 cap)")
    cost = agent["cost_per_investigation_usd"]
    if cost is not None:
        within_cost = cost < COST_CAP_USD
        print(f"  cost_per_investigation_usd: {cost:.4f} "
              f"({'within' if within_cost else 'EXCEEDS'} the ${COST_CAP_USD} Phase 2 cap)")


if __name__ == "__main__":
    run_files = sorted(Path("eval_runs").glob("eval_run_*.json"))
    if not run_files:
        print("no eval_runs/*.json found -- run src.eval.run_eval first")
        sys.exit(1)
    run_record = json.loads(run_files[-1].read_text())
    print(f"using run record: {run_files[-1]} ({run_record['n_alerts']} alerts)")

    conn = get_conn()
    df = load_eval_results(conn, alert_ids=run_record["alert_ids"])
    conn.close()

    cost_per = (
        run_record["estimated_cost_usd"] / run_record["n_alerts"]
        if run_record.get("estimated_cost_usd") is not None
        else None
    )

    for alert_type in ["phishing", "lateral_movement"]:
        subset = df[df.alert_type == alert_type]
        if len(subset):
            print_comparison(alert_type, compute_metrics(subset, cost_per))
        else:
            print(f"\n=== {alert_type}: no rows in this run ===")
