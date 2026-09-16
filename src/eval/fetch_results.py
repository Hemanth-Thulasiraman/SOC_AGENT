# src/eval/fetch_results.py
"""
Fetches all fable_ investigations from Neon including full evidence trails
and prints a detailed analysis report.
"""
from __future__ import annotations
import json
import psycopg
from psycopg.rows import dict_row
from collections import Counter

NEON_URL = "postgresql://neondb_owner:npg_ajGNSf1E4QDB@ep-young-rain-a5zx38do-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
DATASET_PATH = "src/data/combined_alerts.json"


def run():
    # Load true labels
    with open(DATASET_PATH) as f:
        records = json.load(f)
    true_labels = {r["alert_id"]: r["true_label"] for r in records}
    scenario_types = {r["alert_id"]: r.get("scenario_type", "unknown") for r in records}

    # Fetch all investigations from Neon
    conn = psycopg.connect(NEON_URL, row_factory=dict_row)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT alert_id, alert_type, verdict, confidence_score,
                   escalation_flag, evidence, summary_text,
                   start_timestamp, verdict_timestamp
            FROM investigations
            WHERE alert_id LIKE 'fable_%'
            ORDER BY alert_type, alert_id
        """)
        results = cur.fetchall()
    conn.close()

    print(f"\n{'='*70}")
    print(f"FULL INVESTIGATION ANALYSIS — {len(results)} completed")
    print(f"{'='*70}\n")

    for alert_type in ["phishing", "lateral_movement", "insider_threat"]:
        type_results = [r for r in results if r["alert_type"] == alert_type]
        if not type_results:
            print(f"{alert_type}: no results\n")
            continue

        total = len(type_results)
        actual_malicious = [r for r in type_results if true_labels.get(r["alert_id"]) == "malicious"]
        actual_benign = [r for r in type_results if true_labels.get(r["alert_id"]) == "benign"]

        missed = [r for r in actual_malicious if r["verdict"] == "benign"]
        fn_rate = len(missed) / len(actual_malicious) if actual_malicious else 0

        escalated = [r for r in type_results if r["escalation_flag"]]
        true_pos_esc = [r for r in escalated if true_labels.get(r["alert_id"]) == "malicious"]
        esc_precision = len(true_pos_esc) / len(escalated) if escalated else 0

        benign_escalated = [r for r in actual_benign if r["escalation_flag"]]
        benign_esc_rate = len(benign_escalated) / len(actual_benign) if actual_benign else 0

        # Latency
        times = []
        for r in type_results:
            if r["start_timestamp"] and r["verdict_timestamp"]:
                delta = (r["verdict_timestamp"] - r["start_timestamp"]).total_seconds()
                times.append(delta)
        times_sorted = sorted(times)
        median = times_sorted[len(times_sorted) // 2] if times_sorted else 0
        p95 = times_sorted[int(len(times_sorted) * 0.95)] if times_sorted else 0

        print(f"{'─'*70}")
        print(f"{alert_type.upper()} — {total} alerts")
        print(f"{'─'*70}")
        print(f"  Malicious: {len(actual_malicious)}, Benign: {len(actual_benign)}")
        print(f"  False-negative rate:    {fn_rate:.3f} ({len(missed)} missed)")
        print(f"  Escalation precision:   {esc_precision:.3f} ({len(true_pos_esc)}/{len(escalated)})")
        print(f"  Benign escalation rate: {benign_esc_rate:.3f} ({len(benign_escalated)}/{len(actual_benign)})")
        print(f"  Median latency:         {median:.1f}s")
        print(f"  P95 latency:            {p95:.1f}s")
        print(f"  Auto-resolved:          {total - len(escalated)}")

        # Tool usage analysis
        print(f"\n  TOOL CALL ANALYSIS:")
        tool_success = Counter()
        tool_failure = Counter()
        tool_counts = Counter()

        for r in type_results:
            evidence = r["evidence"] or []
            for step in evidence:
                tool = step.get("tool_name", "unknown")
                status = step.get("status", "unknown")
                tool_counts[tool] += 1
                if status == "success":
                    tool_success[tool] += 1
                else:
                    tool_failure[tool] += 1

        for tool, total_calls in tool_counts.most_common():
            success = tool_success[tool]
            failure = tool_failure[tool]
            print(f"    {tool}: {total_calls} calls — {success} success, {failure} failure")

        # Evidence analysis by verdict
        print(f"\n  VERDICT BREAKDOWN:")
        for verdict in ["malicious", "benign", "inconclusive"]:
            v_results = [r for r in type_results if r["verdict"] == verdict]
            if not v_results:
                continue
            confidences = [r["confidence_score"] for r in v_results]
            avg_conf = sum(confidences) / len(confidences)
            correct = sum(1 for r in v_results if true_labels.get(r["alert_id"]) == verdict)
            print(f"    {verdict}: {len(v_results)} cases, avg confidence {avg_conf:.2f}")

        # Show missed cases (false negatives) with evidence
        if missed:
            print(f"\n  FALSE NEGATIVES ({len(missed)} cases):")
            for r in missed[:5]:  # show first 5
                evidence = r["evidence"] or []
                tool_results = [f"{s.get('tool_name')}={s.get('status')}" for s in evidence]
                print(f"    {r['alert_id']}: confidence={r['confidence_score']:.2f} tools={tool_results}")

        # Show inconclusive cases with evidence
        inconclusive = [r for r in type_results if r["verdict"] == "inconclusive"]
        if inconclusive:
            print(f"\n  INCONCLUSIVE SAMPLE (first 3):")
            for r in inconclusive[:3]:
                evidence = r["evidence"] or []
                tool_results = [f"{s.get('tool_name')}={s.get('status')}" for s in evidence]
                print(f"    {r['alert_id']}: tools={tool_results}")
                print(f"    summary: {r['summary_text']}")

        print()

    # Overall summary
    all_malicious = [r for r in results if true_labels.get(r["alert_id"]) == "malicious"]
    all_missed = [r for r in all_malicious if r["verdict"] == "benign"]
    all_escalated = [r for r in results if r["escalation_flag"]]
    all_true_pos = [r for r in all_escalated if true_labels.get(r["alert_id"]) == "malicious"]

    print(f"{'='*70}")
    print(f"OVERALL SUMMARY")
    print(f"{'='*70}")
    print(f"  Total investigated:     {len(results)}")
    print(f"  False-negative rate:    {len(all_missed)/len(all_malicious):.3f}")
    print(f"  Escalation precision:   {len(all_true_pos)/len(all_escalated):.3f}" if all_escalated else "  Escalation precision: N/A")
    print(f"  Total escalated:        {len(all_escalated)}")
    print(f"  Auto-resolved:          {len(results) - len(all_escalated)}")

    # Save full results to JSON for further analysis
    output = []
    for r in results:
        output.append({
            "alert_id": r["alert_id"],
            "alert_type": r["alert_type"],
            "true_label": true_labels.get(r["alert_id"]),
            "scenario_type": scenario_types.get(r["alert_id"]),
            "verdict": r["verdict"],
            "confidence_score": r["confidence_score"],
            "escalation_flag": r["escalation_flag"],
            "summary_text": r["summary_text"],
            "evidence": r["evidence"],
            "latency_seconds": (
                (r["verdict_timestamp"] - r["start_timestamp"]).total_seconds()
                if r["start_timestamp"] and r["verdict_timestamp"] else None
            ),
        })

    with open("src/eval/results_full.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  Full results saved to src/eval/results_full.json")


if __name__ == "__main__":
    run()