"""
Builds fixture DataFrames from the Fable dataset for tool lookups.
Each tool queries its fixture by alert_id — same keying as V1.
"""
from __future__ import annotations
import json
import pandas as pd


def build_fixtures(dataset_path: str) -> dict[str, pd.DataFrame]:
    with open(dataset_path) as f:
        records = json.load(f)

    lm = [r for r in records if r["alert_type"] == "lateral_movement"]
    ph = [r for r in records if r["alert_type"] == "phishing"]
    it = [r for r in records if r["alert_type"] == "insider_threat"]

    # Reputation records — phishing
    reputation_records = pd.DataFrame([
        {
            "alert_id": r["alert_id"],
            "reputation_signal": r["reputation_signal"],
        }
        for r in ph
    ])

    # IP reputation records — lateral movement
    ip_reputation_records = pd.DataFrame([
        {
            "alert_id": r["alert_id"],
            "ip_reputation_signal": r["ip_reputation_signal"],
        }
        for r in lm
    ])

    # Click history — phishing
    click_history = pd.DataFrame([
        {
            "alert_id": r["alert_id"],
            "user_id": r["user_id"],
            "click_action": r["click_action"],
            "click_timestamp": r.get("click_timestamp"),
        }
        for r in ph
    ])

    # User behavior records — insider threat
    behavior_records = pd.DataFrame([
        {
            "alert_id": r["alert_id"],
            "user_id": r["user_id"],
            "is_anomalous": r["is_anomalous"],
            "normal_hours": r.get("normal_hours", "09:00-17:00"),
            "avg_bytes_transferred": r.get("avg_bytes_transferred", 0),
        }
        for r in it
    ])

    # Data access records — insider threat
    access_records = pd.DataFrame([
        {
            "alert_id": r["alert_id"],
            "user_id": r["user_id"],
            "resource_id": r["resource_id"],
            "prior_access_count": r.get("prior_access_count", 0),
            "last_access_date": r.get("last_access_date", "never"),
            "resource_sensitivity": r.get("resource_sensitivity", "internal"),
        }
        for r in it
    ])

    # Investigations DataFrame for sql_correlation (starts empty —
    # gets populated as the eval harness runs alerts in order)
    investigations = pd.DataFrame(columns=[
        "alert_id", "source_ip", "dest_ip",
        "verdict", "verdict_timestamp"
    ])

    return {
        "reputation_records": reputation_records,
        "ip_reputation_records": ip_reputation_records,
        "click_history": click_history,
        "behavior_records": behavior_records,
        "access_records": access_records,
        "investigations": investigations,
    }


if __name__ == "__main__":
    fixtures = build_fixtures("src/data/combined_alerts.json")
    for name, df in fixtures.items():
        print(f"{name}: {len(df)} rows, columns: {list(df.columns)}")