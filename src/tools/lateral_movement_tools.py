"""
Phase 6b: lateral-movement evidence tools.

ip_reputation_lookup now calls AbuseIPDB live for real alerts,
with VirusTotal as fallback. sql_correlation and flow_analysis unchanged.
"""
from __future__ import annotations

import os
import requests
from datetime import datetime

import pandas as pd
import psycopg
from psycopg.rows import dict_row

from src.data.synthesize_infiltration import MAX_OCCURRENCE_GAP_DAYS

DEFAULT_CORRELATION_WINDOW_DAYS = int(MAX_OCCURRENCE_GAP_DAYS * 2)


def _abuseipdb_lookup(dest_ip: str) -> str | None:
    """
    Calls AbuseIPDB for IP reputation.
    Returns a signal string or None on API failure.
    """
    api_key = os.environ.get("ABUSEIPDB_KEY")
    if not api_key:
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": dest_ip, "maxAgeInDays": 90},
            timeout=8,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()["data"]
        score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        if score > 50 or total_reports > 10:
            return "known_malicious"
        if score > 15 or total_reports > 2:
            return "suspicious"
        if score == 0 and total_reports == 0:
            return "known_clean"
        return "no_history"
    except Exception:
        return None


def _virustotal_ip(dest_ip: str) -> str | None:
    """
    Calls VirusTotal for IP reputation as fallback.
    Returns a signal string or None on API failure.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{dest_ip}",
            headers={"x-apikey": api_key},
            timeout=8,
        )
        if resp.status_code == 404:
            return "no_history"
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 3:
            return "known_malicious"
        if malicious > 0 or suspicious > 2:
            return "suspicious"
        if stats.get("harmless", 0) > 5:
            return "known_clean"
        return "no_history"
    except Exception:
        return None


def ip_reputation_lookup(
    alert_id: str,
    dest_ip: str,
    reputation_records: pd.DataFrame,
) -> str:
    """
    Checks dest_ip reputation.

    For real alerts (not in fixture): calls AbuseIPDB first,
    falls back to VirusTotal, then returns unknown if both fail.
    For synthetic alerts: reads fixture keyed by alert_id.
    """
    if not dest_ip:
        raise ValueError("ip_reputation_lookup requires a non-empty dest_ip")

    # Try fixture first — if this alert_id has a record, use it
    if reputation_records is not None and not reputation_records.empty:
        matches = reputation_records[reputation_records["alert_id"] == alert_id]
        if not matches.empty:
            signal = matches.iloc[0]["ip_reputation_signal"]
            if signal == "known_malicious":
                return f"dest_ip {dest_ip} has known-malicious reputation"
            if signal == "suspicious":
                return f"dest_ip {dest_ip} has suspicious reputation signals"
            if signal == "known_clean":
                return f"dest_ip {dest_ip} has clean, established reputation"
            return f"no reputation history found for dest_ip {dest_ip}"

    # No fixture record — call live APIs
    signal = _abuseipdb_lookup(dest_ip)
    if signal is None:
        signal = _virustotal_ip(dest_ip)
    if signal is None:
        signal = "no_history"

    if signal == "known_malicious":
        return f"dest_ip {dest_ip} has known-malicious reputation"
    if signal == "suspicious":
        return f"dest_ip {dest_ip} has suspicious reputation signals"
    if signal == "known_clean":
        return f"dest_ip {dest_ip} has clean, established reputation"
    return f"no reputation history found for dest_ip {dest_ip}"


SQL_CORRELATION_QUERY = """
    SELECT alert_id, verdict, host(source_ip) AS source_ip, host(dest_ip) AS dest_ip
    FROM investigations
    WHERE alert_id != %(alert_id)s
      AND verdict_timestamp IS NOT NULL
      AND verdict_timestamp >= %(alert_timestamp)s::timestamptz - make_interval(days => %(window_days)s)
      AND verdict_timestamp < %(alert_timestamp)s::timestamptz
      AND (source_ip = %(source_ip)s::inet OR dest_ip = %(dest_ip)s::inet)
"""


def sql_correlation(
    alert_id: str,
    source_ip: str,
    dest_ip: str,
    alert_timestamp: datetime,
    conn: psycopg.Connection,
    window_days: int = DEFAULT_CORRELATION_WINDOW_DAYS,
) -> str:
    if not source_ip or not dest_ip:
        raise ValueError("sql_correlation requires non-empty source_ip and dest_ip")
    if alert_timestamp is None:
        raise ValueError("sql_correlation requires a non-null alert_timestamp")

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            SQL_CORRELATION_QUERY,
            {
                "alert_id": alert_id,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "alert_timestamp": alert_timestamp,
                "window_days": window_days,
            },
        )
        candidates = cur.fetchall()

    if not candidates:
        return f"no prior investigations found for this host within the last {window_days} days"

    full_pair_count = sum(
        1 for row in candidates
        if row["source_ip"] == source_ip and row["dest_ip"] == dest_ip
    )

    verdict_counts: dict[str, int] = {}
    for row in candidates:
        verdict_counts[row["verdict"]] = verdict_counts.get(row["verdict"], 0) + 1
    verdict_summary = ", ".join(
        f"{verdict}={count}" for verdict, count in sorted(verdict_counts.items())
    )

    return (
        f"{len(candidates)} prior investigation(s) in the last {window_days} days "
        f"({full_pair_count} exact source+dest host-pair match(es)); verdicts: {verdict_summary}"
    )