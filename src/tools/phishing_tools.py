"""
Phase 6b: phishing evidence tools.

reputation_lookup now calls VirusTotal live for real alerts,
falling back to the fixture DataFrame for synthetic ones.
click_history_lookup unchanged — internal log, no live API.
"""
from __future__ import annotations

import os
import requests
import pandas as pd


def click_history_lookup(alert_id: str, click_history: pd.DataFrame) -> str:
    """
    Looks up the click-history record for this specific alert.
    Keyed by alert_id — internal log, always has a record.
    """
    matches = click_history[click_history["alert_id"] == alert_id]
    if matches.empty:
        raise LookupError(f"no click-history record found for alert_id={alert_id!r}")

    record = matches.iloc[0]
    click_action = record["click_action"]
    click_timestamp = record["click_timestamp"]

    if click_action == "entered_credentials":
        return f"user entered credentials at {click_timestamp}"
    if click_action == "clicked_link":
        return f"user clicked link, no credentials entered, at {click_timestamp}"
    return "user viewed only, did not click"


def _virustotal_domain(sender_domain: str) -> str | None:
    """
    Calls VirusTotal for domain reputation.
    Returns a signal string or None on API failure.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{sender_domain}",
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


def reputation_lookup(
    alert_id: str,
    sender_domain: str,
    is_synthetic: bool,
    reputation_records: pd.DataFrame | None = None,
) -> str:
    """
    Checks sender_domain's reputation.

    For real alerts: calls VirusTotal live, falls back to
    AbuseIPDB, then returns unknown if both fail.
    For synthetic alerts: reads pre-assigned fixture keyed by
    alert_id (not sender_domain — avoids cross-alert collision).
    """
    if not sender_domain:
        raise ValueError("reputation_lookup requires a non-empty sender_domain")

    if is_synthetic:
        if reputation_records is None or reputation_records.empty:
            raise LookupError("no reputation fixture available for synthetic alert")
        matches = reputation_records[reputation_records["alert_id"] == alert_id]
        if matches.empty:
            raise LookupError(f"no reputation fixture found for alert_id={alert_id!r}")
        signal = matches.iloc[0]["reputation_signal"]
    else:
        # Real alert — try VirusTotal first
        signal = _virustotal_domain(sender_domain)
        if signal is None:
            # VirusTotal failed — return unknown rather than raising
            # so the agent can still reason with partial evidence
            signal = "no_history"

    if signal == "known_malicious":
        return f"domain {sender_domain} has known-malicious reputation"
    if signal == "suspicious":
        return f"domain {sender_domain} has suspicious reputation signals"
    if signal == "known_clean":
        return f"domain {sender_domain} has clean, established reputation"
    return f"no reputation history found for domain {sender_domain}"