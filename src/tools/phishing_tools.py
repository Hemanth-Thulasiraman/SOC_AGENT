"""
Phase 6b: phishing evidence tools.

Each tool matches the Callable[..., str] shape ToolRegistry.dispatch
expects -- takes kwargs, returns evidence as a string on success, raises
on failure. Retry/circuit-breaker handling lives entirely in the
registry; tools stay dumb.
"""
from __future__ import annotations

import pandas as pd


def click_history_lookup(alert_id: str, click_history: pd.DataFrame) -> str:
    """
    Looks up the click-history record for this specific alert.

    Matched by alert_id, not user_id: the same user_id can legitimately
    recur across separate investigations (a user targeted by phishing
    more than once is exactly the repeat-offender case episodic memory
    exists to catch), so filtering by user_id alone risks silently
    pulling in a different alert's click outcome. alert_id is the unique
    key (Phase 3 schema) for "the record this investigation is actually
    about," and each alert has exactly one click record, so no
    most-recent tiebreak is needed once the key is right.

    Unlike reputation_lookup (a third-party check where "no history" is
    the expected state for freshly-registered infrastructure), click
    history is this system's own internal log -- every phishing alert was
    generated from an email event, so a record should always exist, even
    one that just says the user viewed the email and never clicked. A
    record's absence here is therefore anomalous: it means the pipeline
    failed to log the event, not that nothing happened. So this raises
    (-> registry treats it as `failure`, subject to retry/circuit-breaker)
    rather than returning a hollow "no record" success string the way
    reputation_lookup would.
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


def reputation_lookup(
    alert_id: str,
    sender_domain: str,
    is_synthetic: bool,
    reputation_records: pd.DataFrame | None = None,
) -> str:
    """
    Checks sender_domain's reputation.

    For synthetic alerts, reads the pre-assigned mock signal for THIS
    alert specifically, keyed by alert_id -- not sender_domain. Faker's
    domain pool is small relative to alert volume: empirically, in a
    2000-row synthetic batch, 205 domains are reused across multiple
    alerts with a *different* reputation_signal assigned each time
    (reputation_signal is assigned per scenario cell during generation,
    not per domain). A domain-keyed fixture would silently return one
    alert's signal for a different alert referencing the same domain --
    the same cross-alert collision class already caught in
    click_history_lookup, just far more frequent here. For real alerts,
    would call VirusTotal/AbuseIPDB live, keyed by sender_domain as usual
    -- that collision is an artifact of how this mock fixture was
    generated, not something a real live lookup needs to worry about.

    "No history" is always a legitimate success (not a failure) -- expected
    for newly-registered malicious infrastructure, per Phase 2.

    sender_domain isn't part of the lookup key (alert_id is), only the
    returned string -- so a missing sender_domain wouldn't otherwise be
    caught by anything below and would silently produce evidence like
    "domain None has known-malicious reputation". Guarded explicitly so a
    missing raw_evidence field surfaces as a real tool failure (Phase 3:
    same mechanism as any other tool failure) instead of a malformed
    success no one would think to look for.
    """
    if not sender_domain:
        raise ValueError("reputation_lookup requires a non-empty sender_domain")
    if is_synthetic:
        matches = reputation_records[reputation_records["alert_id"] == alert_id]
        if matches.empty:
            raise LookupError(f"no reputation fixture found for alert_id={alert_id!r}")
        signal = matches.iloc[0]["reputation_signal"]
    else:
        # TODO (Phase 10+): real VirusTotal/AbuseIPDB call goes here, keyed by sender_domain
        raise NotImplementedError("live reputation lookup not built yet")

    if signal == "known_malicious":
        return f"domain {sender_domain} has known-malicious reputation"
    if signal == "suspicious":
        return f"domain {sender_domain} has suspicious reputation signals"
    if signal == "known_clean":
        return f"domain {sender_domain} has clean, established reputation"
    return f"no reputation history found for domain {sender_domain}"
