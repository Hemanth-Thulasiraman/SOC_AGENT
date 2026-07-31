"""
Phase 6b: lateral-movement evidence tools.

Each tool matches the Callable[..., str] shape ToolRegistry.dispatch
expects -- takes kwargs, returns evidence as a string on success, raises
on failure. Retry/circuit-breaker handling lives entirely in the
registry; tools stay dumb.
"""
from __future__ import annotations

from datetime import datetime

import pandas as pd
import psycopg
from psycopg.rows import dict_row

from src.data.synthesize_infiltration import MAX_OCCURRENCE_GAP_DAYS

# Linked by import, not by coincidence: the window must stay >= the widest
# gap synthesize_infiltration.py can place between two occurrences of the
# same host, or a repeat-offender case the generator built specifically to
# be found would fall outside the window and sql_correlation would find
# nothing, by construction. 2x gives room for several occurrences' worth
# of verdict history, not just the single immediately-prior one.
DEFAULT_CORRELATION_WINDOW_DAYS = int(MAX_OCCURRENCE_GAP_DAYS * 2)


def ip_reputation_lookup(
    alert_id: str,
    dest_ip: str,
    reputation_records: pd.DataFrame,
) -> str:
    """
    Checks dest_ip's reputation for this specific alert.

    Keyed by alert_id, not dest_ip, for the same reason reputation_lookup
    is keyed by alert_id rather than sender_domain: dest_ip is not a safe
    join key here. synthesize_infiltration.py's per-template IP jitter only
    guards against collisions among synthetic templates and the real rows
    -- it never checks the separately-sampled benign population. In
    practice this collides (e.g. a synthetic malicious dest_ip landing on
    the same address as a real benign flow in the same /24), so a
    dest_ip-keyed fixture would silently return the wrong alert's signal.

    Unlike reputation_lookup, there is no is_synthetic branch here: that
    branch made sense for phishing because every row is synthetic and the
    is_synthetic check was really just future-proofing for a live API path.
    For lateral movement, only a minority of rows are_synthetic=True -- the
    36 real Infiltration rows and the real BENIGN sample are both
    is_synthetic=False, but neither has any more of a live reputation path
    than the synthetic rows do (this is 2017 capture data; nothing here is
    a live-queryable address today). ip_reputation_signal
    (assign_ip_reputation_signal) is assigned to the entire combined
    population regardless of is_synthetic, so the fixture lookup applies
    uniformly.

    "No history" is always a legitimate success (not a failure) -- expected
    for freshly-provisioned infrastructure, same reasoning as phishing.

    dest_ip isn't part of the lookup key (alert_id is), only the returned
    string -- guarded explicitly, same reasoning as reputation_lookup, so
    a missing dest_ip surfaces as a real failure rather than a malformed
    "dest_ip None has ..." success.
    """
    if not dest_ip:
        raise ValueError("ip_reputation_lookup requires a non-empty dest_ip")

    matches = reputation_records[reputation_records["alert_id"] == alert_id]
    if matches.empty:
        raise LookupError(f"no ip-reputation fixture found for alert_id={alert_id!r}")

    signal = matches.iloc[0]["ip_reputation_signal"]

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
    """
    Finds prior investigations involving source_ip and/or dest_ip, within
    window_days of alert_timestamp, that had already concluded before this
    alert arrived. Phase 7: queries the real `investigations` table
    (psycopg) instead of the Phase 6b DataFrame stand-in -- same matching
    logic, same window, same success-even-when-empty rule, only the data
    source changed.

    Filters on verdict_timestamp, not start_timestamp: the ordering
    guarantee this tool depends on (synthesize_infiltration.py spaces
    repeat occurrences of the same host 1-14 days apart) is specifically
    that a prior investigation *finished and was written back* before the
    next occurrence was even alerted -- an investigation that had started
    but not yet verdicted isn't queryable evidence yet ("was this host
    already flagged as a concern," not "was an alert for it merely
    received"). The query enforces this directly (verdict_timestamp IS NOT
    NULL, verdict_timestamp < this alert's own timestamp) rather than
    relying on the caller to have filtered rows correctly beforehand.

    Reports verdict history, not a bare count: "this host appeared twice
    before" is ambiguous (could be a chatty benign server); "appeared
    twice before, both verdicted malicious" is the actual signal that
    should move a quiet, low-volume flow's assessment. A full source+dest
    host-pair match is reported separately from a single-field match,
    since it's categorically stronger evidence (the same compromised
    asset contacting the same destination again, not just an asset or a
    destination each independently reappearing in unrelated contexts).

    No prior match is a legitimate success, not a failure -- most hosts
    genuinely have no investigation history, the same way "no reputation
    history" is an expected state for reputation_lookup, not an anomaly.

    source_ip/dest_ip/alert_timestamp are guarded explicitly rather than
    left to the database to reject or silently not-match -- same reasoning
    as the DataFrame version: these aren't part of any lookup key, so a
    None here should surface as a real failure, not a misleadingly clean
    "no prior investigations found".
    """
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
        1 for row in candidates if row["source_ip"] == source_ip and row["dest_ip"] == dest_ip
    )

    verdict_counts: dict[str, int] = {}
    for row in candidates:
        verdict_counts[row["verdict"]] = verdict_counts.get(row["verdict"], 0) + 1
    verdict_summary = ", ".join(f"{verdict}={count}" for verdict, count in sorted(verdict_counts.items()))

    return (
        f"{len(candidates)} prior investigation(s) in the last {window_days} days "
        f"({full_pair_count} exact source+dest host-pair match(es)); verdicts: {verdict_summary}"
    )
