"""
Phase 6b (V2): insider threat evidence tools.

Each tool matches the Callable[..., str] shape ToolRegistry.dispatch
expects -- takes kwargs, returns evidence as a string on success, raises
on failure. Retry/circuit-breaker handling lives entirely in the
registry; tools stay dumb.
"""
from __future__ import annotations
import pandas as pd


def user_behavior_lookup(alert_id: str, user_id: str, behavior_records: pd.DataFrame) -> str:
    """
    Checks whether this user's action fits their normal behavior baseline.
    Keyed by alert_id -- same reasoning as click_history_lookup and
    reputation_lookup: user_id alone is not a safe key since the same
    user can appear across multiple investigations.

    Missing record raises -- this is an internal log. Every active
    employee should have a behavior baseline. Absence means the pipeline
    failed, not that the user has no history.
    """
    if user_id is None:
        raise ValueError("user_id is None -- cannot look up behavior baseline")

    matches = behavior_records[behavior_records["alert_id"] == alert_id]
    if matches.empty:
        raise LookupError(f"no behavior record found for alert_id={alert_id!r}")

    record = matches.iloc[0]
    is_anomalous = record.get("is_anomalous", False)
    normal_hours = record.get("normal_hours", "unknown")
    avg_bytes = record.get("avg_bytes_transferred", 0)

    if is_anomalous:
        return (
            f"user {user_id} behavior is anomalous — "
            f"normal hours: {normal_hours}, "
            f"average bytes transferred: {avg_bytes}"
        )
    return (
        f"user {user_id} behavior fits normal baseline — "
        f"normal hours: {normal_hours}, "
        f"average bytes transferred: {avg_bytes}"
    )


def data_access_logs(
    alert_id: str,
    user_id: str,
    resource_id: str,
    access_records: pd.DataFrame,
) -> str:
    """
    Checks whether this user normally accesses this specific resource.
    Keyed by alert_id for the same collision reasons as other tools.

    Missing record raises -- internal log, absence is anomalous.
    """
    if user_id is None:
        raise ValueError("user_id is None -- cannot look up access logs")
    if resource_id is None:
        raise ValueError("resource_id is None -- cannot look up access logs")

    matches = access_records[access_records["alert_id"] == alert_id]
    if matches.empty:
        raise LookupError(f"no access record found for alert_id={alert_id!r}")

    record = matches.iloc[0]
    access_count = record.get("prior_access_count", 0)
    last_access = record.get("last_access_date", "never")
    sensitivity = record.get("resource_sensitivity", "unknown")

    if access_count == 0:
        return (
            f"user {user_id} has never previously accessed resource {resource_id} "
            f"(sensitivity: {sensitivity}) — first-time access"
        )
    return (
        f"user {user_id} has accessed resource {resource_id} "
        f"{access_count} times before, last access: {last_access} "
        f"(sensitivity: {sensitivity})"
    )