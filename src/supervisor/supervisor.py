"""
Supervisor agent: classifies incoming alerts and publishes
to the correct Redis stream. Never investigates — one job only.
"""
from __future__ import annotations
import json
import redis
from src.streams.config import ALERT_TYPE_TO_STREAM, STREAM_REJECTIONS
import time

SUPERVISOR_PROMPT = """You are a security alert classifier.
Given an alert, output the alert_type as exactly one of:
- phishing
- lateral_movement  
- insider_threat

Output only the alert_type string, nothing else."""


class SupervisorAgent:
    def __init__(self, llm_client, redis_client: redis.Redis):
        self._llm = llm_client
        self._redis = redis_client
        self._routed: dict[str, str] = {}  # alert_id → stream, for re-route tracking

    def process(self, alert: dict) -> str:
        """
        Classify and publish to the correct stream.
        Returns the stream name the alert was published to.
        """
        alert_type = self._classify(alert)
        stream = ALERT_TYPE_TO_STREAM.get(alert_type)

        if not stream:
            # Classification produced an unrecognised type — safe fallback
            self._publish_to_human(alert, reason=f"unrecognised alert_type: {alert_type}")
            return "hitl"

        message = {
            "alert_id": alert["alert_id"],
            "alert_type": alert_type,
            "payload": json.dumps(alert),
            "attempt": "1",
        }
        self._redis.xadd(stream, message)
        self._routed[alert["alert_id"]] = stream
        return stream

    def handle_rejection(self, rejection: dict) -> None:
        """
        Called when a worker rejects an alert (wrong domain).
        Re-routes once to a different stream, then escalates to HITL.
        """
        alert_id = rejection["alert_id"]
        rejected_stream = rejection["worker_stream"]
        attempt = int(rejection.get("attempt", "1"))

        if attempt >= 2:
            self._publish_to_human(
                json.loads(rejection["payload"]),
                reason="no worker accepted after re-route"
            )
            return

        # Re-classify excluding the stream that just rejected
        alert = json.loads(rejection["payload"])
        alert_type = self._classify(alert, exclude_stream=rejected_stream)
        stream = ALERT_TYPE_TO_STREAM.get(alert_type)

        if not stream or stream == rejected_stream:
            self._publish_to_human(alert, reason="re-classification produced same or invalid type")
            return

        message = {
            "alert_id": alert_id,
            "alert_type": alert_type,
            "payload": rejection["payload"],
            "attempt": "2",
        }
        self._redis.xadd(stream, message)

    def _classify(self, alert: dict, exclude_stream: str | None = None) -> str:
        exclude_types = [
            k for k, v in ALERT_TYPE_TO_STREAM.items()
            if v == exclude_stream
        ] if exclude_stream else []

        user_content = (
            f"Source: {alert.get('source', 'unknown')}\n"
            f"Raw evidence fields present: {list(alert.get('raw_evidence', {}).keys())}\n"
            f"Alert type if known: {alert.get('alert_type', 'unknown')}\n"
            f"Exclude these types (already tried): {exclude_types}"
        )

        for attempt in range(3):  # retry up to 3 times
            try:
                response = self._llm.call_classifier(
                    system=SUPERVISOR_PROMPT,
                    user=user_content,
                )
                return response.strip().lower()
            except Exception as e:
                if "rate_limit" in str(e).lower() or "429" in str(e):
                    wait = 2 ** attempt  # exponential backoff: 1s, 2s, 4s
                    print(f"[supervisor] rate limit, retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    raise
        return "phishing"  # safe fallback after 3 failed attempts

    def _publish_to_human(self, alert: dict, reason: str) -> None:
        self._redis.xadd(STREAM_REJECTIONS, {
            "alert_id": alert["alert_id"],
            "reason": reason,
            "payload": json.dumps(alert),
        })