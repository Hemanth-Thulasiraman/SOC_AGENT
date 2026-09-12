"""
Base worker: shared investigation loop all three workers inherit from.
Each worker overrides: domain, tool_registry, confidence_weights.
"""
from __future__ import annotations
import json
import redis
from src.streams.config import STREAM_REJECTIONS
from src.agent.graph import build_graph
from src.agent.state import new_investigation_state
from src.agent.llm_client import LLMClient


class BaseWorker:
    domain: str  # "phishing" | "lateral_movement" | "insider_threat"
    expected_alert_type: str

    def __init__(
        self,
        llm_client: LLMClient,
        redis_client: redis.Redis,
        registry,
        data_sources: dict,
        conn,
        true_label_lookup: dict | None = None,
    ):
        self._llm = llm_client
        self._redis = redis_client
        self._graph = build_graph(
            llm_client, registry, data_sources, conn, true_label_lookup
        )

    def handle(self, message: dict) -> str:
        alert = json.loads(message["payload"])
        alert_type = alert.get("alert_type")

        if alert_type != self.expected_alert_type:
            self._reject(message, alert, reason=(
                f"alert_type={alert_type} does not match "
                f"worker domain={self.expected_alert_type}"
            ))
            return "rejected"

        state = new_investigation_state(
            alert_id=alert["alert_id"],
            alert_type=alert_type,
            raw_evidence=alert.get("raw_evidence", {}),
            is_synthetic=alert.get("is_synthetic", False),
        )
        self._graph.invoke(state)
        return "done"

    def _reject(self, message: dict, alert: dict, reason: str) -> None:
        self._redis.xadd(STREAM_REJECTIONS, {
            "alert_id": alert["alert_id"],
            "worker_stream": f"soc:alerts:{self.domain}",
            "attempt": message.get("attempt", "1"),
            "reason": reason,
            "payload": message["payload"],
        })