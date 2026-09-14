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
    domain: str
    expected_alert_type: str

    def __init__(
        self,
        llm_client: LLMClient,
        redis_client: redis.Redis,
        registry,
        data_sources: dict,
        db_url: str,  # store URL instead of connection
        true_label_lookup: dict | None = None,
    ):
        self._llm = llm_client
        self._redis = redis_client
        self._registry = registry
        self._data_sources = data_sources
        self._db_url = db_url  # store URL
        self._true_label_lookup = true_label_lookup

    def handle(self, message: dict) -> str:
        import psycopg
        from src.config import DATABASE_URL
        
        alert = json.loads(message["payload"])
        alert_type = alert.get("alert_type")

        if alert_type != self.expected_alert_type:
            self._reject(message, alert, reason=(
                f"alert_type={alert_type} does not match "
                f"worker domain={self.expected_alert_type}"
            ))
            return "rejected"

        # Fresh connections per investigation — avoids Neon idle timeout
        write_conn = psycopg.connect(self._db_url)
        query_conn = psycopg.connect(self._db_url)
        
        # Update data_sources with fresh query connection
        data_sources = {**self._data_sources, "conn": query_conn}

        graph = build_graph(
            self._llm, self._registry, data_sources,
            write_conn, self._true_label_lookup
        )

        state = new_investigation_state(
            alert_id=alert["alert_id"],
            alert_type=alert_type,
            raw_evidence=alert.get("raw_evidence", {}),
            is_synthetic=alert.get("is_synthetic", False),
        )
        
        try:
            graph.invoke(state)
        finally:
            write_conn.close()
            query_conn.close()
            
        return "done"