import redis
import psycopg
from src.workers.insider_threat_worker import InsiderThreatWorker
from src.workers.consumer import run_consumer
from src.agent.llm_client import StubLLMClient
from src.streams.config import STREAM_INSIDER_THREAT
from src.tools.insider_threat_tools import user_behavior_lookup, data_access_logs
from src.tools.registry import ToolRegistry
from src.data.build_fixtures import build_fixtures


def main():
    r = redis.Redis(host="localhost", port=6379, decode_responses=True)
    conn = psycopg.connect(
        "postgresql://postgres:devpassword@localhost:5433/soc_agent"
    )

    fixtures = build_fixtures("src/data/combined_alerts.json")

    registry = ToolRegistry({
        "user_behavior_lookup": lambda **kw: user_behavior_lookup(**kw),
        "data_access_logs": lambda **kw: data_access_logs(**kw),
    })

    data_sources = {
        "behavior_records": fixtures["behavior_records"],
        "access_records": fixtures["access_records"],
    }

    worker = InsiderThreatWorker(
        llm_client=StubLLMClient(),
        redis_client=r,
        registry=registry,
        data_sources=data_sources,
        conn=conn,
    )

    run_consumer(worker, STREAM_INSIDER_THREAT, "insider-threat-worker-1")


if __name__ == "__main__":
    main()