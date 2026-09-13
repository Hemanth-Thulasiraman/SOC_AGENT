import redis
import psycopg
from src.workers.lateral_movement_worker import LateralMovementWorker
from src.workers.consumer import run_consumer
from src.agent.llm_client import StubLLMClient
from src.streams.config import STREAM_LATERAL_MOVEMENT
from src.tools.lateral_movement_tools import ip_reputation_lookup, sql_correlation
from src.tools.registry import ToolRegistry
from src.data.build_fixtures import build_fixtures


def main():
    r = redis.Redis(host="localhost", port=6379, decode_responses=True)
    conn = psycopg.connect(
        "postgresql://postgres:devpassword@localhost:5433/soc_agent"
    )

    fixtures = build_fixtures("src/data/combined_alerts.json")

    registry = ToolRegistry({
        "ip_reputation_lookup": lambda **kw: ip_reputation_lookup(**kw),
        "sql_correlation": lambda **kw: sql_correlation(**kw),
    })

    data_sources = {
        "ip_reputation_records": fixtures["ip_reputation_records"],
        "investigations": fixtures["investigations"],
        "conn": conn,
    }

    worker = LateralMovementWorker(
        llm_client=StubLLMClient(),
        redis_client=r,
        registry=registry,
        data_sources=data_sources,
        conn=conn,
    )

    run_consumer(worker, STREAM_LATERAL_MOVEMENT, "lateral-movement-worker-1")


if __name__ == "__main__":
    main()