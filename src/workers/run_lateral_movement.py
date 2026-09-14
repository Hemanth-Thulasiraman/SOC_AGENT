import redis as redis_lib
from src.workers.lateral_movement_worker import LateralMovementWorker
from src.workers.consumer import run_consumer
from src.agent.llm_client import OpenAILLMClient
from src.streams.config import STREAM_LATERAL_MOVEMENT
from src.tools.lateral_movement_tools import ip_reputation_lookup, sql_correlation
from src.tools.flow_analysis import flow_analysis
from src.tools.registry import ToolRegistry
from src.data.build_fixtures import build_fixtures
from src.config import DATABASE_URL, REDIS_URL


def main():
    r = redis_lib.from_url(REDIS_URL, decode_responses=True)

    fixtures = build_fixtures("src/data/combined_alerts.json")

    registry = ToolRegistry({
        "ip_reputation_lookup": lambda **kw: ip_reputation_lookup(**kw),
        "sql_correlation": lambda **kw: sql_correlation(**kw),
        "flow_analysis": lambda **kw: flow_analysis(**kw),
    })

    data_sources = {
        "ip_reputation_records": fixtures["ip_reputation_records"],
        "investigations": fixtures["investigations"],
    }

    worker = LateralMovementWorker(
        llm_client=OpenAILLMClient(),
        redis_client=r,
        registry=registry,
        data_sources=data_sources,
        db_url=DATABASE_URL,
    )

    run_consumer(worker, STREAM_LATERAL_MOVEMENT, "lateral-movement-worker-1")


if __name__ == "__main__":
    main()