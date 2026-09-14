import redis as redis_lib
from src.workers.insider_threat_worker import InsiderThreatWorker
from src.workers.consumer import run_consumer
from src.agent.llm_client import OpenAILLMClient
from src.streams.config import STREAM_INSIDER_THREAT
from src.tools.insider_threat_tools import user_behavior_lookup, data_access_logs
from src.tools.registry import ToolRegistry
from src.data.build_fixtures import build_fixtures
from src.config import DATABASE_URL, REDIS_URL


def main():
    r = redis_lib.from_url(REDIS_URL, decode_responses=True)

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
        llm_client=OpenAILLMClient(),
        redis_client=r,
        registry=registry,
        data_sources=data_sources,
        db_url=DATABASE_URL,
    )

    run_consumer(worker, STREAM_INSIDER_THREAT, "insider-threat-worker-1")


if __name__ == "__main__":
    main()