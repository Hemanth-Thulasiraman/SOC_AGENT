import redis as redis_lib
import psycopg
from src.config import DATABASE_URL, REDIS_URL
from src.workers.phishing_worker import PhishingWorker
from src.workers.consumer import run_consumer
from src.agent.llm_client import OpenAILLMClient
from src.streams.config import STREAM_PHISHING
from src.tools.phishing_tools import click_history_lookup, reputation_lookup
from src.tools.registry import ToolRegistry
from src.data.build_fixtures import build_fixtures


def main():
    r = redis_lib.from_url(REDIS_URL, decode_responses=True)

    query_conn = psycopg.connect(DATABASE_URL)
    write_conn = psycopg.connect(DATABASE_URL)

    fixtures = build_fixtures("src/data/combined_alerts.json")

    registry = ToolRegistry({
        "click_history_lookup": lambda **kw: click_history_lookup(**kw),
        "reputation_lookup": lambda **kw: reputation_lookup(**kw),
    })

    data_sources = {
        "click_history": fixtures["click_history"],
        "reputation_records": fixtures["reputation_records"],
        "conn": query_conn,
    }

    worker = PhishingWorker(
        llm_client=OpenAILLMClient(),
        redis_client=r,
        registry=registry,
        data_sources=data_sources,
        conn=write_conn,
    )

    run_consumer(worker, STREAM_PHISHING, "phishing-worker-1")


if __name__ == "__main__":
    main()
