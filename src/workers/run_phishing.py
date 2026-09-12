import redis
import psycopg
import pandas as pd
from src.workers.phishing_worker import PhishingWorker
from src.workers.consumer import run_consumer
from src.agent.llm_client import StubLLMClient
from src.streams.config import STREAM_PHISHING
from src.tools.phishing_tools import click_history_lookup, reputation_lookup
from src.tools.registry import ToolRegistry


def main():
    r = redis.Redis(host="localhost", port=6379, decode_responses=True)

    conn = psycopg.connect(
        "postgresql://postgres:devpassword@localhost:5433/soc_agent"
    )

    registry = ToolRegistry({
        "click_history_lookup": lambda **kw: click_history_lookup(**kw),
        "reputation_lookup": lambda **kw: reputation_lookup(**kw),
    })

    data_sources = {
        "click_history": pd.DataFrame(),
        "reputation_records": pd.DataFrame(),
    }

    worker = PhishingWorker(
        llm_client=StubLLMClient(),
        redis_client=r,
        registry=registry,
        data_sources=data_sources,
        conn=conn,
    )

    run_consumer(worker, STREAM_PHISHING, "phishing-worker-1")


if __name__ == "__main__":
    main()