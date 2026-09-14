"""Central config — reads from environment variables."""
import os

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:devpassword@localhost:5433/soc_agent"
)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")