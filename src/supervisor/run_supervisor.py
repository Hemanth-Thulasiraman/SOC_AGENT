import redis
import time
from src.supervisor.supervisor import SupervisorAgent
from src.agent.llm_client import StubLLMClient
from src.streams.config import STREAM_REJECTIONS


def main():
    r = redis.Redis(host="localhost", port=6379, decode_responses=True)
    supervisor = SupervisorAgent(StubLLMClient(), r)
    print("[supervisor] listening for rejections")

    while True:
        try:
            messages = r.xread(
                streams={STREAM_REJECTIONS: "$"},
                count=1,
                block=2000,
            )
            if not messages:
                continue
            for stream_name, entries in messages:
                for msg_id, msg_dict in entries:
                    print(f"[supervisor] re-routing {msg_dict.get('alert_id')}")
                    supervisor.handle_rejection(msg_dict)

        except KeyboardInterrupt:
            print("[supervisor] shutting down")
            break
        except Exception as e:
            print(f"[supervisor] error: {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()