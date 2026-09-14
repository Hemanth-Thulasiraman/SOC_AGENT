"""
Consumer loop: reads from one Redis stream and dispatches
to the worker. Runs as a blocking loop in its own process.
"""
from __future__ import annotations
import traceback
import time
import redis
from src.streams.config import CONSUMER_GROUP


def run_consumer(worker, stream: str, consumer_name: str) -> None:
    """
    worker: an instance of BaseWorker subclass
    stream: the Redis stream to consume from
    consumer_name: unique name for this consumer instance
    """
    r = worker._redis
    
    # Create consumer group if it doesn't exist
    try:
        r.xgroup_create(stream, CONSUMER_GROUP, id="$", mkstream=True)
        print(f"[{consumer_name}] created consumer group for {stream}")
    except Exception as e:
        if "BUSYGROUP" in str(e):
            pass  # group already exists, fine
        else:
            raise
    
    print(f"[{consumer_name}] listening on {stream}")

    while True:
        try:
            messages = r.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=consumer_name,
                streams={stream: ">"},
                count=1,
                block=2000,
            )

            if not messages:
                continue

            for stream_name, entries in messages:
                for msg_id, msg_dict in entries:
                    print(f"[{consumer_name}] received {msg_dict.get('alert_id')}")
                    try:
                        result = worker.handle(msg_dict)
                        r.xack(stream_name, CONSUMER_GROUP, msg_id)
                        if result != "rejected":
                            print(f"[{consumer_name}] done {msg_dict.get('alert_id')}")
                        else:
                            print(f"[{consumer_name}] rejected {msg_dict.get('alert_id')} → sent to rejections stream")
                    except Exception as e:
                        traceback.print_exc()
                        print(f"[{consumer_name}] error: {e}")

        except KeyboardInterrupt:
            print(f"[{consumer_name}] shutting down")
            break
        except Exception as e:
            traceback.print_exc()
            print(f"[{consumer_name}] consumer error: {e}")
            time.sleep(1)