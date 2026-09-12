"""
Consumer loop: reads from one Redis stream and dispatches
to the worker. Runs as a blocking loop in its own process.
"""
from __future__ import annotations
import time
import redis
from src.streams.config import CONSUMER_GROUP


def run_consumer(worker, stream: str, consumer_name: str) -> None:
    """
    worker: an instance of BaseWorker subclass
    stream: the Redis stream to consume from
    consumer_name: unique name for this consumer instance
                   (matters if you run multiple instances of the same worker)
    """
    r = worker._redis
    print(f"[{consumer_name}] listening on {stream}")

    while True:
        try:
            # Block for up to 2 seconds waiting for a new message
            messages = r.xreadgroup(
                groupname=CONSUMER_GROUP,
                consumername=consumer_name,
                streams={stream: ">"},
                count=1,
                block=2000,  # ms
            )

            if not messages:
                continue  # nothing arrived, loop and wait again

            # messages shape: [(stream_name, [(msg_id, msg_dict), ...])]
            for stream_name, entries in messages:
                for msg_id, msg_dict in entries:
                    print(f"[{consumer_name}] received {msg_dict.get('alert_id')}")
                    try:
                        worker.handle(msg_dict)
                        # Acknowledge — tells Redis this message was processed
                        r.xack(stream_name, CONSUMER_GROUP, msg_id)
                        print(f"[{consumer_name}] done {msg_dict.get('alert_id')}")
                    except Exception as e:
                        # Don't acknowledge on failure — Redis will
                        # redeliver to another consumer after timeout
                        print(f"[{consumer_name}] error: {e}")

        except KeyboardInterrupt:
            print(f"[{consumer_name}] shutting down")
            break
        except Exception as e:
            print(f"[{consumer_name}] consumer error: {e}")
            time.sleep(1)  # brief pause before retrying