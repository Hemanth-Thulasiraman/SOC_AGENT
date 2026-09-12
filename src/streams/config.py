"""
Stream names and message schemas for supervisor → worker routing.
One stream per worker domain — workers only consume from their own stream.
"""

# Stream names
STREAM_PHISHING = "soc:alerts:phishing"
STREAM_LATERAL_MOVEMENT = "soc:alerts:lateral_movement"
STREAM_INSIDER_THREAT = "soc:alerts:insider_threat"
STREAM_REJECTIONS = "soc:alerts:rejections"  # workers publish back here on mismatch

# Consumer group name — all workers in the same group so each alert
# is processed by exactly one worker instance, not broadcast to all
CONSUMER_GROUP = "soc-workers"

# Maps alert_type values to their stream
ALERT_TYPE_TO_STREAM = {
    "phishing": STREAM_PHISHING,
    "lateral_movement": STREAM_LATERAL_MOVEMENT,
    "insider_threat": STREAM_INSIDER_THREAT,
}