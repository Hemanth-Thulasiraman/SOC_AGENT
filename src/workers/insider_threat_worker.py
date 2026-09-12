# src/workers/insider_threat_worker.py
from src.workers.base_worker import BaseWorker

class InsiderThreatWorker(BaseWorker):
    domain = "insider_threat"
    expected_alert_type = "insider_threat"