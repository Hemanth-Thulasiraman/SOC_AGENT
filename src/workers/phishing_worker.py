from src.workers.base_worker import BaseWorker

class PhishingWorker(BaseWorker):
    domain = "phishing"
    expected_alert_type = "phishing"