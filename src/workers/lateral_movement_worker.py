from src.workers.base_worker import BaseWorker

class LateralMovementWorker(BaseWorker):
    domain = "lateral_movement"
    expected_alert_type = "lateral_movement"