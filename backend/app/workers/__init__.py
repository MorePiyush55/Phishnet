"""
PhishNet Background Workers
===========================
Background task workers for automated email processing.
"""

from app.workers.email_polling_worker import (
    EmailPollingWorker,
    get_email_polling_worker,
    start_background_polling,
    email_polling_service,
    WorkerState,
    WorkerMetrics
)

__all__ = [
    "EmailPollingWorker",
    "get_email_polling_worker",
    "start_background_polling",
    "email_polling_service",
    "WorkerState",
    "WorkerMetrics"
]
