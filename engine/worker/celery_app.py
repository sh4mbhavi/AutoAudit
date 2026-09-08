"""Celery application configuration for AutoAudit worker."""

import ssl

from celery import Celery

from worker.config import settings

# Create Celery app
celery_app = Celery(
    "autoaudit",
    broker=settings.REDIS_URL,
    broker_use_ssl={"ssl_cert_reqs": ssl.CERT_REQUIRED, "ssl_check_hostname": True}
    if settings.REDIS_URL.startswith("rediss://")
    else None,
    # No result backend - results are written directly to PostgreSQL
)

# Configure Celery
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Task tracking
    task_track_started=False,
    task_ignore_result=True,
    task_store_errors_even_if_ignored=False,
    task_send_sent_event=False,
    worker_send_task_events=False,
    result_expires=3600,
    broker_transport_options={"visibility_timeout": 3600},
    # Task routing
    task_default_queue="autoaudit",
    # Retry settings
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Concurrency (for gevent pool)
    worker_concurrency=10,
)

# Auto-discover tasks from the worker.tasks module
celery_app.autodiscover_tasks(["worker"])
