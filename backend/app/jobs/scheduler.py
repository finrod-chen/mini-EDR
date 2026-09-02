"""APScheduler 排程,定期跑 app/jobs/ 底下的同步 job。

規格〈規則引擎〉章節假設 5~10 分鐘的延遲可接受,資產同步用同一個量級。
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app.core.db import SessionLocal
from app.jobs.sync_assets import sync_client_roster

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()


def _run_sync_client_roster() -> None:
    with SessionLocal() as session:
        try:
            count = sync_client_roster(session)
            logger.info("sync_client_roster synced %d assets", count)
        except Exception:
            logger.exception("sync_client_roster failed")


def start() -> None:
    if scheduler.running:
        return
    scheduler.add_job(
        _run_sync_client_roster,
        "interval",
        minutes=5,
        id="sync_client_roster",
        replace_existing=True,
    )
    scheduler.start()


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
