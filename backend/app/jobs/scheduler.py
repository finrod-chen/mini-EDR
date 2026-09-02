"""APScheduler 排程,定期跑 app/jobs/ 底下的同步 job。

規格〈規則引擎〉章節假設 5~10 分鐘的延遲可接受,事件/資產同步都用同一個
量級;retention 清除不急,用天為單位即可。
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from apscheduler.schedulers.background import BackgroundScheduler

from app.core.db import SessionLocal
from app.jobs.retention import purge_old_defender_events
from app.jobs.sync_assets import sync_client_roster
from app.jobs.sync_defender_events import sync_defender_events
from app.jobs.sync_sysmon_events import sync_sysmon_events

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()


def _run_with_session(job_name: str, fn: Callable[..., object]) -> None:
    with SessionLocal() as session:
        try:
            result = fn(session)
            logger.info("%s finished: %s", job_name, result)
        except Exception:
            logger.exception("%s failed", job_name)


def _run_sync_client_roster() -> None:
    _run_with_session("sync_client_roster", sync_client_roster)


def _run_sync_sysmon_events() -> None:
    _run_with_session("sync_sysmon_events", sync_sysmon_events)


def _run_sync_defender_events() -> None:
    _run_with_session("sync_defender_events", sync_defender_events)


def _run_purge_old_defender_events() -> None:
    _run_with_session("purge_old_defender_events", purge_old_defender_events)


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
    scheduler.add_job(
        _run_sync_sysmon_events,
        "interval",
        minutes=5,
        id="sync_sysmon_events",
        replace_existing=True,
    )
    scheduler.add_job(
        _run_sync_defender_events,
        "interval",
        minutes=5,
        id="sync_defender_events",
        replace_existing=True,
    )
    scheduler.add_job(
        _run_purge_old_defender_events,
        "interval",
        hours=24,
        id="purge_old_defender_events",
        replace_existing=True,
    )
    scheduler.start()


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
