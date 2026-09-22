"""APScheduler 排程,定期跑 app/jobs/ 底下的同步 job。

規格〈規則引擎〉章節假設 5~10 分鐘的延遲可接受,事件/資產同步都用同一個
量級;retention 清除不急,用天為單位即可。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler

from app.core.db import SessionLocal
from app.jobs.retention import purge_old_defender_events
from app.jobs.sync_assets import (
    sync_client_roster,
    sync_hardware_details,
    sync_software_inventory,
)
from app.jobs.sync_asus_exporter import sync_asus_exporter_assets
from app.jobs.sync_defender_events import sync_defender_events
from app.jobs.sync_snmp_assets import sync_snmp_assets
from app.jobs.sync_sysmon_events import sync_sysmon_events
from app.rules.engine import run_all_rules
from app.services import pan_os_remediation

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


def _run_sync_hardware_details() -> None:
    _run_with_session("sync_hardware_details", sync_hardware_details)


def _run_sync_software_inventory() -> None:
    _run_with_session("sync_software_inventory", sync_software_inventory)


def _run_sync_sysmon_events() -> None:
    _run_with_session("sync_sysmon_events", sync_sysmon_events)


def _run_sync_defender_events() -> None:
    _run_with_session("sync_defender_events", sync_defender_events)


def _run_sync_snmp_assets() -> None:
    _run_with_session("sync_snmp_assets", sync_snmp_assets)


def _run_sync_asus_exporter_assets() -> None:
    _run_with_session("sync_asus_exporter_assets", sync_asus_exporter_assets)


def _run_purge_old_defender_events() -> None:
    _run_with_session("purge_old_defender_events", purge_old_defender_events)


def _run_all_rules() -> None:
    _run_with_session("run_all_rules", run_all_rules)


def _run_clear_registered_ips() -> None:
    # 不需要 DB session,不走 _run_with_session——這個 job 只是呼叫 PAN-OS
    # API,見 pan_os_remediation.clear_all_registered_ips() 開頭的說明:
    # 這個指令對 persistent 條目沒有效果(使用者已知悉這個限制,仍要求
    # 排程執行)。
    try:
        result = pan_os_remediation.clear_all_registered_ips()
        logger.info("clear_registered_ips finished: %s", result)
    except Exception:
        logger.exception("clear_registered_ips failed")


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
    # 硬體資訊(ip/memory)很少變動,不用跟資產清單一樣密集,而且是用 hunt()
    # 對所有端點發起一次性收集(見 app/jobs/sync_assets.py 的說明),比資產
    # 清單同步(單純讀 server 已有的 datastore)貴得多,間隔要拉長。
    scheduler.add_job(
        _run_sync_hardware_details,
        "interval",
        hours=6,
        id="sync_hardware_details",
        replace_existing=True,
    )
    # 軟體清單(Windows.Detection.Amcache,見 app/jobs/sync_assets.py 的說明)
    # 同樣是貴的 hunt、同樣很少變動,間隔拉得更長;跟硬體同步的第一次執行
    # 錯開 3 分鐘,避免兩個都對所有端點發起 hunt 的排程同時搶跑。
    scheduler.add_job(
        _run_sync_software_inventory,
        "interval",
        hours=12,
        id="sync_software_inventory",
        next_run_time=datetime.now() + timedelta(minutes=3),
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
    # SNMP 輪詢是輕量的 UDP GET(不像 hunt 要等端點下一次 polling 週期),
    # 5 分鐘頻率沒問題;offset 2 分鐘避開 t=0 那批(sync_client_roster/
    # sync_sysmon_events/sync_defender_events)跟 run_all_rules 的 1 分鐘、
    # sync_software_inventory 的 3 分鐘。
    scheduler.add_job(
        _run_sync_snmp_assets,
        "interval",
        minutes=5,
        id="sync_snmp_assets",
        next_run_time=datetime.now() + timedelta(minutes=2),
        replace_existing=True,
    )
    # 同一種輕量 HTTP 輪詢,5 分鐘頻率跟 SNMP job 一致;offset 4 分鐘
    # 避開上面幾個 job 的 0/1/2/3 分鐘起始點,降低同時搶跑的機率。
    scheduler.add_job(
        _run_sync_asus_exporter_assets,
        "interval",
        minutes=5,
        id="sync_asus_exporter_assets",
        next_run_time=datetime.now() + timedelta(minutes=4),
        replace_existing=True,
    )
    scheduler.add_job(
        _run_purge_old_defender_events,
        "interval",
        hours=24,
        id="purge_old_defender_events",
        replace_existing=True,
    )
    # 規則要查詢事件同步 job 剛寫入的資料,把第一次執行時間錯開 1 分鐘,
    # 減少跟上面幾個同步 job 在同一時間點搶跑、看到還沒同步完資料的機率
    # (不是嚴格保證,只是降低機率——即使真的搶跑,下一輪 5 分鐘後也會補上)。
    scheduler.add_job(
        _run_all_rules,
        "interval",
        minutes=5,
        id="run_all_rules",
        next_run_time=datetime.now() + timedelta(minutes=1),
        replace_existing=True,
    )
    # 使用者明確要求的每日排程,不是我們建議的解法——這個指令對 PAN-OS
    # persistent 條目沒有效果(見 pan_os_remediation.clear_all_registered_ips
    # 開頭的說明),排這個排程不會解決 registered-IP 容量被塞滿的問題,只是
    # 清掉非 persistent 的殘留。
    scheduler.add_job(
        _run_clear_registered_ips,
        "cron",
        hour=7,
        minute=0,
        id="clear_registered_ips",
        replace_existing=True,
    )
    scheduler.start()


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
