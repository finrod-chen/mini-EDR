"""ASUS 路由器資產監控(沒有 SNMP 服務的裝置,見 deploy/asus-exporter/README.md)。

跟 sync_snmp_assets.py 共用同一套 asset_inventory 資料模型
(monitor_type='snmp' + ip 當 upsert 鍵),但資料來源完全不是 SNMP——是
deploy/asus-exporter/ 這個 vendor 進來的第三方 Prometheus exporter,模擬
ASUS 官方 App 登入路由器管理介面拿到 CPU/記憶體/uptime/連線裝置/WAN
狀態。刻意沿用 monitor_type='snmp' 而不是另開一個獨立的值,是為了讓這批
裝置直接吃到既有的健康分數(app/services/health_score.py)與資產管理
頁面 UI,不用另外刻一套——代價是 snmp_last_poll_ok/snmp_uptime_seconds/
snmp_metric_data 這些欄位名稱字面上是「snmp」但資料其實是 HTTP scrape
來的,這個語意落差是已知且接受的取捨。

一個 exporter container 只服務一台路由器(見 deploy/asus-exporter/
asus-exporter.py 的 login_router() 沒有多目標概念),監控多台路由器就是
多個 exporter_url,目標清單見 app/core/config.py 的
asus_exporter_targets_config_path。
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from prometheus_client.parser import text_string_to_metric_families
from prometheus_client.samples import Sample
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.asset import AssetInventory

logger = logging.getLogger(__name__)

# CPU/記憶體使用率超過這個門檻才算異常,比照 sync_snmp_assets.py 的
# NAS_HIGH_USAGE_PERCENT=90 同一個量級——裝置持續高負載但還連得上,
# 嚴重度定位在「留意」而不是「完全連不上」。
ROUTER_HIGH_CPU_PERCENT = 90
ROUTER_HIGH_MEMORY_PERCENT = 90


@dataclass
class AsusExporterTarget:
    exporter_url: str
    ip: str
    label: str


@dataclass
class AsusExporterPollResult:
    ip: str
    ok: bool
    uptime_seconds: int | None = None
    metric_data: list[dict[str, str]] | None = None
    metric_alert: str | None = None


def load_asus_exporter_targets(config_path: str | None = None) -> list[AsusExporterTarget]:
    """讀靜態 JSON 設定檔(格式見 deploy/asus_exporter/asus_targets.example.json)。

    設定檔不存在時直接讓 FileNotFoundError 往外拋——這是設定錯誤,不是
    「沒有目標可監控」這種正常情境,不該吞掉讓 job 靜默跑出 0 筆結果
    (跟 sync_snmp_assets.py 的 load_snmp_targets() 同一個理由)。
    """
    path = config_path or settings.asus_exporter_targets_config_path
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return [
        AsusExporterTarget(exporter_url=item["exporter_url"], ip=item["ip"], label=item["label"])
        for item in raw
    ]


def _parse_metrics(text: str) -> dict[str, list[Sample]]:
    """把 Prometheus text exposition 格式解析成 {metric_name: samples}。"""
    return {family.name: list(family.samples) for family in text_string_to_metric_families(text)}


def _build_metrics(
    families: dict[str, list[Sample]],
) -> tuple[int | None, list[dict[str, str]], str | None]:
    """把解析出的 Prometheus samples 轉成 (uptime_seconds, metric_data, metric_alert),
    格式比照 sync_snmp_assets.py 的 _build_nas_metrics 等函式:統一
    [{"label":..., "value":...}, ...] 讓前端不用分資料來源另刻 UI。"""
    metric_data: list[dict[str, str]] = []
    alerts: list[str] = []

    uptime_seconds: int | None = None
    uptime_samples = families.get("uptime")
    if uptime_samples:
        uptime_seconds = int(uptime_samples[0].value)

    # 少於 4 核心的路由器,沒有的核心 exporter 會明確回報 NaN(不是 0.0
    # ——Gauge 沒被 set 過預設就是 0.0,無法分辨「真的閒置在 0%」還是
    # 「這台路由器沒有這顆核心」,見 deploy/asus-exporter/asus-exporter.py
    # 的說明),這裡要濾掉 NaN,不然平均值會被不存在的核心拉低。
    cpu_values = [
        families[name][0].value
        for name in ("cpu1_percent", "cpu2_percent", "cpu3_percent", "cpu4_percent")
        if families.get(name) and not math.isnan(families[name][0].value)
    ]
    if cpu_values:
        cpu_avg = round(sum(cpu_values) / len(cpu_values))
        metric_data.append({"label": "CPU 使用率", "value": f"{cpu_avg}%"})
        if cpu_avg > ROUTER_HIGH_CPU_PERCENT:
            alerts.append(f"CPU 使用率過高({cpu_avg}%)")

    memory_total = families.get("memory_total")
    memory_used = families.get("memory_used")
    if memory_total and memory_used and memory_total[0].value > 0:
        memory_percent = round(memory_used[0].value / memory_total[0].value * 100)
        metric_data.append({"label": "記憶體使用率", "value": f"{memory_percent}%"})
        if memory_percent > ROUTER_HIGH_MEMORY_PERCENT:
            alerts.append(f"記憶體使用率過高({memory_percent}%)")

    active_devices = families.get("active_device")
    if active_devices:
        # 同一台裝置的每種 metric(RSSI/RX/TX/連線時間)各是一筆獨立
        # sample,用 mac_address 去重才是實際連線裝置數。
        distinct_macs = {
            s.labels.get("mac_address") for s in active_devices if s.labels.get("mac_address")
        }
        metric_data.append({"label": "無線連線裝置數", "value": str(len(distinct_macs))})

    wan_samples = families.get("wan_information")
    if wan_samples:
        # wan_status 數值語意上游沒有文件說明(見 deploy/asus-exporter/
        # asus-exporter.py 的 parse_wanlink_status),先只顯示原始值,
        # 不判斷異常——寫死猜測的門檻風險比不判斷更高,等有實機資料再補。
        wan_status = wan_samples[0].labels.get("wan_status", "unknown")
        metric_data.append({"label": "WAN 狀態", "value": wan_status})

    alert = "、".join(alerts) if alerts else None
    return uptime_seconds, metric_data, alert


def _poll_one(target: AsusExporterTarget, *, timeout: float) -> AsusExporterPollResult:
    """對單一 exporter 發 HTTP GET,失敗(逾時/連線失敗/HTTP 錯誤/解析失敗/
    抓不到 uptime)一律回傳 ok=False,不拋例外——呼叫端(poll_all_targets)
    逐台輪詢,一台壞掉不能讓其他台也拿不到結果(跟 sync_snmp_assets.py 的
    _poll_one 同一個設計)。"""
    try:
        response = httpx.get(target.exporter_url, timeout=timeout)
        response.raise_for_status()
        families = _parse_metrics(response.text)
        uptime_seconds, metric_data, metric_alert = _build_metrics(families)
    except Exception:
        logger.warning("ASUS exporter poll failed for %s (%s)", target.ip, target.exporter_url)
        return AsusExporterPollResult(ip=target.ip, ok=False)

    if uptime_seconds is None:
        # 連上了 exporter,但 uptime 這個最基本的指標都沒抓到,視同這次
        # 輪詢沒有成功——跟 SNMP job 用 MIB-II GET 是否成功當「有沒有拿到
        # 最基本身分資訊」是同一種判斷。
        return AsusExporterPollResult(ip=target.ip, ok=False)

    return AsusExporterPollResult(
        ip=target.ip,
        ok=True,
        uptime_seconds=uptime_seconds,
        metric_data=metric_data or None,
        metric_alert=metric_alert,
    )


def poll_all_targets(
    targets: list[AsusExporterTarget] | None = None, *, timeout: float | None = None
) -> list[AsusExporterPollResult]:
    """輪詢所有設定檔裡的目標。每一台獨立 try/except,逐台失敗不影響其他台。"""
    if targets is None:
        targets = load_asus_exporter_targets()
    resolved_timeout = timeout if timeout is not None else settings.asus_exporter_timeout_seconds

    results: list[AsusExporterPollResult] = []
    for target in targets:
        try:
            result = _poll_one(target, timeout=resolved_timeout)
        except Exception:
            logger.exception("ASUS exporter poll failed for %s", target.ip)
            result = AsusExporterPollResult(ip=target.ip, ok=False)
        results.append(result)
    return results


def sync_asus_exporter_assets(
    session: Session,
    targets: list[AsusExporterTarget] | None = None,
    results: list[AsusExporterPollResult] | None = None,
) -> int:
    """把輪詢結果 upsert 進 asset_inventory,邏輯幾乎照抄
    sync_snmp_assets.sync_snmp_assets()——monitor_type='snmp' + ip 當比對
    鍵,ok=False 時不覆蓋既有身分資訊,只更新 snmp_last_poll_at/ok。

    device_type 固定寫 'router'(跟 SNMP 路由器共用同一個值,資產管理
    頁面不用分辨資料來源)。hostname 永遠等於設定檔的 label——這類裝置
    沒有自報的 sysName 可用,不像 SNMP 裝置的 hostname 有 sys_name 當
    第一順位、label 只是備援。
    """
    if targets is None:
        targets = load_asus_exporter_targets()
    label_by_ip = {t.ip: t.label for t in targets}

    if results is None:
        results = poll_all_targets(targets)

    synced = 0
    now = datetime.now(UTC)
    for result in results:
        asset = session.execute(
            select(AssetInventory).where(
                AssetInventory.monitor_type == "snmp",
                AssetInventory.ip == result.ip,
            )
        ).scalar_one_or_none()
        if asset is None:
            asset = AssetInventory(monitor_type="snmp", ip=result.ip)
            session.add(asset)

        asset.device_type = "router"
        asset.snmp_last_poll_at = now
        asset.snmp_last_poll_ok = result.ok

        if result.ok:
            asset.hostname = label_by_ip.get(result.ip, asset.hostname)
            asset.snmp_uptime_seconds = result.uptime_seconds
            asset.last_seen = now
        # ok=False:保留上一次成功輪詢的身分資訊,只更新
        # snmp_last_poll_ok/at,理由跟 sync_snmp_assets.py 完全一致。

        if result.metric_data is not None:
            asset.snmp_metric_data = result.metric_data
            asset.snmp_metric_alert = result.metric_alert

        synced += 1

    session.commit()
    return synced


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        count = sync_asus_exporter_assets(db_session)
        print(f"synced {count} ASUS exporter assets")
