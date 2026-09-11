"""SNMP v2c 資產監控 job(Phase 1:MIB-II 基本身分 + 連線狀態)。

跟 sync_assets.py(Velociraptor)完全獨立、互不呼叫——監控對象、識別鍵、
失敗語意都不一樣:這裡以 `ip` 當 upsert 鍵(monitor_type='snmp'),因為
SNMP 裝置的 sysName 常是空的或廠牌預設值(出廠沒改過),不像 hostname
一樣可靠,IP 才是這類裝置比較穩定的身分。

目標設備清單(IP/裝置類型)來自靜態 JSON 設定檔(見
app/core/config.py 的 snmp_targets_config_path,格式範本見
deploy/snmp/snmp_targets.example.json),不是資料庫表——裝置數量少、
極少變動,不需要 CRUD 介面。

Phase 1 只查 MIB-II 標準 OID(sysDescr/sysObjectID/sysUpTime/sysName),
所有裝置類型一律適用,拿來判斷「上線/離線 + 基本身分」。印表機碳粉量、
NAS 磁碟用量、防火牆介面狀態這類裝置類型專屬指標刻意不在這支模組裡——
先把最小可用的端到端路徑走通,裝置專屬指標之後再加,不影響這裡已經定的
schema/upsert 邏輯。

SNMP 版本鎖定 v2c(CommunityData mpModel=1)是既定環境限制,不是這支模組
能改變的事;pysnmp 目前(7.x,lextudio 維護版)的同步 hlapi 已在 6.2 移除,
只剩 asyncio 介面(pysnmp.hlapi.v3arch.asyncio),所以 _poll_one() 內部用
asyncio.run() 包一層,讓這支模組對外仍是一般同步函式,符合
app/jobs/scheduler.py 的 BackgroundScheduler 呼叫慣例。
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.asset import AssetInventory

logger = logging.getLogger(__name__)

# MIB-II(RFC 1213)標準 OID,所有 SNMP 目標一律查這四個,不分裝置類型。
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

_DEFAULT_SNMP_PORT = 161


@dataclass
class SnmpTarget:
    ip: str
    device_type: str = "other"
    label: str | None = None
    port: int = _DEFAULT_SNMP_PORT


@dataclass
class SnmpPollResult:
    ip: str
    ok: bool
    sys_descr: str | None = None
    sys_object_id: str | None = None
    sys_name: str | None = None
    uptime_seconds: int | None = None


def load_snmp_targets(config_path: str | None = None) -> list[SnmpTarget]:
    """讀靜態 JSON 設定檔(格式見 deploy/snmp/snmp_targets.example.json)。

    設定檔不存在時直接讓 FileNotFoundError 往外拋——這是設定錯誤,不是
    「沒有目標可監控」這種正常情境,不該吞掉讓 job 靜默跑出 0 筆結果。
    """
    path = config_path or settings.snmp_targets_config_path
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return [
        SnmpTarget(
            ip=item["ip"],
            device_type=item.get("device_type", "other"),
            label=item.get("label"),
            port=item.get("port", _DEFAULT_SNMP_PORT),
        )
        for item in raw
    ]


async def _get_mib2_fields(
    target: SnmpTarget, *, community: str, timeout: float, retries: int
) -> SnmpPollResult:
    # 延遲 import:pysnmp 只有這支模組會用到,不用讓整個 app 啟動都載入它。
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )

    snmp_engine = SnmpEngine()
    transport_target = await UdpTransportTarget.create(
        (target.ip, target.port), timeout=timeout, retries=retries
    )
    try:
        error_indication, error_status, error_index, var_binds = await get_cmd(
            snmp_engine,
            CommunityData(community, mpModel=1),  # mpModel=1 => SNMPv2c
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(OID_SYS_DESCR)),
            ObjectType(ObjectIdentity(OID_SYS_OBJECT_ID)),
            ObjectType(ObjectIdentity(OID_SYS_UPTIME)),
            ObjectType(ObjectIdentity(OID_SYS_NAME)),
        )
    finally:
        snmp_engine.close_dispatcher()

    if error_indication or error_status:
        return SnmpPollResult(ip=target.ip, ok=False)

    sys_descr, sys_object_id, sys_uptime, sys_name = (str(vb[1]) for vb in var_binds)
    uptime_seconds: int | None
    try:
        # sysUpTime 是 TimeTicks(百分之一秒為單位),換算成秒數方便儲存/顯示。
        uptime_seconds = int(sys_uptime) // 100
    except ValueError:
        uptime_seconds = None

    return SnmpPollResult(
        ip=target.ip,
        ok=True,
        sys_descr=sys_descr or None,
        sys_object_id=sys_object_id or None,
        sys_name=sys_name or None,
        uptime_seconds=uptime_seconds,
    )


def _poll_one(
    target: SnmpTarget, *, community: str, timeout: float, retries: int
) -> SnmpPollResult:
    """對單一裝置發 SNMP GET,失敗(逾時/無回應/community 錯誤/裝置不支援
    某個 OID)一律回傳 ok=False,不拋例外——呼叫端(poll_all_targets)逐台
    輪詢,一台壞掉不能讓其他台也拿不到結果。"""
    return asyncio.run(
        _get_mib2_fields(target, community=community, timeout=timeout, retries=retries)
    )


def poll_all_targets(
    targets: list[SnmpTarget] | None = None,
    *,
    community: str | None = None,
    timeout: float | None = None,
    retries: int | None = None,
) -> list[SnmpPollResult]:
    """輪詢所有設定檔裡的目標。每一台獨立 try/except,逐台失敗不影響其他台。"""
    if targets is None:
        targets = load_snmp_targets()
    resolved_community = community if community is not None else settings.snmp_community
    resolved_timeout = timeout if timeout is not None else settings.snmp_timeout_seconds
    resolved_retries = retries if retries is not None else settings.snmp_retries

    results: list[SnmpPollResult] = []
    for target in targets:
        try:
            result = _poll_one(
                target,
                community=resolved_community,
                timeout=resolved_timeout,
                retries=resolved_retries,
            )
        except Exception:
            logger.exception("SNMP poll failed for %s", target.ip)
            result = SnmpPollResult(ip=target.ip, ok=False)
        results.append(result)
    return results


def sync_snmp_assets(
    session: Session,
    targets: list[SnmpTarget] | None = None,
    results: list[SnmpPollResult] | None = None,
) -> int:
    """把 SNMP 輪詢結果 upsert 進 asset_inventory,以 ip + monitor_type='snmp'
    當比對鍵(理由見本模組開頭說明)——不會跟 monitor_type='velociraptor'
    的資產混淆或互相覆蓋,即使兩者剛好 IP 相同(理論上不會發生,但查詢條件
    仍明確帶 monitor_type 過濾,不依賴這個假設)。

    `targets`/`results` 都只給測試注入用:`results` 可以整個繞過真正的
    SNMP I/O(單元測試主要用這個),`targets` 只在需要單獨測試「讀取設定檔
    以外的裝置清單」時才需要(例如測試 upsert 邏輯本身,不想連帶測
    load_snmp_targets)。兩者都不給時各自走正常流程(讀設定檔 / 實際輪詢)。
    """
    if targets is None:
        targets = load_snmp_targets()
    device_type_by_ip = {t.ip: t.device_type for t in targets}
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

        asset.device_type = device_type_by_ip.get(result.ip, asset.device_type)
        asset.snmp_last_poll_at = now
        asset.snmp_last_poll_ok = result.ok

        if result.ok:
            asset.hostname = result.sys_name or label_by_ip.get(result.ip) or asset.hostname
            asset.snmp_sys_descr = result.sys_descr
            asset.snmp_sys_object_id = result.sys_object_id
            asset.snmp_uptime_seconds = result.uptime_seconds
            asset.last_seen = now
        # ok=False:刻意不覆蓋 hostname/snmp_sys_descr/snmp_uptime_seconds/
        # last_seen——保留上一次成功輪詢的身分資訊,只更新
        # snmp_last_poll_ok/at,讓健康分數的離線判斷(見 health_score.py)
        # 跟前端都還看得到裝置「上一次是什麼」,不會因為輪詢失敗一次就整批
        # 清空成 NULL。

        synced += 1

    session.commit()
    return synced


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        count = sync_snmp_assets(db_session)
        print(f"synced {count} SNMP assets")
