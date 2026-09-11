"""SNMP v2c 資產監控 job(Phase 1:MIB-II 基本身分 + 連線狀態)。

跟 sync_assets.py(Velociraptor)完全獨立、互不呼叫——監控對象、識別鍵、
失敗語意都不一樣:這裡以 `ip` 當 upsert 鍵(monitor_type='snmp'),因為
SNMP 裝置的 sysName 常是空的或廠牌預設值(出廠沒改過),不像 hostname
一樣可靠,IP 才是這類裝置比較穩定的身分。

目標設備清單(IP/裝置類型)來自靜態 JSON 設定檔(見
app/core/config.py 的 snmp_targets_config_path,格式範本見
deploy/snmp/snmp_targets.example.json),不是資料庫表——裝置數量少、
極少變動,不需要 CRUD 介面。

MIB-II 標準 OID(sysDescr/sysObjectID/sysUpTime/sysName)所有裝置類型一律
查,拿來判斷「上線/離線 + 基本身分」。

Phase 2:MIB-II 之外,依 device_type 額外走一個裝置類型專屬的 SNMP table
(印表機 Printer-MIB 碳粉量、NAS HOST-RESOURCES-MIB 磁碟用量、防火牆
IF-MIB 介面狀態),彙整成統一的 [{"label":..., "value":...}, ...] 格式存進
snmp_metric_data,命中門檻(碳粉過低/磁碟過高/介面異常)時額外產生一句
snmp_metric_alert 文字,餵給健康分數扣分(見 app/services/health_score.py)。
這些 table 都只用標準 MIB,不做廠牌私有 MIB——覆蓋率因裝置而異,是已知
且可接受的限制。metrics 收集失敗或逾時不影響 MIB-II 判定的 ok/
snmp_last_poll_ok(裝置已經證明連得上),也不清空 snmp_metric_data/
snmp_metric_alert 的舊值,邏輯跟 sync_snmp_assets() 對 snmp_sys_descr 等
欄位「輪詢失敗保留上次成功值」一致。

SNMP 版本鎖定 v2c(CommunityData mpModel=1)是既定環境限制,不是這支模組
能改變的事;pysnmp 目前(7.x,lextudio 維護版)的同步 hlapi 已在 6.2 移除,
只剩 asyncio 介面(pysnmp.hlapi.v3arch.asyncio),所以 _poll_one() 內部用
asyncio.run() 包一層,讓這支模組對外仍是一般同步函式,符合
app/jobs/scheduler.py 的 BackgroundScheduler 呼叫慣例。
"""

from __future__ import annotations

import asyncio
import functools
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

# Printer-MIB(RFC 3805)prtMarkerSuppliesTable 的三個欄。
OID_PRT_MARKER_SUPPLIES_DESCRIPTION = "1.3.6.1.2.1.43.11.1.1.6"
OID_PRT_MARKER_SUPPLIES_MAX_CAPACITY = "1.3.6.1.2.1.43.11.1.1.8"
OID_PRT_MARKER_SUPPLIES_LEVEL = "1.3.6.1.2.1.43.11.1.1.9"
# 耗材百分比低於這個門檻才算「偏低」,寫死常數不開放設定——目前沒有使用者
# 要求可調整,不為假設性需求先開介面(比照 health_score.py 既有做法)。
PRINTER_LOW_SUPPLY_PERCENT = 10

# HOST-RESOURCES-MIB(RFC 2790)hrStorageTable 的四個欄。
OID_HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
OID_HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
# hrStorageType 只留這個類型(實體磁碟),排除記憶體/swap/網路磁碟等
# 非「本機磁碟容量」的項目。
HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"
NAS_HIGH_USAGE_PERCENT = 90

# IF-MIB(RFC 2863)ifTable 的三個欄。
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_STATUS_UP = "1"
IF_STATUS_DOWN = "2"

_DEFAULT_SNMP_PORT = 161
# metrics table walk 比單純 MIB-II GET 貴得多(要走好幾欄、好幾列),逾時
# 上限抓 timeout 的倍數,避免單一裝置卡住拖累同一輪 poll_all_targets 的
# 其他裝置(目前是逐台循序輪詢,不是併發)。
_METRICS_TIMEOUT_MULTIPLIER = 4
# _walk_column 的安全上限(50 輪 * 每輪最多 10 筆 = 500 列),防止裝置回應
# 異常(例如一直回報同一個 OID)造成無窮迴圈——實際印表機/NAS/防火牆的
# table 大小遠小於這個數字。
_MAX_WALK_ITERATIONS = 50
_WALK_MAX_REPETITIONS = 10


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
    # Phase 2:裝置類型專屬指標,見 _collect_printer_metrics 等函式。metrics
    # 收集失敗/逾時,或 device_type 沒有對應的收集器,兩者都保持 None——
    # 呼叫端(sync_snmp_assets)看到 None 就不覆蓋 asset 既有的欄位值,跟
    # ok=False 時不清空 sys_descr 等欄位是同一種「沒抓到就別動舊資料」設計。
    metric_data: list[dict[str, str]] | None = None
    metric_alert: str | None = None


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


def _decode_snmp_value(value: object) -> str:
    """SNMP OCTET STRING 的預設 str() 轉換不是 UTF-8-aware,遇到多位元組字元
    (例如中文資料夾/分享名稱)會逐 byte 對應成錯的字元,產生亂碼——在真實
    Synology NAS 的 hrStorageDescr(含中文分享資料夾名稱)上實測驗證過這個
    問題。優先用 pysnmp OctetString 的 asOctets() 拿原始 bytes,自己明確用
    UTF-8 解碼;非 OCTET STRING 的型別(Integer/TimeTicks/ObjectIdentifier
    等)沒有 asOctets(),直接退回原本的 str() 轉換——這些型別的 str() 本來
    就正確,不受這個問題影響,不用另外判斷型別。
    """
    as_octets = getattr(value, "asOctets", None)
    if as_octets is None:
        return str(value)
    try:
        return bytes(as_octets()).decode("utf-8")
    except UnicodeDecodeError:
        # 不是合法 UTF-8(少數裝置可能用別的編碼),退回預設轉換好過整個爛掉。
        return str(value)


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _build_printer_metrics(
    descriptions: dict[str, str], levels: dict[str, str], max_capacities: dict[str, str]
) -> tuple[list[dict[str, str]], str | None]:
    """把 prtMarkerSuppliesTable 三欄的 {列索引: 值} 合併成統一格式,並判斷
    是否有耗材偏低。只有 level>=0 且 maxCapacity>0 才計算百分比——RFC 3805
    定義了好幾個負數特殊碼(語意因裝置而異),與其猜錯,一律視為無法判讀,
    只保留描述文字供人工查看,不計入告警。"""
    metric_data: list[dict[str, str]] = []
    low_supplies: list[str] = []
    for index, description in descriptions.items():
        label = description or f"耗材 {index}"
        level = _to_int(levels.get(index))
        max_capacity = _to_int(max_capacities.get(index))
        if level is None or max_capacity is None or level < 0 or max_capacity <= 0:
            metric_data.append({"label": label, "value": "無法判讀"})
            continue
        percent = round(level / max_capacity * 100)
        metric_data.append({"label": label, "value": f"{percent}%"})
        if percent < PRINTER_LOW_SUPPLY_PERCENT:
            low_supplies.append(f"{label} {percent}%")
    alert = f"碳粉/耗材偏低({'、'.join(low_supplies)})" if low_supplies else None
    return metric_data, alert


def _build_nas_metrics(
    types: dict[str, str],
    descriptions: dict[str, str],
    sizes: dict[str, str],
    useds: dict[str, str],
) -> tuple[list[dict[str, str]], str | None]:
    """把 hrStorageTable 四欄的 {列索引: 值} 合併成統一格式,只留
    hrStorageFixedDisk 類型(排除記憶體/swap/網路磁碟),並判斷是否有磁碟
    使用率過高。"""
    metric_data: list[dict[str, str]] = []
    high_usage: list[str] = []
    for index, storage_type in types.items():
        if storage_type != HR_STORAGE_FIXED_DISK:
            continue
        label = descriptions.get(index) or f"磁碟 {index}"
        size = _to_int(sizes.get(index))
        used = _to_int(useds.get(index))
        if size is None or used is None or size <= 0:
            metric_data.append({"label": label, "value": "無法判讀"})
            continue
        percent = round(used / size * 100)
        metric_data.append({"label": label, "value": f"{percent}% 已使用"})
        if percent > NAS_HIGH_USAGE_PERCENT:
            high_usage.append(f"{label} {percent}%")
    alert = f"磁碟空間不足({'、'.join(high_usage)})" if high_usage else None
    return metric_data, alert


def _build_firewall_metrics(
    descriptions: dict[str, str], admin_statuses: dict[str, str], oper_statuses: dict[str, str]
) -> tuple[list[dict[str, str]], str | None]:
    """把 ifTable 三欄的 {列索引: 值} 合併成統一格式,只有「管理上啟用
    (ifAdminStatus=up)但實際斷線(ifOperStatus=down)」的介面才算異常——
    單純沒插線或本來就手動關閉的 port 不該一直誤報。"""
    metric_data: list[dict[str, str]] = []
    down_interfaces: list[str] = []
    for index, description in descriptions.items():
        label = description or f"介面 {index}"
        oper = oper_statuses.get(index)
        if oper == IF_STATUS_UP:
            status_text = "up"
        elif oper == IF_STATUS_DOWN:
            status_text = "down"
        else:
            status_text = "unknown"
        metric_data.append({"label": label, "value": status_text})
        if admin_statuses.get(index) == IF_STATUS_UP and oper == IF_STATUS_DOWN:
            down_interfaces.append(label)
    alert = f"介面異常({'、'.join(down_interfaces)})" if down_interfaces else None
    return metric_data, alert


async def _walk_column(
    snmp_engine: object, community: str, transport_target: object, base_oid: str
) -> dict[str, str]:
    """走一個 SNMP table 的單一欄(column),用 GETBULK 逐批取得,直到超出
    這個欄位的 OID 子樹或裝置回報 end-of-mib。回傳 {列索引(OID尾碼): 值},
    列索引是扣掉 base_oid 之後剩下的 OID 後綴,供呼叫端跟同一個 table
    其他欄位的結果對齊合併成一列列的資料。

    每次只請求一個 OID(不是 pysnmp 文件範例裡「多個 OID 交錯走」的用法)
    ——用「這批最後一個 OID」當下一批的起點,是標準 SNMP walk 的做法
    (snmpwalk/snmpbulkwalk 都是這樣),比信任 pysnmp 對多重 varbind GETBULK
    的內部延續邏輯更容易驗證正確性。
    """
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        bulk_cmd,
    )

    values: dict[str, str] = {}
    prefix = base_oid + "."
    next_oid = base_oid
    for _ in range(_MAX_WALK_ITERATIONS):
        error_indication, error_status, error_index, var_bind_table = await bulk_cmd(
            snmp_engine,
            CommunityData(community, mpModel=1),
            transport_target,
            ContextData(),
            0,
            _WALK_MAX_REPETITIONS,
            ObjectType(ObjectIdentity(next_oid)),
        )
        if error_indication or error_status or not var_bind_table:
            break
        reached_end = False
        for oid, value in var_bind_table:
            oid_str = str(oid)
            if not oid_str.startswith(prefix):
                reached_end = True
                break
            values[oid_str[len(prefix) :]] = _decode_snmp_value(value)
            next_oid = oid_str
        if reached_end:
            break
    return values


async def _collect_printer_metrics(
    snmp_engine: object, community: str, transport_target: object
) -> tuple[list[dict[str, str]], str | None] | None:
    walk = functools.partial(_walk_column, snmp_engine, community, transport_target)
    descriptions = await walk(OID_PRT_MARKER_SUPPLIES_DESCRIPTION)
    if not descriptions:
        return None
    levels = await walk(OID_PRT_MARKER_SUPPLIES_LEVEL)
    max_capacities = await walk(OID_PRT_MARKER_SUPPLIES_MAX_CAPACITY)
    return _build_printer_metrics(descriptions, levels, max_capacities)


async def _collect_nas_metrics(
    snmp_engine: object, community: str, transport_target: object
) -> tuple[list[dict[str, str]], str | None] | None:
    walk = functools.partial(_walk_column, snmp_engine, community, transport_target)
    types = await walk(OID_HR_STORAGE_TYPE)
    if not types:
        return None
    descriptions = await walk(OID_HR_STORAGE_DESCR)
    sizes = await walk(OID_HR_STORAGE_SIZE)
    useds = await walk(OID_HR_STORAGE_USED)
    return _build_nas_metrics(types, descriptions, sizes, useds)


async def _collect_firewall_metrics(
    snmp_engine: object, community: str, transport_target: object
) -> tuple[list[dict[str, str]], str | None] | None:
    walk = functools.partial(_walk_column, snmp_engine, community, transport_target)
    descriptions = await walk(OID_IF_DESCR)
    if not descriptions:
        return None
    admin_statuses = await walk(OID_IF_ADMIN_STATUS)
    oper_statuses = await walk(OID_IF_OPER_STATUS)
    return _build_firewall_metrics(descriptions, admin_statuses, oper_statuses)


_METRIC_COLLECTORS = {
    "printer": _collect_printer_metrics,
    "nas": _collect_nas_metrics,
    "firewall": _collect_firewall_metrics,
}


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
        if error_indication or error_status:
            return SnmpPollResult(ip=target.ip, ok=False)

        sys_descr, sys_object_id, sys_uptime, sys_name = (
            _decode_snmp_value(vb[1]) for vb in var_binds
        )
        uptime_seconds: int | None
        try:
            # sysUpTime 是 TimeTicks(百分之一秒為單位),換算成秒數方便儲存/顯示。
            uptime_seconds = int(sys_uptime) // 100
        except ValueError:
            uptime_seconds = None

        metric_data: list[dict[str, str]] | None = None
        metric_alert: str | None = None
        collector = _METRIC_COLLECTORS.get(target.device_type)
        if collector is not None:
            try:
                collected = await asyncio.wait_for(
                    collector(snmp_engine, community, transport_target),
                    timeout=timeout * _METRICS_TIMEOUT_MULTIPLIER,
                )
            except Exception:
                # metrics 是「盡量而為」,收集失敗/逾時不影響 MIB-II 已經證明
                # 的連線成功狀態,也不該讓整個 SnmpPollResult 變成失敗。
                logger.warning(
                    "SNMP metrics collection failed for %s (%s)", target.ip, target.device_type
                )
            else:
                if collected is not None:
                    metric_data, metric_alert = collected
    finally:
        snmp_engine.close_dispatcher()

    return SnmpPollResult(
        ip=target.ip,
        ok=True,
        sys_descr=sys_descr or None,
        sys_object_id=sys_object_id or None,
        sys_name=sys_name or None,
        uptime_seconds=uptime_seconds,
        metric_data=metric_data,
        metric_alert=metric_alert,
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

        # metric_data 用獨立的 None 判斷(不是跟著 result.ok 一起判斷)——
        # 即使 MIB-II 成功(ok=True),裝置類型專屬指標這次也可能因為逾時/
        # 例外而沒抓到(見 _get_mib2_fields 的 except 分支),這時一樣要保留
        # 上次成功抓到的 metrics,不能因為這次沒抓到就清空。
        if result.metric_data is not None:
            asset.snmp_metric_data = result.metric_data
            asset.snmp_metric_alert = result.metric_alert

        synced += 1

    session.commit()
    return synced


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        count = sync_snmp_assets(db_session)
        print(f"synced {count} SNMP assets")
