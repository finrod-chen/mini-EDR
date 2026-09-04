"""資產清單同步 job(Phase 1)。

用 Velociraptor 的 `clients()` VQL plugin 讀「Server 已知的端點清單」寫入
asset_inventory 的 hostname / os_version / last_seen 欄位。這份清單是
Velociraptor Server 本來就持續維護的 datastore 內容,查詢不會另外對端點
發起新的 collection,適合每 5~10 分鐘的排程頻率(見規格〈規則引擎〉章節的
延遲假設)。

os_version 讀 `os_info.release`(實機驗證過,例如
"Microsoft Windows 11 Pro23H2"),`clients()` 這個 plugin 本身就有,不用另外
發起 collection。

sync_hardware_details() 補 ip / memory,實機對 Generic.Client.Info 的
WindowsInfo source 驗證過真實欄位:`Computer Info.TotalPhysicalMemory`
(位元組數字字串)、`Network Info.IPAddresses`(逗號分隔,IPv4/IPv6 混在一起,
例如 "192.168.2.24, fe80::...")。vendor/model/cpu/defender_* 這幾個欄位
還是刻意留白:Generic.Client.Info 的 BasicInformation/WindowsInfo 兩個
source 完全沒有 vendor/model/cpu,也沒有任何規格核心 Artifact 清單內的
artifact 涵蓋 defender_status 相關欄位——這是規格本身留下的缺口,不是
遺漏或漏查。

硬體資訊很少變動,不需要跟事件同步一樣密集,sync_hardware_details() 排程
間隔要比 5 分鐘長很多(見 app/jobs/scheduler.py),而且用 hunt() 一次對
所有端點發起,不是逐台 collect_client()——100 台端點的規模下效率差很多。
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import AssetInventory
from app.services import velociraptor_client

_HARDWARE_HUNT_VQL = """
SELECT hunt(
    description='mini-edr sync_hardware_details',
    artifacts=['Generic.Client.Info'],
    os="windows",
    expires=now() + 1800
) AS hunt_id
FROM scope()
"""

_HARDWARE_HUNT_RESULTS_VQL = (
    "SELECT * FROM hunt_results(hunt_id=HuntId, artifact='Generic.Client.Info/WindowsInfo')"
)

_BYTES_PER_GIB = 1024**3

CLIENT_ROSTER_VQL = """
SELECT client_id,
       os_info.hostname AS hostname,
       os_info.release AS os_version,
       last_seen_at
FROM clients()
"""


def sync_client_roster(session: Session, rows: list[dict[str, Any]] | None = None) -> int:
    """把 Velociraptor 已知的端點清單(hostname + last_seen)同步進 asset_inventory。

    以 `hostname` 當作 upsert 的比對鍵,因為 asset_inventory.asset_id 是我們
    自己配發的 UUID、不是 Velociraptor 的 client_id(格式像 "C.869eb611..."、
    不是 UUID)。前提是內網端點的機器名稱是唯一的;若之後出現「重灌但沿用
    舊機名」以外的改名情境(換機名但沒重灌),這裡會把它當成新資產處理,
    需要另外設計 client_id 對應表才能解決,Phase 1 先不處理。

    `rows` 參數只給測試注入用,正常呼叫不用傳。
    """
    if rows is None:
        rows = velociraptor_client.query(CLIENT_ROSTER_VQL)

    synced = 0
    for row in rows:
        hostname = row.get("hostname")
        if not hostname:
            continue

        asset = session.execute(
            select(AssetInventory).where(AssetInventory.hostname == hostname)
        ).scalar_one_or_none()
        if asset is None:
            asset = AssetInventory(hostname=hostname)
            session.add(asset)

        os_version = row.get("os_version")
        if os_version:
            asset.os_version = os_version

        last_seen_at = row.get("last_seen_at")
        if last_seen_at:
            # Velociraptor 的 clients() 回傳的 last_seen_at 是微秒(microseconds)
            # 為單位的 Unix epoch,不是標準的秒數——直接丟給 fromtimestamp() 會把
            # 時間往後推 100 萬倍,算出西元幾千萬年這種荒謬日期而丟出
            # ValueError,讓整個函式在 commit 前就整個 crash(見這個 bug 被抓到
            # 的過程:sync_client_roster 因此從來沒有真的寫進資料庫過)。
            asset.last_seen = datetime.fromtimestamp(last_seen_at / 1_000_000, tz=UTC)

        synced += 1

    session.commit()
    return synced


def _format_memory(total_physical_memory: object) -> str | None:
    if total_physical_memory is None:
        return None
    try:
        bytes_value = int(str(total_physical_memory))
    except ValueError:
        return None
    return f"{bytes_value / _BYTES_PER_GIB:.1f} GB"


def _first_ipv4(ip_addresses: object) -> str | None:
    """IPAddresses 是逗號分隔字串,IPv4/IPv6 混在一起(IPv6 含 fe80:: 這種
    link-local 位址)。IPv6 一定含冒號,用這個簡單排除法取第一個 IPv4。"""
    if not isinstance(ip_addresses, str):
        return None
    for candidate in ip_addresses.split(","):
        candidate = candidate.strip()
        if candidate and ":" not in candidate:
            return candidate
    return None


def sync_hardware_details(
    session: Session, rows: list[dict[str, Any]] | None = None
) -> int:
    """補 asset_inventory 的 ip / memory(vendor/model/cpu 見本模組開頭的說明,
    Generic.Client.Info 沒有提供,持續留白)。回傳更新筆數。

    只更新已經存在的資產(由 sync_client_roster() 建立),不會自己新建——
    硬體同步的排程間隔比資產清單同步長很多,不該讓還沒被 roster 同步過的
    端點在這裡先被建立成缺 last_seen 的殘缺資料。

    `rows` 參數只給測試注入用,正常呼叫不用傳。
    """
    if rows is None:
        launch_rows = velociraptor_client.query(_HARDWARE_HUNT_VQL)
        hunt_id = str(launch_rows[0]["hunt_id"]["HuntId"])
        deadline = time.monotonic() + 90
        rows = []
        while True:
            rows = velociraptor_client.query(_HARDWARE_HUNT_RESULTS_VQL, HuntId=hunt_id)
            if rows or time.monotonic() >= deadline:
                break
            time.sleep(5)

    synced = 0
    for row in rows:
        computer_info = row.get("Computer Info") or {}
        network_info = row.get("Network Info") or {}
        hostname = computer_info.get("Name")
        if not hostname:
            continue

        asset = session.execute(
            select(AssetInventory).where(AssetInventory.hostname == hostname)
        ).scalar_one_or_none()
        if asset is None:
            continue

        memory = _format_memory(computer_info.get("TotalPhysicalMemory"))
        if memory:
            asset.memory = memory

        ip = _first_ipv4(network_info.get("IPAddresses"))
        if ip:
            asset.ip = ip

        synced += 1

    session.commit()
    return synced


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        count = sync_client_roster(db_session)
        print(f"synced {count} assets (roster)")
        hw_count = sync_hardware_details(db_session)
        print(f"synced {hw_count} assets (hardware)")
