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

sync_software_inventory() 用 Windows.Detection.Amcache(見函式本身的說明
——這個 artifact 的正確名稱、資料特性、以及只留有 EntryName 紀錄的過濾
決策都是實機驗證/跟使用者確認過的,細節寫在函式 docstring,不重複寫在
這裡),排程頻率跟硬體同步一樣低。
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models.asset import AssetInventory, SoftwareInventory
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

# "Windows.Detection.Amcache" 不是 Windows.System.Amcache(那個名稱在這個
# Velociraptor 版本不存在,實機測過會直接 "Unknown artifact")。這是社群
# artifact(作者 Matt Green),GUI 的 View Artifacts 搜尋 Amcache 找到、手動
# 存成 Server Artifact 才能用,原始 YAML 裡的 name 欄位其實寫的是
# "Custom.Windows.Detection.Amcache",但存檔後實際生效的名稱是這裡的
# "Windows.Detection.Amcache"(沒有 Custom. 前綴),同樣是實機驗證過才確定
# 的,不要憑印象改回帶前綴的版本。
_SOFTWARE_HUNT_VQL = """
SELECT hunt(
    description='mini-edr sync_software_inventory',
    artifacts=['Windows.Detection.Amcache'],
    os="windows",
    expires=now() + 1800
) AS hunt_id
FROM scope()
"""

_SOFTWARE_HUNT_RESULTS_VQL = (
    "SELECT * FROM hunt_results(hunt_id=HuntId, artifact='Windows.Detection.Amcache')"
)

_BYTES_PER_GIB = 1024**3


def _launch_and_poll_hunt(
    launch_vql: str, results_vql: str, *, timeout: float = 90.0, poll_interval: float = 5.0
) -> list[dict[str, Any]]:
    """建 hunt 並輪詢等結果,而不是建完立刻查——hunt 是非同步的,client 要等
    下一次 polling 週期才會真的執行,立刻查幾乎都是空的(同
    app/services/evtx_hunt.py 的 run_evtx_hunt() 撞到的坑,這裡另外寫一份是
    因為 Generic.Client.Info/Windows.Detection.Amcache 不需要
    ChannelRegex/IdRegex 這種 evtx 專屬的 spec 參數,共用介面不合適)。
    """
    launch_rows = velociraptor_client.query(launch_vql)
    hunt_id = str(launch_rows[0]["hunt_id"]["HuntId"])
    deadline = time.monotonic() + timeout
    rows: list[dict[str, Any]] = []
    while True:
        rows = velociraptor_client.query(results_vql, HuntId=hunt_id)
        if rows or time.monotonic() >= deadline:
            return rows
        time.sleep(poll_interval)

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
        rows = _launch_and_poll_hunt(_HARDWARE_HUNT_VQL, _HARDWARE_HUNT_RESULTS_VQL)

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


def sync_software_inventory(
    session: Session, rows: list[dict[str, Any]] | None = None
) -> int:
    """用 Windows.Detection.Amcache 補 software_inventory(見本模組開頭對這個
    artifact 的說明)。回傳寫入筆數。

    Amcache 記錄的是「執行過的 PE 檔案」,不是嚴格意義上的「已安裝軟體」,
    一台機器動輒回報幾千筆,大量是沒有 EntryName 的驅動程式/系統元件
    (EntryType 常是 InventoryNonArp,代表沒透過「新增/移除程式」註冊安裝)。
    這裡只留 EntryName 不是空字串的紀錄,把明顯不是「軟體」的雜訊濾掉
    ——這是規劃決策,不是資料有缺陷:濾掉的部分依然是真實資料,只是不適合
    當「軟體清單」呈現。

    install_date 故意不填:Amcache 沒有可靠的「安裝日期」欄位,KeyMTime
    (登錄機碼修改時間)頂多是「第一次被記錄」的時間,跟真正的安裝時間
    不是同一件事,硬湊容易誤導分析師。

    每次執行都是整批覆蓋(先刪掉該資產舊的 software_inventory 再寫入新的),
    不是逐筆 append——這份資料本質是「當下的快照」,不該無限累積成一堆
    重複紀錄的歷史 log。

    只更新已經存在的資產(邏輯同 sync_hardware_details()),`rows` 參數只給
    測試注入用,正常呼叫不用傳。
    """
    if rows is None:
        rows = _launch_and_poll_hunt(_SOFTWARE_HUNT_VQL, _SOFTWARE_HUNT_RESULTS_VQL)

    by_hostname: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        entry_name = row.get("EntryName")
        fqdn = row.get("Fqdn")
        if not entry_name or not fqdn:
            continue
        hostname = str(fqdn).split(".")[0]
        by_hostname.setdefault(hostname, []).append(row)

    synced = 0
    for hostname, entries in by_hostname.items():
        asset = session.execute(
            select(AssetInventory).where(AssetInventory.hostname == hostname)
        ).scalar_one_or_none()
        if asset is None:
            continue

        session.execute(
            delete(SoftwareInventory).where(SoftwareInventory.asset_id == asset.asset_id)
        )

        seen: set[tuple[str, str | None]] = set()
        for row in entries:
            name = str(row["EntryName"])
            version = row.get("Version") or None
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)

            session.add(
                SoftwareInventory(
                    asset_id=asset.asset_id,
                    software_name=name,
                    version=version,
                    publisher=row.get("Publisher") or None,
                )
            )
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
        sw_count = sync_software_inventory(db_session)
        print(f"synced {sw_count} software entries")
