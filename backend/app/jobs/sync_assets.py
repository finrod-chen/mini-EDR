"""資產清單同步 job(Phase 1)。

用 Velociraptor 的 `clients()` VQL plugin 讀「Server 已知的端點清單」寫入
asset_inventory 的 hostname / os_version / last_seen 欄位。這份清單是
Velociraptor Server 本來就持續維護的 datastore 內容,查詢不會另外對端點
發起新的 collection,適合每 5~10 分鐘的排程頻率(見規格〈規則引擎〉章節的
延遲假設)。

os_version 讀 `os_info.release`(實機驗證過,例如
"Microsoft Windows 11 Pro23H2"),`clients()` 這個 plugin 本身就有,不用另外
發起 collection。

vendor / model / cpu / memory / ip / defender_* 這幾個欄位還是刻意先不做:
規格核心 Artifact 清單裡的 Generic.Client.Info 只保證有
Hostname/OS/Platform/Architecture/MACAddresses(BasicInformation source)與
Windows 專屬的 TotalPhysicalMemory/DomainRole/IPAddresses
(WindowsInfo source,https://docs.velociraptor.app/artifact_references/pages/generic.client.info/),
完全沒有 vendor/model/cpu,也沒有任何 artifact 涵蓋 defender_status 相關
欄位——這是規格本身留下的缺口,不是遺漏。實作 sync_hardware_details() 前,
請先在真實 Velociraptor 環境對至少一台端點跑一次 Generic.Client.Info,
對照實際輸出欄位後再補。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import AssetInventory
from app.services import velociraptor_client

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


def sync_hardware_details(session: Session) -> None:
    """待補:vendor/model/cpu/memory/ip/defender_* 欄位同步(os_version 已經在
    sync_client_roster() 裡處理掉了,見本模組開頭的說明)。

    需要先在真實 Velociraptor 環境確認 Generic.Client.Info(以及 Defender
    狀態要另外找資料來源,規格的核心 Artifact 清單沒有涵蓋)的實際輸出欄位,
    見本模組開頭的說明,才不會寫出憑空猜欄位名稱、實際永遠是 None 的程式碼。
    """
    raise NotImplementedError(
        "需要先在真實 Velociraptor 環境確認 Generic.Client.Info 的實際輸出欄位,"
        "見 deploy/velociraptor/README.md 與本模組的說明"
    )


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        count = sync_client_roster(db_session)
        print(f"synced {count} assets")
