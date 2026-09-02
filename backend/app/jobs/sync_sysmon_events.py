"""Sysmon process/network 事件同步 job(Phase 2)。

用 app.services.evtx_hunt 對所有 Windows 端點跑
`Windows.EventLogs.EvtxHunter`,鎖定 Microsoft-Windows-Sysmon/Operational
channel 的 Process Create(EventID 1)與 Network Connection(EventID 3),
寫入 process_events / network_events。

欄位對應到 EventData 的 key 名稱(Image/CommandLine/ProcessId/
ParentProcessId/User/Hashes/SourceIp/DestinationIp/DestinationPort)是
Sysmon 官方文件穩定多年沒變的 schema,可信度高;真正需要在真實環境驗證的
是 `Windows.EventLogs.EvtxHunter` 這個 artifact 回傳的 EventData 是否原封
不動保留這些 key(理論上會,因為它就是把 evtx 的 EventData XML 節點轉成
dict),但沒有實機測過。

已知限制(v1,規格接受 5~10 分鐘延遲、不做即時 streaming pipeline 的前提下
可接受,量大時建議改用 Velociraptor 的 Client Monitoring 事件機制取代這種
「每次都重新掃一輪」的 hunt 模式):
- 每次執行都會建立一個新的 hunt,重新掃過 EvtxHunter 預設涵蓋的 Sysmon
  紀錄範圍,不是只抓「上次同步之後」的新事件——不確定 EvtxHunter 有沒有
  內建時間篩選參數,所以不去猜參數名稱,改成寫入端用(全域 MAX(timestamp))
  當高水位篩掉已經寫過的事件。
- 沒有等 hunt 全部端點跑完就讀結果(100 台端點不一定都在線、也不一定同時
  回應),呼叫端要接受單次同步可能拿不到還沒回應的端點資料,下次排程會
  再補上。
- 高水位是全域 MAX,不是分主機,若某台端點時鐘明顯超前,可能誤壓到其他
  主機同時間窗的事件——量小的環境目前先接受這個簡化。
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.events import NetworkEvent, ProcessEvent
from app.services import evtx_hunt

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PROCESS_CREATE_EVENT_ID = 1
NETWORK_CONNECT_EVENT_ID = 3


def sync_sysmon_events(
    session: Session, rows: list[dict[str, Any]] | None = None
) -> tuple[int, int]:
    """回傳 (process_events 新增筆數, network_events 新增筆數)。

    `rows` 只給測試注入用,正常呼叫不用傳——會自己建 hunt 並讀結果。
    """
    if rows is None:
        hunt_id = evtx_hunt.launch_evtx_hunt(
            description="mini-edr sync_sysmon_events",
            channel_regex=SYSMON_CHANNEL,
            id_regex=f"{PROCESS_CREATE_EVENT_ID}|{NETWORK_CONNECT_EVENT_ID}",
        )
        rows = evtx_hunt.fetch_hunt_results(hunt_id)

    process_high_water_raw = session.execute(select(func.max(ProcessEvent.timestamp))).scalar()
    network_high_water_raw = session.execute(select(func.max(NetworkEvent.timestamp))).scalar()
    process_high_water = (
        evtx_hunt.ensure_utc(process_high_water_raw) if process_high_water_raw else None
    )
    network_high_water = (
        evtx_hunt.ensure_utc(network_high_water_raw) if network_high_water_raw else None
    )

    process_count = 0
    network_count = 0
    for row in rows:
        event_time = evtx_hunt.parse_event_time(row.get("EventTime"))
        if event_time is None:
            continue

        event_id = evtx_hunt.to_int(row.get("EventID"))
        event_data: dict[str, Any] = row.get("EventData") or {}
        hostname = row.get("Computer")

        if event_id == PROCESS_CREATE_EVENT_ID:
            if process_high_water is not None and event_time <= process_high_water:
                continue
            session.add(
                ProcessEvent(
                    timestamp=event_time,
                    hostname=hostname,
                    pid=evtx_hunt.to_int(event_data.get("ProcessId")),
                    ppid=evtx_hunt.to_int(event_data.get("ParentProcessId")),
                    user=event_data.get("User"),
                    image=event_data.get("Image"),
                    command_line=event_data.get("CommandLine"),
                    hash=event_data.get("Hashes"),
                )
            )
            process_count += 1
        elif event_id == NETWORK_CONNECT_EVENT_ID:
            if network_high_water is not None and event_time <= network_high_water:
                continue
            session.add(
                NetworkEvent(
                    timestamp=event_time,
                    hostname=hostname,
                    process_name=event_data.get("Image"),
                    src_ip=event_data.get("SourceIp"),
                    dst_ip=event_data.get("DestinationIp"),
                    dst_port=evtx_hunt.to_int(event_data.get("DestinationPort")),
                )
            )
            network_count += 1

    session.commit()
    return process_count, network_count


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        p_count, n_count = sync_sysmon_events(db_session)
        print(f"synced {p_count} process_events, {n_count} network_events")
