"""Defender 事件同步 job(Phase 2)。

用 app.services.evtx_hunt 對所有 Windows 端點跑
`Windows.EventLogs.EvtxHunter`,鎖定 Microsoft-Windows-Windows Defender/
Operational channel 的 4 個規格列出的 Event ID,寫入 defender_events。

event_type 對應(對照規格 defender_events.event_type 欄位註解
`-- detect / action_taken / protection_disabled`,規格只分三類但列了四個
Event ID,1006/1116 都算「偵測到」,合併成同一個 event_type 是規格本身的
設計,不是這裡簡化的):

| Event ID | event_type          |
|----------|---------------------|
| 1006     | detect              |
| 1116     | detect              |
| 1117     | action_taken        |
| 5001     | protection_disabled |

threat_name 讀 EventData 的 "Threat Name"(含空白,這是 Defender operational
log 1006/1116/1117 共用的標準欄位名稱,5001 不是偵測事件、通常沒有這個欄位,
threat_name 會是 None)。

高水位去重邏輯與已知限制同 app/jobs/sync_sysmon_events.py。
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.events import DefenderEvent
from app.services import evtx_hunt

DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"

EVENT_TYPE_BY_ID: dict[int, str] = {
    1006: "detect",
    1116: "detect",
    1117: "action_taken",
    5001: "protection_disabled",
}


def sync_defender_events(session: Session, rows: list[dict[str, Any]] | None = None) -> int:
    """回傳 defender_events 新增筆數。

    `rows` 只給測試注入用,正常呼叫不用傳——會自己建 hunt 並讀結果。
    """
    if rows is None:
        rows = evtx_hunt.run_evtx_hunt(
            description="mini-edr sync_defender_events",
            channel_regex=DEFENDER_CHANNEL,
            id_regex="|".join(str(event_id) for event_id in EVENT_TYPE_BY_ID),
        )

    high_water_raw = session.execute(select(func.max(DefenderEvent.timestamp))).scalar()
    high_water = evtx_hunt.ensure_utc(high_water_raw) if high_water_raw else None

    count = 0
    for row in rows:
        event_time = evtx_hunt.parse_event_time(row.get("EventTime"))
        if event_time is None:
            continue
        if high_water is not None and event_time <= high_water:
            continue

        event_id = evtx_hunt.to_int(row.get("EventID"))
        event_type = EVENT_TYPE_BY_ID.get(event_id) if event_id is not None else None
        if event_type is None:
            continue

        event_data: dict[str, Any] = row.get("EventData") or {}
        session.add(
            DefenderEvent(
                hostname=row.get("Computer"),
                event_type=event_type,
                threat_name=event_data.get("Threat Name"),
                timestamp=event_time,
            )
        )
        count += 1

    session.commit()
    return count


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        synced = sync_defender_events(db_session)
        print(f"synced {synced} defender_events")
