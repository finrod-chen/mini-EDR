"""共用:用 hunt() + hunt_results() 對所有 Windows 端點跑
`Windows.EventLogs.EvtxHunter`,給 app/jobs/sync_sysmon_events.py 與
app/jobs/sync_defender_events.py 共用。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services import velociraptor_client

EVTX_HUNTER_ARTIFACT = "Windows.EventLogs.EvtxHunter"

# artifact 名稱(在 artifacts=[...] 跟 spec 的 dict key 裡)故意用 f-string
# 寫死成字面量,不能走 VQL env 變數帶進去——見
# app/services/velociraptor_remediation.py 開頭的說明,hunt()/collect_client()
# 的 ACL 檢查需要在編譯當下就能靜態解析出實際會跑哪個 artifact,如果是變數
# 會靜默回傳 NULL(不拋錯誤),導致 launch_evtx_hunt() 拿到的 hunt_id 一直是
# None,實機測試撞到這個坑才發現的(sync_sysmon_events/sync_defender_events
# 因此從來沒有真的同步到任何事件)。EVTX_HUNTER_ARTIFACT 是程式碼常數不是
# 使用者輸入,寫死進 VQL 字串沒有注入風險。
_LAUNCH_HUNT_VQL = f"""
SELECT hunt(
    description=Description,
    artifacts=['{EVTX_HUNTER_ARTIFACT}'],
    spec=dict(`{EVTX_HUNTER_ARTIFACT}`=dict(
        ChannelRegex=ChannelRegex,
        IdRegex=IdRegex
    )),
    os="windows",
    expires=now() + 1800
) AS hunt_id
FROM scope()
"""

_HUNT_RESULTS_VQL = f"SELECT * FROM hunt_results(hunt_id=HuntId, artifact='{EVTX_HUNTER_ARTIFACT}')"


def launch_evtx_hunt(description: str, channel_regex: str, id_regex: str) -> str:
    rows = velociraptor_client.query(
        _LAUNCH_HUNT_VQL,
        Description=description,
        ChannelRegex=channel_regex,
        IdRegex=id_regex,
    )
    return str(rows[0]["hunt_id"])


def fetch_hunt_results(hunt_id: str) -> list[dict[str, Any]]:
    return velociraptor_client.query(_HUNT_RESULTS_VQL, HuntId=hunt_id)


def to_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ensure_utc(value: datetime) -> datetime:
    # SQLite(單元測試用)讀回來的 TIMESTAMP 會丟 tzinfo,Postgres 的
    # TIMESTAMPTZ 不會有這個問題,這裡統一補上 UTC 避免 aware/naive datetime
    # 互相比較時噴 TypeError。
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def parse_event_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)
    try:
        return ensure_utc(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError:
        return None
