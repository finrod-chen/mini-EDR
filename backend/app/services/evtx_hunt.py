"""共用:用 hunt() + hunt_results() 對所有 Windows 端點跑
`Windows.EventLogs.EvtxHunter`,給 app/jobs/sync_sysmon_events.py 與
app/jobs/sync_defender_events.py 共用。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services import velociraptor_client

EVTX_HUNTER_ARTIFACT = "Windows.EventLogs.EvtxHunter"

_LAUNCH_HUNT_VQL = """
SELECT hunt(
    description=Description,
    artifacts=[Artifact],
    spec=dict(`Windows.EventLogs.EvtxHunter`=dict(
        ChannelRegex=ChannelRegex,
        IdRegex=IdRegex
    )),
    os="windows",
    expires=now() + 1800
) AS hunt_id
FROM scope()
"""

_HUNT_RESULTS_VQL = "SELECT * FROM hunt_results(hunt_id=HuntId, artifact=Artifact)"


def launch_evtx_hunt(description: str, channel_regex: str, id_regex: str) -> str:
    rows = velociraptor_client.query(
        _LAUNCH_HUNT_VQL,
        Description=description,
        Artifact=EVTX_HUNTER_ARTIFACT,
        ChannelRegex=channel_regex,
        IdRegex=id_regex,
    )
    return str(rows[0]["hunt_id"])


def fetch_hunt_results(hunt_id: str) -> list[dict[str, Any]]:
    return velociraptor_client.query(
        _HUNT_RESULTS_VQL, HuntId=hunt_id, Artifact=EVTX_HUNTER_ARTIFACT
    )


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
