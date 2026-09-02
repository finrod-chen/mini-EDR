"""defender_events 的資料保留期限清除 job(Phase 2)。

process_events / network_events 是 TimescaleDB hypertable,保留期限已經在
migration(d6572296a296)用原生 `add_retention_policy(..., INTERVAL '6 months')`
處理,不需要另外寫程式清。

defender_events 不是 hypertable(見 app/models/events.py 的 DefenderEvent
docstring),沒有原生 retention policy 可用,所以用這支 job 定期
`DELETE ... WHERE timestamp < now() - 6 個月` 代替。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete
from sqlalchemy.orm import Session

from app.models.events import DefenderEvent

DEFENDER_EVENTS_RETENTION = timedelta(days=182)  # ~6 個月


def purge_old_defender_events(
    session: Session, retention: timedelta = DEFENDER_EVENTS_RETENTION
) -> int:
    cutoff = datetime.now(UTC) - retention
    stmt = delete(DefenderEvent).where(DefenderEvent.timestamp < cutoff)
    result = cast("CursorResult[Any]", session.execute(stmt))
    session.commit()
    return int(result.rowcount)


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        deleted = purge_old_defender_events(db_session)
        print(f"purged {deleted} defender_events")
