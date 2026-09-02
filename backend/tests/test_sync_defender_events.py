from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.jobs.sync_defender_events import sync_defender_events
from app.models.base import Base
from app.models.events import DefenderEvent


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def defender_row(event_id: int, event_time: str, threat_name: str | None = None) -> dict:
    return {
        "EventID": event_id,
        "EventTime": event_time,
        "Computer": "PC-01",
        "EventData": {"Threat Name": threat_name} if threat_name else {},
    }


def test_sync_defender_events_maps_event_ids_to_event_type() -> None:
    session = make_session()
    rows = [
        defender_row(1006, "2026-01-01T00:00:00Z", "Trojan:Win32/Foo"),
        defender_row(1116, "2026-01-01T00:00:01Z", "Trojan:Win32/Bar"),
        defender_row(1117, "2026-01-01T00:00:02Z", "Trojan:Win32/Bar"),
        defender_row(5001, "2026-01-01T00:00:03Z"),
    ]

    count = sync_defender_events(session, rows=rows)

    assert count == 4
    stmt = select(DefenderEvent).order_by(DefenderEvent.timestamp)
    events = session.execute(stmt).scalars().all()
    assert [e.event_type for e in events] == [
        "detect",
        "detect",
        "action_taken",
        "protection_disabled",
    ]
    assert events[0].threat_name == "Trojan:Win32/Foo"
    assert events[3].threat_name is None


def test_sync_defender_events_ignores_unknown_event_id() -> None:
    session = make_session()
    rows = [defender_row(9999, "2026-01-01T00:00:00Z")]

    count = sync_defender_events(session, rows=rows)

    assert count == 0


def test_sync_defender_events_skips_rows_already_synced() -> None:
    session = make_session()
    session.add(
        DefenderEvent(
            hostname="PC-01",
            event_type="detect",
            timestamp=datetime(2026, 1, 1, 0, 5, 0, tzinfo=UTC),
        )
    )
    session.commit()

    rows = [defender_row(1006, "2026-01-01T00:00:00Z")]
    count = sync_defender_events(session, rows=rows)

    assert count == 0
