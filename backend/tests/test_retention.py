from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.jobs.retention import purge_old_defender_events
from app.models.base import Base
from app.models.events import DefenderEvent


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_purge_old_defender_events_deletes_only_expired_rows() -> None:
    session = make_session()
    now = datetime.now(UTC)
    session.add_all(
        [
            DefenderEvent(hostname="OLD", event_type="detect", timestamp=now - timedelta(days=200)),
            DefenderEvent(hostname="NEW", event_type="detect", timestamp=now - timedelta(days=1)),
        ]
    )
    session.commit()

    deleted = purge_old_defender_events(session, retention=timedelta(days=182))

    assert deleted == 1
    remaining = session.execute(select(DefenderEvent)).scalars().all()
    assert [e.hostname for e in remaining] == ["NEW"]
