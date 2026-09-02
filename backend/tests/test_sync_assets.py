from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.jobs.sync_assets import sync_client_roster
from app.models.asset import AssetInventory
from app.models.base import Base


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def assert_same_instant(actual: datetime | None, expected_epoch: int) -> None:
    # SQLite 沒有原生 tz-aware timestamp,寫入/讀出後 tzinfo 會被丟掉(Postgres
    # 的 TIMESTAMPTZ 不會有這個問題),測試環境用 SQLite 只比對「naive UTC」數值。
    assert actual is not None
    assert actual.replace(tzinfo=UTC) == datetime.fromtimestamp(expected_epoch, tz=UTC)


def test_sync_client_roster_inserts_new_assets() -> None:
    session = make_session()
    rows = [
        {"client_id": "C.1111", "hostname": "PC-01", "last_seen_at": 1_700_000_000},
        {"client_id": "C.2222", "hostname": "PC-02", "last_seen_at": 1_700_000_100},
    ]

    synced = sync_client_roster(session, rows=rows)

    assert synced == 2
    stmt = select(AssetInventory).order_by(AssetInventory.hostname)
    assets = session.execute(stmt).scalars().all()
    assert [a.hostname for a in assets] == ["PC-01", "PC-02"]
    assert_same_instant(assets[0].last_seen, 1_700_000_000)


def test_sync_client_roster_updates_existing_asset_by_hostname() -> None:
    session = make_session()
    session.add(AssetInventory(hostname="PC-01", last_seen=None))
    session.commit()

    rows = [{"client_id": "C.1111", "hostname": "PC-01", "last_seen_at": 1_700_000_200}]
    synced = sync_client_roster(session, rows=rows)

    assert synced == 1
    assets = session.execute(select(AssetInventory)).scalars().all()
    assert len(assets) == 1
    assert_same_instant(assets[0].last_seen, 1_700_000_200)


def test_sync_client_roster_skips_rows_without_hostname() -> None:
    session = make_session()
    rows = [{"client_id": "C.1111", "hostname": None, "last_seen_at": 1_700_000_000}]

    synced = sync_client_roster(session, rows=rows)

    assert synced == 0
    assert session.execute(select(AssetInventory)).scalars().all() == []
