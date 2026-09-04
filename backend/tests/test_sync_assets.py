from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.jobs.sync_assets import (
    sync_client_roster,
    sync_hardware_details,
    sync_software_inventory,
)
from app.models.asset import AssetInventory, SoftwareInventory
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
    # last_seen_at 是 Velociraptor 回傳的微秒(microseconds)epoch,不是秒數,
    # 見 app/jobs/sync_assets.py 的說明。
    rows = [
        {"client_id": "C.1111", "hostname": "PC-01", "last_seen_at": 1_700_000_000_000_000},
        {"client_id": "C.2222", "hostname": "PC-02", "last_seen_at": 1_700_000_100_000_000},
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

    rows = [{"client_id": "C.1111", "hostname": "PC-01", "last_seen_at": 1_700_000_200_000_000}]
    synced = sync_client_roster(session, rows=rows)

    assert synced == 1
    assets = session.execute(select(AssetInventory)).scalars().all()
    assert len(assets) == 1
    assert_same_instant(assets[0].last_seen, 1_700_000_200)


def test_sync_client_roster_stores_os_version() -> None:
    session = make_session()
    rows = [
        {
            "client_id": "C.1111",
            "hostname": "PC-01",
            "os_version": "Microsoft Windows 11 Pro23H2",
            "last_seen_at": 1_700_000_000_000_000,
        }
    ]

    sync_client_roster(session, rows=rows)

    asset = session.execute(select(AssetInventory)).scalar_one()
    assert asset.os_version == "Microsoft Windows 11 Pro23H2"


def test_sync_hardware_details_updates_existing_asset() -> None:
    session = make_session()
    session.add(AssetInventory(hostname="G60010"))
    session.commit()

    # 對照實機對 Generic.Client.Info/WindowsInfo 驗證過的真實結構。
    rows = [
        {
            "Computer Info": {
                "Name": "G60010",
                "TotalPhysicalMemory": "25567424512",
            },
            "Network Info": {
                "IPAddresses": "192.168.2.24, fe80::93b3:e824:5605:9ac2",
            },
        }
    ]

    synced = sync_hardware_details(session, rows=rows)

    assert synced == 1
    asset = session.execute(select(AssetInventory)).scalar_one()
    assert asset.ip == "192.168.2.24"
    assert asset.memory == "23.8 GB"


def test_sync_hardware_details_skips_unknown_hostname() -> None:
    session = make_session()
    rows = [
        {
            "Computer Info": {"Name": "UNKNOWN-PC", "TotalPhysicalMemory": "1000"},
            "Network Info": {"IPAddresses": "10.0.0.1"},
        }
    ]

    synced = sync_hardware_details(session, rows=rows)

    assert synced == 0
    assert session.execute(select(AssetInventory)).scalars().all() == []


def test_sync_software_inventory_filters_and_dedupes() -> None:
    session = make_session()
    session.add(AssetInventory(hostname="G60010"))
    session.commit()

    rows = [
        # 有 EntryName,要留下
        {
            "EntryName": "notepad.exe",
            "Version": "10.0.1",
            "Publisher": "Microsoft Corporation",
            "Fqdn": "G60010.ad.xiyuebiomed.com.tw",
        },
        # 同名同版本重複一次,要去重
        {
            "EntryName": "notepad.exe",
            "Version": "10.0.1",
            "Publisher": "Microsoft Corporation",
            "Fqdn": "G60010.ad.xiyuebiomed.com.tw",
        },
        # 沒有 EntryName(驅動程式/系統元件那類雜訊)要被濾掉
        {
            "EntryName": "",
            "Version": "1.0",
            "Fqdn": "G60010.ad.xiyuebiomed.com.tw",
        },
        # 沒有 Fqdn 對不到任何主機,要被濾掉
        {"EntryName": "orphan.exe", "Version": "1.0"},
    ]

    synced = sync_software_inventory(session, rows=rows)

    assert synced == 1
    entry = session.execute(select(SoftwareInventory)).scalar_one()
    assert entry.software_name == "notepad.exe"
    assert entry.version == "10.0.1"
    assert entry.publisher == "Microsoft Corporation"


def test_sync_software_inventory_replaces_previous_snapshot() -> None:
    session = make_session()
    asset = AssetInventory(hostname="G60010")
    session.add(asset)
    session.commit()
    session.add(SoftwareInventory(asset_id=asset.asset_id, software_name="stale.exe"))
    session.commit()

    rows = [{"EntryName": "fresh.exe", "Fqdn": "G60010.ad.xiyuebiomed.com.tw"}]
    sync_software_inventory(session, rows=rows)

    entries = session.execute(select(SoftwareInventory)).scalars().all()
    assert [e.software_name for e in entries] == ["fresh.exe"]


def test_sync_client_roster_skips_rows_without_hostname() -> None:
    session = make_session()
    rows = [{"client_id": "C.1111", "hostname": None, "last_seen_at": 1_700_000_000}]

    synced = sync_client_roster(session, rows=rows)

    assert synced == 0
    assert session.execute(select(AssetInventory)).scalars().all() == []
