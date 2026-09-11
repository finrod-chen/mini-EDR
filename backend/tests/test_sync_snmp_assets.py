import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.jobs.sync_snmp_assets import (
    SnmpPollResult,
    SnmpTarget,
    load_snmp_targets,
    poll_all_targets,
    sync_snmp_assets,
)
from app.models.asset import AssetInventory
from app.models.base import Base


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_sync_snmp_assets_inserts_new_device() -> None:
    session = make_session()
    targets = [SnmpTarget(ip="10.0.0.5", device_type="printer", label="MFP")]
    results = [
        SnmpPollResult(
            ip="10.0.0.5",
            ok=True,
            sys_descr="HP LaserJet",
            sys_object_id="1.3.6.1.4.1.11.2.3.9.1",
            sys_name="MFP-3F",
            uptime_seconds=12345,
        )
    ]

    synced = sync_snmp_assets(session, targets=targets, results=results)

    assert synced == 1
    asset = session.execute(select(AssetInventory)).scalar_one()
    assert asset.monitor_type == "snmp"
    assert asset.ip == "10.0.0.5"
    assert asset.device_type == "printer"
    assert asset.hostname == "MFP-3F"
    assert asset.snmp_sys_descr == "HP LaserJet"
    assert asset.snmp_sys_object_id == "1.3.6.1.4.1.11.2.3.9.1"
    assert asset.snmp_uptime_seconds == 12345
    assert asset.snmp_last_poll_ok is True
    assert asset.last_seen is not None


def test_sync_snmp_assets_updates_existing_by_ip_not_hostname() -> None:
    session = make_session()
    session.add(
        AssetInventory(
            monitor_type="snmp", ip="10.0.0.5", hostname="old-name", device_type="printer"
        )
    )
    session.commit()

    targets = [SnmpTarget(ip="10.0.0.5", device_type="printer")]
    results = [SnmpPollResult(ip="10.0.0.5", ok=True, sys_name="new-name")]

    synced = sync_snmp_assets(session, targets=targets, results=results)

    assert synced == 1
    assets = session.execute(select(AssetInventory)).scalars().all()
    assert len(assets) == 1
    assert assets[0].hostname == "new-name"


def test_sync_snmp_assets_failed_poll_sets_offline_without_clearing_identity() -> None:
    session = make_session()
    session.add(
        AssetInventory(
            monitor_type="snmp",
            ip="10.0.0.5",
            hostname="MFP-3F",
            snmp_sys_descr="HP LaserJet",
            snmp_uptime_seconds=999,
            snmp_last_poll_ok=True,
        )
    )
    session.commit()

    targets = [SnmpTarget(ip="10.0.0.5", device_type="printer")]
    results = [SnmpPollResult(ip="10.0.0.5", ok=False)]

    synced = sync_snmp_assets(session, targets=targets, results=results)

    assert synced == 1
    asset = session.execute(select(AssetInventory)).scalar_one()
    assert asset.snmp_last_poll_ok is False
    assert asset.snmp_last_poll_at is not None
    # 失敗不清空既有身分資訊
    assert asset.hostname == "MFP-3F"
    assert asset.snmp_sys_descr == "HP LaserJet"
    assert asset.snmp_uptime_seconds == 999


def test_sync_snmp_assets_one_failure_does_not_block_others() -> None:
    session = make_session()
    targets = [
        SnmpTarget(ip="10.0.0.5", device_type="printer"),
        SnmpTarget(ip="10.0.0.6", device_type="nas"),
    ]
    results = [
        SnmpPollResult(ip="10.0.0.5", ok=False),
        SnmpPollResult(ip="10.0.0.6", ok=True, sys_name="NAS-01"),
    ]

    synced = sync_snmp_assets(session, targets=targets, results=results)

    assert synced == 2
    assets = session.execute(select(AssetInventory)).scalars().all()
    assert len(assets) == 2


def test_sync_snmp_assets_does_not_collide_with_velociraptor_row_same_ip() -> None:
    session = make_session()
    session.add(AssetInventory(monitor_type="velociraptor", hostname="PC-01", ip="10.0.0.5"))
    session.commit()

    targets = [SnmpTarget(ip="10.0.0.5", device_type="printer")]
    results = [SnmpPollResult(ip="10.0.0.5", ok=True, sys_name="MFP-3F")]

    synced = sync_snmp_assets(session, targets=targets, results=results)

    assert synced == 1
    assets = session.execute(select(AssetInventory)).scalars().all()
    assert len(assets) == 2
    velociraptor_asset = next(a for a in assets if a.monitor_type == "velociraptor")
    snmp_asset = next(a for a in assets if a.monitor_type == "snmp")
    assert velociraptor_asset.hostname == "PC-01"
    assert snmp_asset.hostname == "MFP-3F"


def test_load_snmp_targets_parses_json(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config_path = tmp_path / "snmp_targets.json"
    config_path.write_text(
        json.dumps(
            [
                {"ip": "10.0.0.5", "device_type": "printer", "label": "MFP", "port": 1161},
                {"ip": "10.0.0.6", "device_type": "nas"},
            ]
        ),
        encoding="utf-8",
    )

    targets = load_snmp_targets(str(config_path))

    assert targets == [
        SnmpTarget(ip="10.0.0.5", device_type="printer", label="MFP", port=1161),
        SnmpTarget(ip="10.0.0.6", device_type="nas", label=None, port=161),
    ]


def test_poll_all_targets_catches_exception_per_target(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    targets = [
        SnmpTarget(ip="10.0.0.5", device_type="printer"),
        SnmpTarget(ip="10.0.0.6", device_type="nas"),
    ]

    def fake_poll_one(
        target: SnmpTarget, *, community: str, timeout: float, retries: int
    ) -> SnmpPollResult:
        if target.ip == "10.0.0.5":
            raise TimeoutError("no response")
        return SnmpPollResult(ip=target.ip, ok=True, sys_name="NAS-01")

    monkeypatch.setattr("app.jobs.sync_snmp_assets._poll_one", fake_poll_one)

    results = poll_all_targets(targets, community="public", timeout=1.0, retries=0)

    assert len(results) == 2
    assert results[0] == SnmpPollResult(ip="10.0.0.5", ok=False)
    assert results[1].ok is True
    assert results[1].sys_name == "NAS-01"
