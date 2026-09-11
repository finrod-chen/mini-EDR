import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.jobs.sync_snmp_assets import (
    SnmpPollResult,
    SnmpTarget,
    _build_firewall_metrics,
    _build_nas_metrics,
    _build_printer_metrics,
    _decode_snmp_value,
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


def test_sync_snmp_assets_updates_metric_fields_when_present() -> None:
    session = make_session()
    targets = [SnmpTarget(ip="10.0.0.5", device_type="printer")]
    results = [
        SnmpPollResult(
            ip="10.0.0.5",
            ok=True,
            sys_name="MFP-3F",
            metric_data=[{"label": "Black Toner", "value": "8%"}],
            metric_alert="碳粉/耗材偏低(Black Toner 8%)",
        )
    ]

    sync_snmp_assets(session, targets=targets, results=results)

    asset = session.execute(select(AssetInventory)).scalar_one()
    assert asset.snmp_metric_data == [{"label": "Black Toner", "value": "8%"}]
    assert asset.snmp_metric_alert == "碳粉/耗材偏低(Black Toner 8%)"


def test_sync_snmp_assets_keeps_metric_fields_when_not_collected_this_round() -> None:
    """就算 ok=True(MIB-II 成功),這次的 metric_data 也可能是 None(逾時/
    device_type 沒有對應收集器),這時不該清空上次成功抓到的 metrics。"""
    session = make_session()
    session.add(
        AssetInventory(
            monitor_type="snmp",
            ip="10.0.0.5",
            hostname="MFP-3F",
            snmp_metric_data=[{"label": "Black Toner", "value": "60%"}],
            snmp_metric_alert=None,
        )
    )
    session.commit()

    targets = [SnmpTarget(ip="10.0.0.5", device_type="printer")]
    results = [SnmpPollResult(ip="10.0.0.5", ok=True, sys_name="MFP-3F", metric_data=None)]

    sync_snmp_assets(session, targets=targets, results=results)

    asset = session.execute(select(AssetInventory)).scalar_one()
    assert asset.snmp_metric_data == [{"label": "Black Toner", "value": "60%"}]


class _FakeOctetString:
    """模擬 pysnmp OctetString 有 asOctets() 但 str() 對非 ASCII 內容不正確
    的行為,不需要真的連 pysnmp/發封包就能測 _decode_snmp_value。"""

    def __init__(self, raw: bytes, broken_str: str) -> None:
        self._raw = raw
        self._broken_str = broken_str

    def asOctets(self) -> bytes:  # noqa: N802 -- 比照 pysnmp 的命名
        return self._raw

    def __str__(self) -> str:
        return self._broken_str


def test_decode_snmp_value_uses_utf8_not_default_str() -> None:
    # 真實案例:Synology NAS 的 hrStorageDescr 含中文分享資料夾名稱,
    # str() 逐 byte 對應成亂碼,asOctets() + UTF-8 解碼才是正確結果
    # ("員工檔案備份" 的 UTF-8 bytes)。
    raw = "員工檔案備份".encode()
    value = _FakeOctetString(raw, broken_str="garbled")
    assert _decode_snmp_value(value) == "員工檔案備份"


def test_decode_snmp_value_falls_back_without_asoctets() -> None:
    # Integer/TimeTicks/ObjectIdentifier 這類型別沒有 asOctets(),str() 本來
    # 就正確,直接退回。
    assert _decode_snmp_value(42) == "42"


def test_build_printer_metrics_flags_low_supply() -> None:
    descriptions = {"1": "Black Toner", "2": "Drum Unit"}
    levels = {"1": "8", "2": "45"}
    max_capacities = {"1": "100", "2": "100"}

    metric_data, alert = _build_printer_metrics(descriptions, levels, max_capacities)

    assert {"label": "Black Toner", "value": "8%"} in metric_data
    assert {"label": "Drum Unit", "value": "45%"} in metric_data
    assert alert == "碳粉/耗材偏低(Black Toner 8%)"


def test_build_printer_metrics_no_alert_when_all_above_threshold() -> None:
    metric_data, alert = _build_printer_metrics(
        {"1": "Black Toner"}, {"1": "60"}, {"1": "100"}
    )
    assert metric_data == [{"label": "Black Toner", "value": "60%"}]
    assert alert is None


def test_build_printer_metrics_unreadable_level_not_alerted() -> None:
    # RFC 3805 的負數特殊碼語意因裝置而異,一律視為無法判讀,不計入告警。
    metric_data, alert = _build_printer_metrics(
        {"1": "Toner"}, {"1": "-2"}, {"1": "100"}
    )
    assert metric_data == [{"label": "Toner", "value": "無法判讀"}]
    assert alert is None


def test_build_nas_metrics_flags_high_usage_and_excludes_non_fixed_disk() -> None:
    types = {"1": "1.3.6.1.2.1.25.2.1.4", "2": "1.3.6.1.2.1.25.2.1.2"}  # 1=fixed disk, 2=RAM
    descriptions = {"1": "/volume1", "2": "Physical Memory"}
    sizes = {"1": "1000", "2": "500"}
    useds = {"1": "920", "2": "100"}

    metric_data, alert = _build_nas_metrics(types, descriptions, sizes, useds)

    assert metric_data == [{"label": "/volume1", "value": "92% 已使用"}]
    assert alert == "磁碟空間不足(/volume1 92%)"


def test_build_nas_metrics_no_alert_below_threshold() -> None:
    types = {"1": "1.3.6.1.2.1.25.2.1.4"}
    metric_data, alert = _build_nas_metrics(
        types, {"1": "/volume1"}, {"1": "1000"}, {"1": "400"}
    )
    assert metric_data == [{"label": "/volume1", "value": "40% 已使用"}]
    assert alert is None


def test_build_firewall_metrics_flags_admin_up_oper_down_only() -> None:
    descriptions = {"1": "eth0", "2": "eth1", "3": "eth2"}
    admin_statuses = {"1": "1", "2": "1", "3": "2"}  # 1=up, 2=down
    oper_statuses = {"1": "1", "2": "2", "3": "2"}  # eth1: admin-up but down; eth2: admin-down

    metric_data, alert = _build_firewall_metrics(descriptions, admin_statuses, oper_statuses)

    assert {"label": "eth0", "value": "up"} in metric_data
    assert {"label": "eth1", "value": "down"} in metric_data
    assert {"label": "eth2", "value": "down"} in metric_data
    # eth2 admin 本來就是 down,不該被誤報成異常。
    assert alert == "介面異常(eth1)"


def test_build_firewall_metrics_multiple_down_interfaces_joined() -> None:
    descriptions = {"1": "eth1", "2": "eth2"}
    admin_statuses = {"1": "1", "2": "1"}
    oper_statuses = {"1": "2", "2": "2"}

    _, alert = _build_firewall_metrics(descriptions, admin_statuses, oper_statuses)

    assert alert == "介面異常(eth1、eth2)"
