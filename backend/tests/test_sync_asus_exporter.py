import json
from unittest.mock import MagicMock

import pytest
from prometheus_client import CollectorRegistry, Gauge, generate_latest
from prometheus_client.samples import Sample
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.jobs.sync_asus_exporter import (
    AsusExporterPollResult,
    AsusExporterTarget,
    _build_metrics,
    _parse_metrics,
    _poll_one,
    load_asus_exporter_targets,
    poll_all_targets,
    sync_asus_exporter_assets,
)
from app.models.asset import AssetInventory
from app.models.base import Base


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def make_metrics_text(
    *,
    uptime: float | None = 12345,
    cpu_percents: list[float] | None = None,
    memory_total: float | None = None,
    memory_used: float | None = None,
    devices: list[tuple[str, str]] | None = None,  # [(mac_address, metric_label)]
    wan_status: str | None = None,
) -> str:
    """組一段格式跟 asus-exporter.py 實際輸出一致的 Prometheus text,用
    prometheus_client 自己的 CollectorRegistry/generate_latest 產生,而不是
    手刻字串,確保跟真正的 exporter 輸出格式(escaping/排序等細節)一致。"""
    registry = CollectorRegistry()
    if uptime is not None:
        Gauge("uptime", "x", registry=registry).set(uptime)
    if cpu_percents:
        for i, value in enumerate(cpu_percents, start=1):
            Gauge(f"cpu{i}_percent", "x", registry=registry).set(value)
    if memory_total is not None:
        Gauge("memory_total", "x", registry=registry).set(memory_total)
    if memory_used is not None:
        Gauge("memory_used", "x", registry=registry).set(memory_used)
    if devices:
        active = Gauge(
            "active_device",
            "x",
            ["ip_address", "device_name", "connection_type", "metric", "mac_address"],
            registry=registry,
        )
        for mac, metric_label in devices:
            active.labels(
                ip_address="192.168.1.1",
                device_name="device",
                connection_type="wireless",
                metric=metric_label,
                mac_address=mac,
            ).set(1)
    if wan_status is not None:
        wan = Gauge(
            "wan_information",
            "x",
            ["wan_status", "wan_type", "wan_ip", "wan_netmask", "wan_gateway", "wan_dns"],
            registry=registry,
        )
        wan.labels(
            wan_status=wan_status,
            wan_type="dhcp",
            wan_ip="1.2.3.4",
            wan_netmask="255.255.255.0",
            wan_gateway="1.2.3.1",
            wan_dns="8.8.8.8",
        ).set(4242)
    return generate_latest(registry).decode("utf-8")


def _mock_response(text: str, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import httpx

        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
    return resp


def test_parse_and_build_metrics_extracts_uptime_cpu_memory_devices_wan() -> None:
    text = make_metrics_text(
        uptime=99999,
        cpu_percents=[10, 20, 30, 40],
        memory_total=1000,
        memory_used=250,
        devices=[("AA:BB", "RSSI"), ("AA:BB", "Current RX speed Mb"), ("CC:DD", "RSSI")],
        wan_status="2",
    )

    families = _parse_metrics(text)
    uptime_seconds, metric_data, alert = _build_metrics(families)

    assert uptime_seconds == 99999
    assert {"label": "CPU 使用率", "value": "25%"} in metric_data
    assert {"label": "記憶體使用率", "value": "25%"} in metric_data
    # 同一個 mac_address 出現在多筆 sample(不同 metric)裡,只算一台裝置。
    assert {"label": "無線連線裝置數", "value": "2"} in metric_data
    assert {"label": "WAN 狀態", "value": "2"} in metric_data
    assert alert is None


def test_build_metrics_flags_high_cpu_and_memory() -> None:
    text = make_metrics_text(
        uptime=1, cpu_percents=[95, 95, 95, 95], memory_total=1000, memory_used=950
    )

    _, _, alert = _build_metrics(_parse_metrics(text))

    assert alert is not None
    assert "CPU 使用率過高" in alert
    assert "記憶體使用率過高" in alert


def test_build_metrics_ignores_nan_cpu_cores_on_routers_with_fewer_than_4_cores() -> None:
    # 少於 4 核心的路由器,exporter 對不存在的核心明確回報 NaN(見
    # deploy/asus-exporter/asus-exporter.py 的說明),不是 0.0——如果誤把
    # NaN 當 0% 算進平均,雙核心路由器的 CPU 使用率會被腰斬。
    families = {
        "uptime": [Sample("uptime", {}, 1.0)],
        "cpu1_percent": [Sample("cpu1_percent", {}, 20.0)],
        "cpu2_percent": [Sample("cpu2_percent", {}, 40.0)],
        "cpu3_percent": [Sample("cpu3_percent", {}, float("nan"))],
        "cpu4_percent": [Sample("cpu4_percent", {}, float("nan"))],
    }

    _, metric_data, _ = _build_metrics(families)

    assert {"label": "CPU 使用率", "value": "30%"} in metric_data


def test_build_metrics_missing_uptime_returns_none() -> None:
    text = make_metrics_text(uptime=None, cpu_percents=[10, 10, 10, 10])

    uptime_seconds, _, _ = _build_metrics(_parse_metrics(text))

    assert uptime_seconds is None


def test_poll_one_success(monkeypatch: pytest.MonkeyPatch) -> None:
    target = AsusExporterTarget(
        exporter_url="http://asus-exporter-1:8000/metrics", ip="10.0.0.1", label="R1"
    )
    text = make_metrics_text(uptime=42, cpu_percents=[10, 10, 10, 10])
    calls = []

    def fake_get(url: str, timeout: float) -> MagicMock:
        calls.append((url, timeout))
        return _mock_response(text)

    monkeypatch.setattr("app.jobs.sync_asus_exporter.httpx.get", fake_get)

    result = _poll_one(target, timeout=5.0)

    assert calls == [(target.exporter_url, 5.0)]
    assert result.ok is True
    assert result.uptime_seconds == 42
    assert result.metric_data is not None


def test_poll_one_connection_error_returns_ok_false(monkeypatch: pytest.MonkeyPatch) -> None:
    target = AsusExporterTarget(
        exporter_url="http://asus-exporter-1:8000/metrics", ip="10.0.0.1", label="R1"
    )

    def fake_get(url: str, timeout: float) -> MagicMock:
        raise ConnectionError("refused")

    monkeypatch.setattr("app.jobs.sync_asus_exporter.httpx.get", fake_get)

    result = _poll_one(target, timeout=5.0)

    assert result == AsusExporterPollResult(ip="10.0.0.1", ok=False)


def test_poll_one_http_error_returns_ok_false(monkeypatch: pytest.MonkeyPatch) -> None:
    target = AsusExporterTarget(
        exporter_url="http://asus-exporter-1:8000/metrics", ip="10.0.0.1", label="R1"
    )

    def fake_get(url: str, timeout: float) -> MagicMock:
        return _mock_response("boom", status_code=500)

    monkeypatch.setattr("app.jobs.sync_asus_exporter.httpx.get", fake_get)

    result = _poll_one(target, timeout=5.0)

    assert result.ok is False


def test_poll_all_targets_one_failure_does_not_block_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = [
        AsusExporterTarget(
            exporter_url="http://asus-exporter-1:8000/metrics", ip="10.0.0.1", label="R1"
        ),
        AsusExporterTarget(
            exporter_url="http://asus-exporter-2:8000/metrics", ip="10.0.0.2", label="R2"
        ),
    ]

    def fake_poll_one(target: AsusExporterTarget, *, timeout: float) -> AsusExporterPollResult:
        if target.ip == "10.0.0.1":
            raise RuntimeError("boom")
        return AsusExporterPollResult(ip=target.ip, ok=True, uptime_seconds=1)

    monkeypatch.setattr("app.jobs.sync_asus_exporter._poll_one", fake_poll_one)

    results = poll_all_targets(targets, timeout=5.0)

    assert len(results) == 2
    assert results[0].ok is False
    assert results[1].ok is True


def test_load_asus_exporter_targets_parses_json(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config_path = tmp_path / "asus_targets.json"
    config_path.write_text(
        json.dumps(
            [
                {
                    "exporter_url": "http://asus-exporter-1:8000/metrics",
                    "ip": "10.0.0.1",
                    "label": "R1",
                },
                {
                    "exporter_url": "http://asus-exporter-2:8000/metrics",
                    "ip": "10.0.0.2",
                    "label": "R2",
                },
            ]
        ),
        encoding="utf-8",
    )

    targets = load_asus_exporter_targets(str(config_path))

    assert targets == [
        AsusExporterTarget(
            exporter_url="http://asus-exporter-1:8000/metrics", ip="10.0.0.1", label="R1"
        ),
        AsusExporterTarget(
            exporter_url="http://asus-exporter-2:8000/metrics", ip="10.0.0.2", label="R2"
        ),
    ]


def test_sync_asus_exporter_assets_inserts_new_router() -> None:
    session = make_session()
    targets = [
        AsusExporterTarget(exporter_url="http://x:8000/metrics", ip="10.0.0.1", label="3F-Router")
    ]
    results = [
        AsusExporterPollResult(
            ip="10.0.0.1",
            ok=True,
            uptime_seconds=100,
            metric_data=[{"label": "CPU 使用率", "value": "10%"}],
        )
    ]

    synced = sync_asus_exporter_assets(session, targets=targets, results=results)

    assert synced == 1
    asset = session.execute(select(AssetInventory)).scalar_one()
    assert asset.monitor_type == "snmp"
    assert asset.device_type == "router"
    assert asset.ip == "10.0.0.1"
    assert asset.hostname == "3F-Router"
    assert asset.snmp_uptime_seconds == 100
    assert asset.snmp_last_poll_ok is True
    assert asset.last_seen is not None


def test_sync_asus_exporter_assets_updates_existing_by_ip() -> None:
    session = make_session()
    session.add(
        AssetInventory(monitor_type="snmp", ip="10.0.0.1", hostname="old", device_type="router")
    )
    session.commit()

    targets = [
        AsusExporterTarget(exporter_url="http://x:8000/metrics", ip="10.0.0.1", label="new-label")
    ]
    results = [AsusExporterPollResult(ip="10.0.0.1", ok=True, uptime_seconds=1)]

    synced = sync_asus_exporter_assets(session, targets=targets, results=results)

    assert synced == 1
    assets = session.execute(select(AssetInventory)).scalars().all()
    assert len(assets) == 1
    assert assets[0].hostname == "new-label"


def test_sync_asus_exporter_assets_failed_poll_does_not_clear_identity() -> None:
    session = make_session()
    session.add(
        AssetInventory(
            monitor_type="snmp",
            ip="10.0.0.1",
            hostname="3F-Router",
            device_type="router",
            snmp_uptime_seconds=999,
            snmp_last_poll_ok=True,
        )
    )
    session.commit()

    targets = [
        AsusExporterTarget(exporter_url="http://x:8000/metrics", ip="10.0.0.1", label="3F-Router")
    ]
    results = [AsusExporterPollResult(ip="10.0.0.1", ok=False)]

    synced = sync_asus_exporter_assets(session, targets=targets, results=results)

    assert synced == 1
    asset = session.execute(select(AssetInventory)).scalar_one()
    assert asset.snmp_last_poll_ok is False
    assert asset.snmp_last_poll_at is not None
    assert asset.hostname == "3F-Router"
    assert asset.snmp_uptime_seconds == 999


def test_sync_asus_exporter_assets_does_not_collide_with_snmp_row_different_ip() -> None:
    session = make_session()
    session.add(
        AssetInventory(
            monitor_type="snmp", ip="10.0.0.5", hostname="Printer", device_type="printer"
        )
    )
    session.commit()

    targets = [
        AsusExporterTarget(exporter_url="http://x:8000/metrics", ip="10.0.0.1", label="Router")
    ]
    results = [AsusExporterPollResult(ip="10.0.0.1", ok=True, uptime_seconds=1)]

    synced = sync_asus_exporter_assets(session, targets=targets, results=results)

    assert synced == 1
    assets = session.execute(select(AssetInventory)).scalars().all()
    assert len(assets) == 2
    printer = next(a for a in assets if a.ip == "10.0.0.5")
    router = next(a for a in assets if a.ip == "10.0.0.1")
    assert printer.device_type == "printer"
    assert router.device_type == "router"
