from datetime import UTC, datetime, timedelta

from app.services.firewall_scan_detector import ScanDetector

_BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_detector(
    *,
    port_scan_threshold: int = 5,
    port_scan_window_seconds: int = 60,
    host_sweep_threshold: int = 5,
    host_sweep_window_seconds: int = 60,
    state_ttl_seconds: int = 300,
) -> ScanDetector:
    return ScanDetector(
        port_scan_threshold=port_scan_threshold,
        port_scan_window=timedelta(seconds=port_scan_window_seconds),
        host_sweep_threshold=host_sweep_threshold,
        host_sweep_window=timedelta(seconds=host_sweep_window_seconds),
        state_ttl=timedelta(seconds=state_ttl_seconds),
    )


def test_port_scan_triggers_at_threshold() -> None:
    detector = make_detector(port_scan_threshold=5)
    result = None
    for port in range(1, 5):
        result = detector.record_traffic(
            src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=port, now=_BASE
        )
        assert result is None  # 還沒到門檻

    result = detector.record_traffic(src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=5, now=_BASE)
    assert result is not None
    reason, kind = result
    assert kind == "port_scan"
    assert "5 個不同連接埠" in reason


def test_port_scan_window_expiry_resets_count() -> None:
    detector = make_detector(port_scan_threshold=5, port_scan_window_seconds=60)
    for port in range(1, 5):
        detector.record_traffic(src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=port, now=_BASE)

    # 超過視窗時間後,舊的活動不該再被算進去。
    later = _BASE + timedelta(seconds=61)
    result = detector.record_traffic(src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=5, now=later)
    assert result is None


def test_host_sweep_triggers_at_threshold() -> None:
    detector = make_detector(host_sweep_threshold=5, port_scan_threshold=1000)
    result = None
    for i in range(5):
        result = detector.record_traffic(
            src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=80, now=_BASE
        )

    assert result is not None
    reason, kind = result
    assert kind == "host_sweep"
    assert "5 台不同主機" in reason


def test_port_scan_and_host_sweep_are_independent_per_source() -> None:
    detector = make_detector(port_scan_threshold=5, host_sweep_threshold=5)
    # 來源 A 掃很多 port(同一個目的地),不該誤觸發來源 B 的狀態。
    for port in range(1, 5):
        detector.record_traffic(src_ip="1.1.1.1", dst_ip="10.0.0.1", dst_port=port, now=_BASE)
    result_b = detector.record_traffic(src_ip="2.2.2.2", dst_ip="10.0.0.1", dst_port=80, now=_BASE)
    assert result_b is None


def test_threat_scan_subtype_triggers_immediately() -> None:
    detector = make_detector()
    result = detector.record_threat(
        src_ip="1.2.3.4", subtype="scan", category="recon", threatid="40001", severity="high"
    )
    assert result is not None
    reason, severity = result
    assert "掃描" in reason
    assert severity == "High"


def test_threat_non_scan_subtype_does_not_trigger() -> None:
    detector = make_detector()
    result = detector.record_threat(
        src_ip="1.2.3.4", subtype="virus", category="malware", threatid="1", severity="high"
    )
    assert result is None


def test_threat_severity_mapping() -> None:
    detector = make_detector()
    for panos_severity, expected in [
        ("informational", "Low"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
        ("unexpected-value", "High"),
    ]:
        result = detector.record_threat(
            src_ip="1.2.3.4", subtype="scan", category="c", threatid="t", severity=panos_severity
        )
        assert result is not None
        _, severity = result
        assert severity == expected


def test_stale_state_is_evicted() -> None:
    detector = make_detector(state_ttl_seconds=100)
    detector.record_traffic(src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, now=_BASE)
    assert "1.2.3.4" in detector._state

    # 超過 TTL + eviction 檢查間隔後再打一次(隨便一個來源皆可觸發清理)。
    later = _BASE + timedelta(seconds=200)
    detector.record_traffic(src_ip="9.9.9.9", dst_ip="10.0.0.1", dst_port=80, now=later)
    assert "1.2.3.4" not in detector._state
