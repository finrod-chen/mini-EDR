from datetime import UTC, datetime, timedelta

from app.services.firewall_scan_detector import (
    THREAT_KIND_HIGH_SEVERITY,
    THREAT_KIND_SCAN,
    ScanDetector,
)

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


def test_port_scan_reason_includes_destination() -> None:
    detector = make_detector(port_scan_threshold=3)
    result = None
    for port in range(1, 4):
        result = detector.record_traffic(
            src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=port, now=_BASE
        )
    assert result is not None
    reason, _ = result
    assert "10.0.0.1" in reason


def test_port_scan_does_not_trigger_across_different_destinations() -> None:
    # 實機上線後的真實誤判:一台工作站在一分鐘內正常存取好幾個不同的
    # 內部服務(各自不同主機、各自不同 port),不該被當成對單一目標的
    # 連接埠掃描——真正的 port scan 定義是同一個目的地被打很多不同 port。
    detector = make_detector(port_scan_threshold=5, host_sweep_threshold=1000)
    result = None
    for i in range(10):
        result = detector.record_traffic(
            src_ip="192.168.2.50", dst_ip=f"192.168.2.{100 + i}", dst_port=1000 + i, now=_BASE
        )
    assert result is None


def test_port_scan_still_triggers_when_mixed_with_other_destinations() -> None:
    detector = make_detector(port_scan_threshold=5, host_sweep_threshold=1000)
    # 先存取幾個不同的內部服務(各自不同主機、各自不同 port),不該累積。
    for i in range(10):
        detector.record_traffic(
            src_ip="192.168.2.50", dst_ip=f"192.168.2.{100 + i}", dst_port=1000 + i, now=_BASE
        )
    # 再對同一個目標打很多不同 port,應該正常觸發。
    result = None
    for port in range(1, 6):
        result = detector.record_traffic(
            src_ip="192.168.2.50", dst_ip="192.168.2.200", dst_port=port, now=_BASE
        )
    assert result is not None
    reason, kind = result
    assert kind == "port_scan"
    assert "192.168.2.200" in reason


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
    assert "5 台不同內網主機" in reason


def test_host_sweep_ignores_external_destinations() -> None:
    # 實機上線後的真實誤判:一般上網瀏覽在 60 秒內連到十幾個不同的外部 IP
    # 很正常(CDN/廣告/雲端服務各自不同 IP),不該被當成內網橫向掃描。
    detector = make_detector(host_sweep_threshold=5, port_scan_threshold=1000)
    result = None
    for i in range(10):
        result = detector.record_traffic(
            src_ip="192.168.2.50", dst_ip=f"93.184.216.{i}", dst_port=443, now=_BASE
        )
    assert result is None


def test_host_sweep_still_triggers_on_private_destinations_mixed_with_external() -> None:
    detector = make_detector(host_sweep_threshold=5, port_scan_threshold=1000)
    # 先來一堆外部流量(不該累積計數)。
    for i in range(10):
        detector.record_traffic(
            src_ip="192.168.2.50", dst_ip=f"93.184.216.{i}", dst_port=443, now=_BASE
        )
    # 再來真的內網掃描,應該正常觸發,不受前面外部流量影響。
    result = None
    for i in range(5):
        result = detector.record_traffic(
            src_ip="192.168.2.50", dst_ip=f"192.168.2.{i}", dst_port=445, now=_BASE
        )
    assert result is not None
    reason, kind = result
    assert kind == "host_sweep"
    assert "5 台不同內網主機" in reason


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
    reason, severity, kind = result
    assert "掃描" in reason
    assert severity == "High"
    assert kind == THREAT_KIND_SCAN


def test_threat_non_scan_low_severity_does_not_trigger() -> None:
    detector = make_detector()
    result = detector.record_threat(
        src_ip="1.2.3.4", subtype="virus", category="malware", threatid="1", severity="medium"
    )
    assert result is None


def test_threat_non_scan_high_severity_triggers_as_high_severity_threat() -> None:
    # 補的缺口:非掃描類、但 PAN-OS 自己判定 high/critical 的 Threat log
    # (真正的惡意程式/漏洞攻擊命中)也要變成 alert,不能因為不是
    # subtype=="scan" 就整個被丟掉。
    detector = make_detector()
    result = detector.record_threat(
        src_ip="1.2.3.4", subtype="virus", category="malware", threatid="1", severity="critical"
    )
    assert result is not None
    reason, severity, kind = result
    assert "高風險" in reason
    assert severity == "Critical"
    assert kind == THREAT_KIND_HIGH_SEVERITY


def test_threat_scan_subtype_takes_priority_over_severity_kind() -> None:
    # subtype=="scan" 且嚴重度也達 high/critical 時,要回報 scan 這個
    # 更明確的分類,不是 high_severity。
    detector = make_detector()
    result = detector.record_threat(
        src_ip="1.2.3.4", subtype="scan", category="recon", threatid="1", severity="critical"
    )
    assert result is not None
    _, _, kind = result
    assert kind == THREAT_KIND_SCAN


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
        _, severity, _ = result
        assert severity == expected


def test_stale_state_is_evicted() -> None:
    detector = make_detector(state_ttl_seconds=100)
    detector.record_traffic(src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, now=_BASE)
    assert "1.2.3.4" in detector._state

    # 超過 TTL + eviction 檢查間隔後再打一次(隨便一個來源皆可觸發清理)。
    later = _BASE + timedelta(seconds=200)
    detector.record_traffic(src_ip="9.9.9.9", dst_ip="10.0.0.1", dst_port=80, now=later)
    assert "1.2.3.4" not in detector._state
