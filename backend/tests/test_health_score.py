from datetime import UTC, datetime, timedelta

from app.models.asset import AssetInventory
from app.services.health_score import HealthScoreDeduction, calculate_health_score_breakdown

_STALE = datetime.now(UTC) - timedelta(days=31)


def test_snmp_asset_offline_deduction() -> None:
    asset = AssetInventory(monitor_type="snmp", snmp_last_poll_ok=False)

    breakdown = calculate_health_score_breakdown(asset)

    reasons = {d.reason: d.points for d in breakdown}
    assert any("SNMP 輪詢失敗" in reason for reason in reasons)
    assert next(points for reason, points in reasons.items() if "SNMP 輪詢失敗" in reason) == 30


def test_snmp_asset_ignores_velociraptor_rules() -> None:
    # os_version/defender_status 剛好帶著 Velociraptor 規則會命中的值,
    # 但因為 monitor_type='snmp',分派邏輯不該套用那組規則。
    asset = AssetInventory(
        monitor_type="snmp",
        os_version="Windows 7",
        defender_status="disabled",
        snmp_last_poll_ok=True,
    )

    breakdown = calculate_health_score_breakdown(asset)

    reasons = [d.reason for d in breakdown]
    assert not any("作業系統過舊" in r for r in reasons)
    assert not any("Defender" in r for r in reasons)
    assert breakdown == []


def test_snmp_asset_stale_last_seen_still_applies() -> None:
    asset = AssetInventory(monitor_type="snmp", snmp_last_poll_ok=True, last_seen=_STALE)

    breakdown = calculate_health_score_breakdown(asset)

    assert any("未回報" in d.reason and d.points == 10 for d in breakdown)


def test_velociraptor_asset_unaffected_by_snmp_branch() -> None:
    asset = AssetInventory(
        monitor_type="velociraptor",
        os_version="Windows 7",
        defender_status="disabled",
        last_seen=_STALE,
    )

    breakdown = calculate_health_score_breakdown(asset)

    reasons = {d.reason: d.points for d in breakdown}
    assert sum(reasons.values()) == 50  # 20(舊OS) + 20(Defender關閉) + 10(太久沒回報)
    assert not any("SNMP" in r for r in reasons)


def test_null_monitor_type_treated_as_velociraptor() -> None:
    asset = AssetInventory(monitor_type=None, os_version="Windows 7")

    breakdown = calculate_health_score_breakdown(asset)

    assert any("作業系統過舊" in d.reason for d in breakdown)


def test_snmp_asset_metric_alert_deduction() -> None:
    asset = AssetInventory(
        monitor_type="snmp",
        snmp_last_poll_ok=True,
        snmp_metric_alert="碳粉/耗材偏低(Black Toner 8%)",
    )

    breakdown = calculate_health_score_breakdown(asset)

    assert breakdown == [HealthScoreDeduction("碳粉/耗材偏低(Black Toner 8%)", 15)]


def test_snmp_asset_offline_and_metric_alert_both_apply() -> None:
    # 裝置這次離線,但 snmp_metric_alert 可能還留著上次成功輪詢偵測到的
    # 異常(sync_snmp_assets.py 的設計:輪詢失敗不清空 metric 舊值)——
    # 兩個扣分項目該同時出現,不是互斥的。
    asset = AssetInventory(
        monitor_type="snmp",
        snmp_last_poll_ok=False,
        snmp_metric_alert="介面異常(eth1)",
    )

    breakdown = calculate_health_score_breakdown(asset)

    total = sum(d.points for d in breakdown)
    assert total == 45  # 30(離線) + 15(指標異常)
