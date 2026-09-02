from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.asset import AssetInventory
from app.models.base import Base
from app.models.events import DefenderEvent, ProcessEvent
from app.rules import definitions as rules
from app.rules.engine import Rule, create_alert_if_not_open, run_all_rules

NOW = datetime.now(UTC)


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_rule_defender_protection_disabled_matches_recent_5001() -> None:
    session = make_session()
    session.add(
        DefenderEvent(
            hostname="PC-01", event_type="protection_disabled", timestamp=NOW - timedelta(minutes=1)
        )
    )
    session.commit()

    assert rules.rule_defender_protection_disabled(session) == ["PC-01"]


def test_rule_defender_detect_without_action_flags_unremediated_threat() -> None:
    session = make_session()
    session.add_all(
        [
            DefenderEvent(
                hostname="PC-01",
                event_type="detect",
                threat_name="Trojan:Win32/Foo",
                timestamp=NOW - timedelta(minutes=5),
            ),
            DefenderEvent(
                hostname="PC-02",
                event_type="detect",
                threat_name="Trojan:Win32/Bar",
                timestamp=NOW - timedelta(minutes=5),
            ),
            DefenderEvent(
                hostname="PC-02",
                event_type="action_taken",
                threat_name="Trojan:Win32/Bar",
                timestamp=NOW - timedelta(minutes=4),
            ),
        ]
    )
    session.commit()

    assert rules.rule_defender_detect_without_action(session) == ["PC-01"]


def test_rule_office_spawns_shell_matches_recent_parent_child_pair() -> None:
    session = make_session()
    session.add_all(
        [
            ProcessEvent(
                timestamp=NOW - timedelta(minutes=2),
                hostname="PC-01",
                pid=100,
                image="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            ),
            ProcessEvent(
                timestamp=NOW - timedelta(minutes=1),
                hostname="PC-01",
                ppid=100,
                pid=200,
                image="C:\\Windows\\System32\\powershell.exe",
            ),
        ]
    )
    session.commit()

    assert rules.rule_office_spawns_shell(session) == ["PC-01"]


def test_rule_office_spawns_shell_ignores_unrelated_child() -> None:
    session = make_session()
    session.add_all(
        [
            ProcessEvent(
                timestamp=NOW - timedelta(minutes=2),
                hostname="PC-01",
                pid=100,
                image="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            ),
            ProcessEvent(
                timestamp=NOW - timedelta(minutes=1),
                hostname="PC-01",
                ppid=999,  # 不是 WINWORD 的 pid
                pid=200,
                image="C:\\Windows\\System32\\powershell.exe",
            ),
        ]
    )
    session.commit()

    assert rules.rule_office_spawns_shell(session) == []


def test_rule_discovery_command_burst_requires_threshold() -> None:
    session = make_session()
    for i, image in enumerate(["whoami.exe", "net.exe"]):
        session.add(
            ProcessEvent(
                timestamp=NOW - timedelta(minutes=i),
                hostname="PC-01",
                image=f"C:\\Windows\\System32\\{image}",
            )
        )
    session.commit()
    assert rules.rule_discovery_command_burst(session) == []  # 只有 2 次,門檻是 3

    session.add(
        ProcessEvent(
            timestamp=NOW,
            hostname="PC-01",
            image="C:\\Windows\\System32\\nltest.exe",
        )
    )
    session.commit()
    assert rules.rule_discovery_command_burst(session) == ["PC-01"]


def test_rule_asset_stale_only_matches_hosts_with_old_last_seen() -> None:
    session = make_session()
    session.add_all(
        [
            AssetInventory(hostname="STALE", last_seen=NOW - timedelta(days=10)),
            AssetInventory(hostname="FRESH", last_seen=NOW - timedelta(days=1)),
            AssetInventory(hostname="NEVER_SYNCED", last_seen=None),
        ]
    )
    session.commit()

    assert rules.rule_asset_stale(session) == ["STALE"]


def test_create_alert_if_not_open_dedupes_same_rule_and_host() -> None:
    session = make_session()

    created_first = create_alert_if_not_open(
        session, rule_name="test-rule", host="PC-01", severity="High"
    )
    session.commit()
    created_second = create_alert_if_not_open(
        session, rule_name="test-rule", host="PC-01", severity="High"
    )
    session.commit()

    assert created_first is True
    assert created_second is False
    assert len(session.execute(select(Alert)).scalars().all()) == 1


def test_create_alert_if_not_open_allows_new_alert_after_resolved() -> None:
    session = make_session()
    create_alert_if_not_open(session, rule_name="test-rule", host="PC-01", severity="High")
    session.commit()

    alert = session.execute(select(Alert)).scalar_one()
    alert.status = "resolved"
    session.commit()

    created_again = create_alert_if_not_open(
        session, rule_name="test-rule", host="PC-01", severity="High"
    )
    session.commit()

    assert created_again is True
    assert len(session.execute(select(Alert)).scalars().all()) == 2


def test_run_all_rules_aggregates_counts_and_survives_a_failing_rule() -> None:
    session = make_session()
    session.add(
        DefenderEvent(
            hostname="PC-01", event_type="protection_disabled", timestamp=NOW - timedelta(minutes=1)
        )
    )
    session.commit()

    def _broken_rule(_session: Session) -> list[str]:
        raise RuntimeError("boom")

    test_rules = [
        Rule("Defender 即時防護被關閉", "Critical", rules.rule_defender_protection_disabled),
        Rule("broken", "Low", _broken_rule),
    ]

    results = run_all_rules(session, rules=test_rules)

    assert results["Defender 即時防護被關閉"] == 1
    assert results["broken"] == 0
    assert len(session.execute(select(Alert)).scalars().all()) == 1
