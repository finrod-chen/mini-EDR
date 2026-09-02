from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.jobs.sync_sysmon_events import sync_sysmon_events
from app.models.base import Base
from app.models.events import NetworkEvent, ProcessEvent


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def process_create_row(event_time: str, hostname: str = "PC-01") -> dict:
    return {
        "EventID": 1,
        "EventTime": event_time,
        "Computer": hostname,
        "EventData": {
            "ProcessId": "1234",
            "ParentProcessId": "999",
            "User": "PC-01\\alice",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "Hashes": "SHA256=ABC123",
        },
    }


def network_connect_row(event_time: str, hostname: str = "PC-01") -> dict:
    return {
        "EventID": 3,
        "EventTime": event_time,
        "Computer": hostname,
        "EventData": {
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "SourceIp": "10.0.0.5",
            "DestinationIp": "8.8.8.8",
            "DestinationPort": "443",
        },
    }


def test_sync_sysmon_events_inserts_process_and_network_events() -> None:
    session = make_session()
    rows = [
        process_create_row("2026-01-01T00:00:00Z"),
        network_connect_row("2026-01-01T00:00:01Z"),
        # 不認識的 EventID,應該被略過
        {"EventID": 99, "EventTime": "2026-01-01T00:00:02Z", "Computer": "PC-01"},
    ]

    process_count, network_count = sync_sysmon_events(session, rows=rows)

    assert (process_count, network_count) == (1, 1)

    process_events = session.execute(select(ProcessEvent)).scalars().all()
    assert len(process_events) == 1
    assert process_events[0].pid == 1234
    assert process_events[0].ppid == 999
    assert process_events[0].image == "C:\\Windows\\System32\\cmd.exe"

    network_events = session.execute(select(NetworkEvent)).scalars().all()
    assert len(network_events) == 1
    assert network_events[0].dst_ip == "8.8.8.8"
    assert network_events[0].dst_port == 443


def test_sync_sysmon_events_skips_rows_already_synced_via_high_water_mark() -> None:
    session = make_session()
    session.add(
        ProcessEvent(
            timestamp=datetime(2026, 1, 1, 0, 5, 0, tzinfo=UTC),
            hostname="PC-01",
            pid=1,
        )
    )
    session.commit()

    rows = [process_create_row("2026-01-01T00:00:00Z")]  # 比已存在的資料舊
    process_count, _ = sync_sysmon_events(session, rows=rows)

    assert process_count == 0
    assert len(session.execute(select(ProcessEvent)).scalars().all()) == 1


def test_sync_sysmon_events_skips_rows_without_parseable_time() -> None:
    session = make_session()
    rows = [{"EventID": 1, "EventTime": None, "Computer": "PC-01", "EventData": {}}]

    process_count, network_count = sync_sysmon_events(session, rows=rows)

    assert (process_count, network_count) == (0, 0)
