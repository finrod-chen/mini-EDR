"""偵測規則引擎(Phase 3)。

每條規則是一個 (name, severity, fn) 的組合,fn 對 process_events/
network_events/defender_events/asset_inventory 做條件查詢,回傳「觸發規則
的主機清單」,引擎負責 dedup 後寫入 alerts 表。

Dedup 策略:同一 (rule_name, host) 只要還有 status 在 open/acknowledged 的
alert 存在,就不會再開新的一筆。事件型規則(例如某次 PowerShell
-EncodedCommand)與持續性條件規則(例如資產逾期未回報)共用同一套 dedup,
效果等同「同一個問題在分析師結案前不會洗版」——這是常見告警系統的簡化
做法,細分事件型/條件型各自的去重邏輯留給之後有實際洗版問題再優化。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert

logger = logging.getLogger(__name__)

OPEN_STATUSES = ("open", "acknowledged")


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    fn: Callable[[Session], list[str]]  # 回傳目前觸發這條規則的主機清單


def create_alert_if_not_open(
    session: Session, *, rule_name: str, host: str, severity: str
) -> bool:
    """host 對這條規則已經有未結案的 alert 就不重複開,回傳是否真的新開了一筆。"""
    existing = session.execute(
        select(Alert.alert_id).where(
            Alert.rule_name == rule_name,
            Alert.host == host,
            Alert.status.in_(OPEN_STATUSES),
        )
    ).first()
    if existing is not None:
        return False

    session.add(
        Alert(
            severity=severity,
            rule_name=rule_name,
            host=host,
            status="open",
            created_at=datetime.now(UTC),
        )
    )
    return True


def evaluate_rule(session: Session, rule: Rule) -> int:
    hosts = {host for host in rule.fn(session) if host}
    created = 0
    for host in hosts:
        if create_alert_if_not_open(
            session, rule_name=rule.name, host=host, severity=rule.severity
        ):
            created += 1
    return created


def run_all_rules(session: Session, rules: list[Rule] | None = None) -> dict[str, int]:
    if rules is None:
        from app.rules.definitions import ALL_RULES

        rules = ALL_RULES

    results: dict[str, int] = {}
    for rule in rules:
        try:
            results[rule.name] = evaluate_rule(session, rule)
        except Exception:
            logger.exception("rule %s failed", rule.name)
            results[rule.name] = 0
    session.commit()
    return results


if __name__ == "__main__":
    from app.core.db import SessionLocal

    with SessionLocal() as db_session:
        for rule_name, created in run_all_rules(db_session).items():
            print(f"{rule_name}: {created} 筆新 alert")
