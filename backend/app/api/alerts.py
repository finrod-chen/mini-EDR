from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.response_actions import ResponseActionOut, to_response_action_out
from app.core.auth import UserSession, get_current_user, require_admin
from app.core.db import get_db
from app.models.alert import Alert
from app.models.response_action import ResponseAction
from app.services import velociraptor_remediation

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: uuid.UUID
    severity: str | None
    rule_name: str | None
    host: str | None
    status: str | None
    ai_explanation: str | None
    created_at: datetime | None


@router.get("", response_model=list[AlertOut])
def list_alerts(
    severity: str | None = None,
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    _user: UserSession = Depends(get_current_user),
) -> list[Alert]:
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    stmt = stmt.order_by(Alert.created_at.desc())
    return list(db.execute(stmt).scalars().all())


ActionType = Literal["quarantine", "kill_process", "ignore", "mark_false_positive"]

# ignore/mark_false_positive 直接改狀態就好,不用呼叫 Velociraptor。
# quarantine/kill_process 才是真的高風險動作(見 require_admin)。
_STATUS_BY_LOCAL_ACTION = {"ignore": "resolved", "mark_false_positive": "false_positive"}


class PerformActionRequest(BaseModel):
    action_type: ActionType
    pid: int | None = None  # 只有 action_type="kill_process" 需要


@router.post("/{alert_id}/actions", response_model=ResponseActionOut)
def perform_action(
    alert_id: uuid.UUID,
    body: PerformActionRequest,
    db: Session = Depends(get_db),
    user: UserSession = Depends(require_admin),
) -> ResponseActionOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")

    if body.action_type in ("quarantine", "kill_process") and not alert.host:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "alert 沒有 host,無法執行")
    if body.action_type == "kill_process" and body.pid is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "kill_process 需要指定 pid")

    new_status: str | None = None
    try:
        if body.action_type == "quarantine":
            assert alert.host is not None
            result = velociraptor_remediation.quarantine_host(alert.host)
            new_status = "acknowledged"
        elif body.action_type == "kill_process":
            assert alert.host is not None
            assert body.pid is not None
            result = velociraptor_remediation.kill_process(alert.host, body.pid)
            new_status = "acknowledged"
        else:
            # ignore / mark_false_positive:不呼叫 Velociraptor,純粹改狀態。
            result = "ok"
            new_status = _STATUS_BY_LOCAL_ACTION[body.action_type]
    except velociraptor_remediation.ClientNotFoundError as exc:
        result = f"failed: {exc}"
    except Exception as exc:  # noqa: BLE001
        # Velociraptor 呼叫失敗要記錄進稽核軌跡(下面的 ResponseAction),
        # 不是直接回 500 讓錯誤消失不見——alert.status 保持不變(new_status
        # 還是 None),讓分析師知道這次操作沒有真的成功、需要重試或人工處理。
        result = f"failed: {exc}"

    action = ResponseAction(
        alert_id=alert.alert_id,
        action_type=body.action_type,
        performed_by=user.email,
        performed_at=datetime.now(UTC),
        result=result,
    )
    db.add(action)
    if new_status:
        alert.status = new_status
    db.commit()
    db.refresh(action)
    return to_response_action_out(action)
