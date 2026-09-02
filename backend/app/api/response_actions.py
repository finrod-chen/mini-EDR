from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.models.response_action import ResponseAction

router = APIRouter(prefix="/api/response-actions", tags=["response-actions"])


class ResponseActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    action_id: uuid.UUID
    alert_id: uuid.UUID | None
    host: str | None
    action_type: str | None
    performed_by: str | None
    performed_at: datetime | None
    result: str | None


def to_response_action_out(action: ResponseAction) -> ResponseActionOut:
    return ResponseActionOut(
        action_id=action.action_id,
        alert_id=action.alert_id,
        host=action.alert.host if action.alert else None,
        action_type=action.action_type,
        performed_by=action.performed_by,
        performed_at=action.performed_at,
        result=action.result,
    )


@router.get("", response_model=list[ResponseActionOut])
def list_response_actions(
    since: datetime | None = Query(None, description="只回傳這個時間之後的紀錄"),
    until: datetime | None = Query(None, description="只回傳這個時間之前的紀錄"),
    db: Session = Depends(get_db),
    _user: UserSession = Depends(get_current_user),
) -> list[ResponseActionOut]:
    stmt = select(ResponseAction)
    if since:
        stmt = stmt.where(ResponseAction.performed_at >= since)
    if until:
        stmt = stmt.where(ResponseAction.performed_at <= until)
    stmt = stmt.order_by(ResponseAction.performed_at.desc())
    actions = db.execute(stmt).scalars().all()
    return [to_response_action_out(action) for action in actions]
