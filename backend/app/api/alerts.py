from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.models.alert import Alert

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
