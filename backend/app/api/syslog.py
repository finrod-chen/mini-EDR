from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.models.syslog_message import SyslogMessage

router = APIRouter(prefix="/api/syslog", tags=["syslog"])

# 前端一次最多拉這麼多筆,避免沒篩選條件時把 syslog_messages 整包撈出來
# ——這張表的量遠比 alerts/response_actions 大(見
# app/services/syslog_listener.py 的說明:每一行原始 log 都存),之後有
# 需要「查更早的資料」再加 cursor 分頁,先用簡單的 limit 夠用。
_MAX_LIMIT = 1000
_DEFAULT_LIMIT = 200


class SyslogMessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    received_at: datetime
    source_ip: str | None
    source_type: str | None
    raw_message: str | None


@router.get("", response_model=list[SyslogMessageOut])
def list_syslog(
    source_type: str | None = None,
    q: str | None = Query(None, description="raw_message 的子字串搜尋"),
    limit: int = _DEFAULT_LIMIT,
    db: Session = Depends(get_db),
    _user: UserSession = Depends(get_current_user),
) -> list[SyslogMessage]:
    stmt = select(SyslogMessage)
    if source_type:
        stmt = stmt.where(SyslogMessage.source_type == source_type)
    if q:
        stmt = stmt.where(SyslogMessage.raw_message.ilike(f"%{q}%"))
    stmt = stmt.order_by(SyslogMessage.received_at.desc()).limit(min(limit, _MAX_LIMIT))
    return list(db.execute(stmt).scalars().all())
