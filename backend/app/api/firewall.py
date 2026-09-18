"""防火牆封鎖清單:查詢/解除 mini-edr 透過 PAN-OS User-ID API 打上
`panos_block_tag` 的 registered-ip(見 app/services/pan_os_remediation.py)。
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import UserSession, get_current_user, require_admin
from app.core.config import settings
from app.core.db import get_db
from app.models.response_action import ResponseAction
from app.services import pan_os_remediation

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


class BlockedIpOut(BaseModel):
    ip: str
    tag: str
    timeout_seconds: int | None


class UnblockIpRequest(BaseModel):
    ip: str


@router.get("/blocked-ips", response_model=list[BlockedIpOut])
def list_blocked_ips(_user: UserSession = Depends(get_current_user)) -> list[BlockedIpOut]:
    try:
        entries = pan_os_remediation.list_blocked_ips(settings.panos_block_tag)
    except pan_os_remediation.PanOsApiError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    return [BlockedIpOut(**entry) for entry in entries]


@router.post("/blocked-ips/unblock")
def unblock_ip(
    body: UnblockIpRequest,
    db: Session = Depends(get_db),
    user: UserSession = Depends(require_admin),
) -> dict[str, str]:
    # 跟 alerts.py 的 block_firewall_ip 同一套稽核邏輯:不管成功失敗都寫一筆
    # ResponseAction 當稽核紀錄(alert_id=None,這個動作不是從某筆告警觸發
    # 的,沒有對應的 alert 可以掛),失敗才回 502 讓前端知道要重試。
    try:
        result = pan_os_remediation.unblock_ip(body.ip, settings.panos_block_tag)
    except pan_os_remediation.PanOsApiError as exc:
        result = f"failed: {exc}"

    action = ResponseAction(
        alert_id=None,
        action_type="unblock_firewall_ip",
        performed_by=user.email,
        performed_at=datetime.now(UTC),
        result=f"{body.ip}: {result}",
    )
    db.add(action)
    db.commit()

    if result.startswith("failed:"):
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, result)
    return {"result": result}
