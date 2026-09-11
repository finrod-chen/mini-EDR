from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.models.asset import AssetInventory, SoftwareInventory
from app.services.health_score import calculate_health_score_breakdown

router = APIRouter(prefix="/api/assets", tags=["assets"])


class HealthScoreDeductionOut(BaseModel):
    reason: str
    points: int


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: uuid.UUID
    hostname: str | None
    ip: str | None
    os_version: str | None
    vendor: str | None
    model: str | None
    cpu: str | None
    memory: str | None
    defender_status: str | None
    defender_last_scan: datetime | None
    defender_signature_date: datetime | None
    last_seen: datetime | None
    monitor_type: str | None
    device_type: str | None
    snmp_sys_descr: str | None
    snmp_uptime_seconds: int | None
    snmp_last_poll_ok: bool | None
    health_score: int
    health_score_breakdown: list[HealthScoreDeductionOut]


class SoftwareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    software_name: str | None
    version: str | None
    publisher: str | None
    install_date: datetime | None


def _to_asset_out(asset: AssetInventory) -> AssetOut:
    breakdown = calculate_health_score_breakdown(asset)
    return AssetOut(
        asset_id=asset.asset_id,
        hostname=asset.hostname,
        ip=asset.ip,
        os_version=asset.os_version,
        vendor=asset.vendor,
        model=asset.model,
        cpu=asset.cpu,
        memory=asset.memory,
        defender_status=asset.defender_status,
        defender_last_scan=asset.defender_last_scan,
        defender_signature_date=asset.defender_signature_date,
        last_seen=asset.last_seen,
        monitor_type=asset.monitor_type,
        device_type=asset.device_type,
        snmp_sys_descr=asset.snmp_sys_descr,
        snmp_uptime_seconds=asset.snmp_uptime_seconds,
        snmp_last_poll_ok=asset.snmp_last_poll_ok,
        health_score=max(100 - sum(d.points for d in breakdown), 0),
        health_score_breakdown=[
            HealthScoreDeductionOut(reason=d.reason, points=d.points) for d in breakdown
        ],
    )


@router.get("", response_model=list[AssetOut])
def list_assets(
    db: Session = Depends(get_db),
    _user: UserSession = Depends(get_current_user),
) -> list[AssetOut]:
    assets = db.execute(select(AssetInventory).order_by(AssetInventory.hostname)).scalars().all()
    return [_to_asset_out(asset) for asset in assets]


@router.get("/{asset_id}/software", response_model=list[SoftwareOut])
def list_asset_software(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    _user: UserSession = Depends(get_current_user),
) -> list[SoftwareInventory]:
    stmt = select(SoftwareInventory).where(SoftwareInventory.asset_id == asset_id)
    return list(db.execute(stmt).scalars().all())
