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
from app.services.health_score import calculate_health_score

router = APIRouter(prefix="/api/assets", tags=["assets"])


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
    health_score: int


class SoftwareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    software_name: str | None
    version: str | None
    publisher: str | None
    install_date: datetime | None


def _to_asset_out(asset: AssetInventory) -> AssetOut:
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
        health_score=calculate_health_score(asset),
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
