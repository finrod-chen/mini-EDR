import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, ForeignKey, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AssetInventory(Base):
    """對應規格 schema 的 asset_inventory 表(資產清單)。"""

    __tablename__ = "asset_inventory"

    asset_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(Text)
    os_version: Mapped[str | None] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    model: Mapped[str | None] = mapped_column(Text)
    cpu: Mapped[str | None] = mapped_column(Text)
    memory: Mapped[str | None] = mapped_column(Text)
    defender_status: Mapped[str | None] = mapped_column(Text)
    defender_last_scan: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    defender_signature_date: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class SoftwareInventory(Base):
    """對應規格 schema 的 software_inventory 表(軟體清單)。

    規格原表沒有定義 primary key,這裡加一個 surrogate id 純粹是 ORM/
    Alembic 操作需要,不影響規格描述的欄位語意。
    """

    __tablename__ = "software_inventory"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("asset_inventory.asset_id"))
    software_name: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    publisher: Mapped[str | None] = mapped_column(Text)
    install_date: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
