import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Alert(Base):
    """對應規格 schema 的 alerts 表(自製規則 + Defender 事件統一寫入同一張表)。"""

    __tablename__ = "alerts"

    alert_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    severity: Mapped[str | None] = mapped_column(Text)  # Critical / High / Medium / Low
    rule_name: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(Text)
    # open / acknowledged / resolved / false_positive
    status: Mapped[str | None] = mapped_column(Text)
    ai_explanation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
