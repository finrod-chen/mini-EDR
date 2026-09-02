import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, ForeignKey, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.alert import Alert
from app.models.base import Base


class ResponseAction(Base):
    """對應規格 schema 的 response_actions 表(應變動作稽核軌跡)。

    Phase 4 先建表、給 Dashboard 應變紀錄頁讀(目前會是空的);真正呼叫
    Velociraptor API 執行隔離/砍進程、寫入這張表的邏輯是 Phase 5 的工作。
    """

    __tablename__ = "response_actions"

    action_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("alerts.alert_id"))
    # quarantine / kill_process / ignore / mark_false_positive
    action_type: Mapped[str | None] = mapped_column(Text)
    performed_by: Mapped[str | None] = mapped_column(Text)
    performed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    result: Mapped[str | None] = mapped_column(Text)

    # 應變紀錄頁要顯示「目標主機」,response_actions 本身沒有 host 欄位,
    # 從關聯的 alert 帶出來(見 app/api/response_actions.py)。
    alert: Mapped[Alert | None] = relationship(lazy="joined")
