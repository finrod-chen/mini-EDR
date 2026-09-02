import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

ADMIN_ROLE = "admin"
VIEWER_ROLE = "viewer"


class User(Base):
    """Dashboard 使用者(Google SSO 登入後 upsert 進來)。

    兩層權限(admin/viewer,見規劃決策):第一個登入、讓資料表從空的變成
    有資料的使用者自動是 admin(bootstrap),之後新登入的人預設 viewer,
    要晉升 admin 目前只能直接改 DB——沒有另外做使用者管理介面,100 人以內
    的內部工具先這樣夠用。
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(Text, unique=True)
    role: Mapped[str] = mapped_column(Text, default=VIEWER_ROLE)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
