from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.user import ADMIN_ROLE, VIEWER_ROLE, User


def get_or_create_user(db: Session, email: str) -> User:
    """email 已存在就直接回傳,否則新增一筆。

    Bootstrap 規則:users 表目前是空的(還沒有任何人登入過)時,第一個
    登入的人自動變 admin,之後新登入的人一律預設 viewer。
    """
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is not None:
        return user

    is_first_user = db.execute(select(func.count()).select_from(User)).scalar_one() == 0
    user = User(
        email=email,
        role=ADMIN_ROLE if is_first_user else VIEWER_ROLE,
        created_at=datetime.now(UTC),
    )
    db.add(user)
    db.commit()
    return user
