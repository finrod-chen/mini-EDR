from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import ADMIN_ROLE, VIEWER_ROLE, User


def _seed_admin_emails() -> set[str]:
    return {e.strip().lower() for e in settings.seed_admin_emails.split(",") if e.strip()}


def get_or_create_user(db: Session, email: str) -> User:
    """email 已存在就直接回傳,否則新增一筆。

    角色規則,依優先序:
    1. email 在 `settings.seed_admin_emails` 名單裡 → 一定是 admin。若這個
       user 已存在但角色不是 admin,登入時會被升級(只升級,不會反過來把
       別人降級)。
    2. users 表目前是空的(還沒有任何人登入過)→ 第一個登入的人自動變
       admin(bootstrap,避免 seed 名單忘了設定時完全沒有 admin 可用)。
    3. 其餘一律預設 viewer。
    """
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    is_seed_admin = email.lower() in _seed_admin_emails()

    if user is not None:
        if is_seed_admin and user.role != ADMIN_ROLE:
            user.role = ADMIN_ROLE
            db.commit()
        return user

    if is_seed_admin:
        role = ADMIN_ROLE
    else:
        is_first_user = db.execute(select(func.count()).select_from(User)).scalar_one() == 0
        role = ADMIN_ROLE if is_first_user else VIEWER_ROLE

    user = User(email=email, role=role, created_at=datetime.now(UTC))
    db.add(user)
    db.commit()
    return user
