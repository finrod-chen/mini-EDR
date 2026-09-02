"""Google SSO 登入(見規劃決策:兩層權限 admin/viewer,Google SSO 認證)。

流程:
1. GET /auth/login          -> 導去 Google 帳號選擇/登入頁
2. GET /auth/callback       -> Google 導回來,換 token,驗證 email 網域,
                               upsert users 表,把 {email, role} 寫進
                               Starlette session(簽章 cookie,不是 DB session)
3. 之後每個 request 靠 get_current_user() 讀 session,不用重新打 Google API
"""

from __future__ import annotations

from dataclasses import dataclass

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, HTTPException, Request, status

from app.core.config import settings

oauth = OAuth()
oauth.register(
    name="google",
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


@dataclass(frozen=True)
class UserSession:
    email: str
    role: str


def get_current_user(request: Request) -> UserSession:
    session_user = request.session.get("user")
    if session_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not logged in")
    return UserSession(email=session_user["email"], role=session_user["role"])


def require_admin(user: UserSession = Depends(get_current_user)) -> UserSession:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    return user
