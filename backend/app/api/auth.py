from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.auth import UserSession, get_current_user, oauth
from app.core.config import settings
from app.core.db import get_db
from app.services.users import get_or_create_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    redirect_uri = str(request.url_for("auth_callback"))
    response = await oauth.google.authorize_redirect(
        request, redirect_uri, hd=settings.google_hosted_domain or None
    )
    return cast(RedirectResponse, response)


@router.get("/callback", name="auth_callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo") or {}
    email = userinfo.get("email")
    if not email or not userinfo.get("email_verified"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Google 帳號沒有已驗證的 email")

    # `hd` 只是 Google 端的 UX 提示(讓帳號選擇畫面預先篩選網域),不是安全
    # 保證,真正的網域限制一定要在伺服器端這裡再檢查一次。
    if settings.google_hosted_domain:
        email_domain = email.rsplit("@", 1)[-1].lower()
        if email_domain != settings.google_hosted_domain.lower():
            raise HTTPException(status.HTTP_403_FORBIDDEN, "不屬於允許登入的網域")

    user = get_or_create_user(db, email)

    request.session["user"] = {"email": user.email, "role": user.role}
    return RedirectResponse(url=settings.frontend_origin)


@router.post("/logout")
def logout(request: Request) -> dict[str, bool]:
    request.session.clear()
    return {"ok": True}


@router.get("/me")
def me(user: UserSession = Depends(get_current_user)) -> UserSession:
    return user
