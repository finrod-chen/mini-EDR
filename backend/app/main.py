from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.api.alerts import router as alerts_router
from app.api.assets import router as assets_router
from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.response_actions import router as response_actions_router
from app.core.config import settings
from app.jobs import scheduler


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

# session cookie 用來存 Google SSO 登入後的 {email, role}(見 app/core/auth.py),
# 不是 DB-backed session。
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key)

# 本機開發時 frontend(Vite,localhost:5173)與 backend 不同 port,session
# cookie 要跨網域帶,需要開 CORS 並允許 credentials。正式環境若前後端同網域
# 走反向代理,這段可以移除。
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(response_actions_router)
app.include_router(assets_router)
