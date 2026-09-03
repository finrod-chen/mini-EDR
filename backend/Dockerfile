# 官方 uv Docker 映像提供 uv 執行檔本身,不含 Python,base stage 另外用
# python:3.12-slim 提供執行環境。見 https://docs.astral.sh/uv/guides/integration/docker/
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:${PATH}"

# 先只複製 lockfile 裝依賴,依賴沒變的話這層可以吃 build cache,程式碼改動
# 不會讓依賴重裝一次。
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --no-dev

EXPOSE 8000

# scheduler(app/jobs/scheduler.py)在 FastAPI 的 lifespan 裡啟動,跟著這個
# process 一起跑,不用另外開一個 worker container。
#
# --proxy-headers / --forwarded-allow-ips=*:部署在 Cloudflare Tunnel 後面時,
# cloudflared 在 NAS 本機是走明文 HTTP 轉發進來,靠 X-Forwarded-Proto 這個
# header 告訴 uvicorn 原始請求其實是 https。沒有這兩個參數的話
# request.url_for()(見 app/api/auth.py 的 Google OAuth redirect_uri)會組出
# http:// 開頭的網址,跟 Google Console 註冊的 https:// redirect URI 對不上,
# 導致登入直接失敗。forwarded-allow-ips 設 * 是因為 cloudflared 在 docker
# network 內的來源 IP 不是固定的,無法列白名單。
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
