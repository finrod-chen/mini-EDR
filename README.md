# mini-edr

內部資產管理 + EDR-like 平台。技術規格見 `security-platform-spec.md`(規格原始檔案位置:
使用者 Downloads 目錄),本 repo 依規格分 Phase 落地實作,執行順序規劃見
`.claude/plans/`(或對話中已核准的規劃文件)。

## 專案結構

```
backend/    Python + FastAPI:規則引擎、REST API、應變動作服務
frontend/   React + Vite:Dashboard(告警佇列/應變紀錄/資產管理)
db/         Schema 文件、retention/分區策略決議(migration 程式碼實際放 backend/migrations)
deploy/     Velociraptor server/client config 範本、GPO 推送流程文件
```

## Phase 對應

| Phase | 內容 | 狀態 |
|---|---|---|
| 0 | repo 骨架 + 開發環境 | 完成 |
| 1 | Velociraptor 部署 + 資產/軟體清單上線 | 進行中(部署文件/DB schema/同步 job 骨架已完成,待實機驗證) |
| 2 | Sysmon + PostgreSQL pipeline + Defender 事件整合 | 進行中(Sysmon 部署文件、hypertable schema、事件同步 job 骨架已完成,待實機驗證) |
| 3 | 排程 SQL 規則 + alerts 表 | 進行中(alerts 表、規則引擎、18 條規則、排程已完成,待實機資料驗證誤報率) |
| 4 | Dashboard | 進行中(Google SSO 登入、兩層 RBAC、三個頁面、唯讀 API 已完成,應變動作按鈕已於 Phase 5 接上真實 API,待實機驗證) |
| 5 | 應變動作串接 Velociraptor API + RBAC | 進行中(隔離主機/砍進程/標記誤判/忽略四個動作 API + Dashboard 按鈕已完成,待實機驗證,砍進程需先在 Velociraptor 匯入 exchange artifact 見 deploy/velociraptor/README.md 第 8 節) |
| 6 | (選配)AI Alert Explain | 進行中(OpenAI-compatible LLM API + 基本遮罩 + Dashboard 按鈕已完成,待接真實 LLM 端點驗證) |

## 本機開發

### 前置需求

- Python 3.12+ 與 [uv](https://docs.astral.sh/uv/)
- Node.js 20+
- Docker(本機起 PostgreSQL + TimescaleDB + Velociraptor Server;若本機尚未安裝
  Docker,需另外安裝或改用現有的 PostgreSQL 16+ 執行個體並自行啟用
  `timescaledb` extension)。實際部署位置是 Synology NAS(Container Manager),
  見 `deploy/velociraptor/README.md`

### 啟動資料庫

```bash
cp .env.example .env
docker compose up -d
```

### 啟動 backend

```bash
cd backend
uv sync
uv run uvicorn app.main:app --reload
# health check: http://localhost:8000/health
```

### 套用 DB migration / 手動跑一次同步 job

```bash
cd backend
uv run alembic upgrade head
# 以下都需要 deploy/velociraptor/etc/api_client.yaml 存在(見 deploy/velociraptor/README.md 第 6 節)
uv run python -m app.jobs.sync_assets            # 資產清單(hostname/last_seen)
uv run python -m app.jobs.sync_sysmon_events      # process_events / network_events
uv run python -m app.jobs.sync_defender_events    # defender_events
uv run python -m app.jobs.retention               # 清除超過 6 個月的 defender_events
uv run python -m app.rules.engine                  # 跑一次全部 18 條規則,印出各規則新開了幾筆 alert
```

正常執行時這幾個 job 由 `app/jobs/scheduler.py` 排程(每 5 分鐘同步一次,
retention 清除每 24 小時一次),在 FastAPI 啟動時(`app/main.py` 的
lifespan)自動開始跑,不用手動呼叫。

### 啟動 frontend

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
# http://localhost:5173
```

### Dashboard 登入(Google SSO)

需要先在 <https://console.cloud.google.com/apis/credentials> 建立 OAuth 2.0
用戶端(Web application),Authorized redirect URI 填
`http://localhost:8000/auth/callback`,把 client id/secret 填進
backend 的 `.env`(見 `.env.example` 的 `GOOGLE_CLIENT_ID` /
`GOOGLE_CLIENT_SECRET` 說明)。

登入限制只開放 `xiyuebiomed.com.tw` 網域(`GOOGLE_HOSTED_DOMAIN`,已是
預設值),`finrodchen@xiyuebiomed.com.tw` 一律是 admin
(`SEED_ADMIN_EMAILS`,即使不是第一個登入的人;已存在但角色不是 admin
會在下次登入時自動升級)。除了 seed 名單外,其餘第一個登入的帳號當
bootstrap admin,之後的人預設 viewer,要晉升 admin 目前只能直接改 DB
(`users` 表)。細節見 `app/services/users.py`。

### AI Alert Explain(選配)

在 backend 的 `.env` 填 `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL`(見
`.env.example`)。走 OpenAI-compatible 的 `/chat/completions` 介面,不綁定
特定供應商。三個值留空就是停用,Dashboard 按「產生 AI 說明」會回
503。送出去的告警上下文會先做基本遮罩(hostname/user 只送前 4 個字元,
`command_line` 保留完整內容),細節見 `app/services/ai_explain.py`。

### 測試 / lint

```bash
cd backend
uv run pytest
uv run ruff check .
uv run mypy app

cd frontend
npm run lint
npx tsc -b
```

## 測試部署(整套服務用 docker compose)

`docker-compose.yml` 現在有完整四個服務(`db` / `velociraptor-server` /
`backend` / `frontend`),本機開發還是建議用 `uv run` / `npm run dev`(改
程式碼不用重新 build image,反應快),但要驗證整套服務串起來能不能動,或
要部署到 Synology NAS,照 **`deploy/README.md`** 的步驟走。

## Docker image

CI(`.github/workflows/ci.yml` 的 `docker` job)在 backend/frontend 測試都過
之後自動建置 `backend/Dockerfile`、`frontend/Dockerfile` 這兩個 image;
push 到 `master` 才會真的推上
`ghcr.io/finrod-chen/mini-edr-backend` / `mini-edr-frontend`(private),
PR 只驗證建得起來,不會 push。frontend image 是 build time 把
`VITE_API_BASE_URL` 燒進靜態檔案(Vite 的限制,不是 runtime 讀環境變數),
CI 目前用預設值建置,不能直接拿去部署——部署到 NAS 的正確流程(用
docker-compose 從 `.env` 的 `BACKEND_PUBLIC_URL` 帶入正確值重新 build)見
`deploy/README.md`。

單獨手動 build 單一 image(不透過 docker-compose)也可以:

```bash
docker build -t mini-edr-backend ./backend
docker build --build-arg VITE_API_BASE_URL=https://實際網址 -t mini-edr-frontend ./frontend
```
