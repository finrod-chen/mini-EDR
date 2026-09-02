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
| 4 | Dashboard | 進行中(Google SSO 登入、兩層 RBAC、三個頁面、唯讀 API 已完成,應變動作按鈕先 UI-only,待實機驗證) |
| 5 | 應變動作串接 Velociraptor API + RBAC | 未開始 |
| 6 | (選配)AI Alert Explain | 未開始 |

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
`GOOGLE_CLIENT_SECRET` 說明)。第一個登入的帳號自動變 admin(見
`app/services/users.py`),之後的人預設 viewer,要晉升 admin 目前只能
直接改 DB(`users` 表)。

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
