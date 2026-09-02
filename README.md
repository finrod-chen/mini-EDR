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
| 0 | repo 骨架 + 開發環境 | 進行中 |
| 1 | Velociraptor 部署 + 資產/軟體清單上線 | 未開始 |
| 2 | Sysmon + PostgreSQL pipeline + Defender 事件整合 | 未開始 |
| 3 | 排程 SQL 規則 + alerts 表 | 未開始 |
| 4 | Dashboard | 未開始 |
| 5 | 應變動作串接 Velociraptor API + RBAC | 未開始 |
| 6 | (選配)AI Alert Explain | 未開始 |

## 本機開發

### 前置需求

- Python 3.12+ 與 [uv](https://docs.astral.sh/uv/)
- Node.js 20+
- Docker(本機起 PostgreSQL + TimescaleDB;若本機尚未安裝 Docker,需另外安裝或改用
  現有的 PostgreSQL 16+ 執行個體並自行啟用 `timescaledb` extension)

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

### 啟動 frontend

```bash
cd frontend
npm install
npm run dev
```

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
