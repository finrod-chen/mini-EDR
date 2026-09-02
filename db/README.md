# db/

實際的 Alembic migration 程式碼放在 `backend/migrations/`(與 SQLAlchemy model 同一個
Python 套件,`alembic.ini` 位於 `backend/alembic.ini`),因為 migration 需要載入
`backend/app` 內的 model 定義與 `app.core.config.settings` 讀連線字串,放在 backend
之外會需要额外處理 sys.path,不划算。

這個目錄用來放與 schema 相關、但不屬於程式碼的文件:

- 資料庫 ERD / schema 說明(對照 `security-platform-spec.md` 的 schema 章節)
- TimescaleDB hypertable 的 retention/分區策略決議(Phase 2 開工前需定案,見規劃文件)
- 資料保留期限對應 ISO 27001 稽核紀錄保存要求的決議紀錄

## 本機執行 migration

```bash
cd backend
uv run alembic upgrade head        # 套用所有 migration
uv run alembic revision -m "xxx"   # 新增一個空白 migration
uv run alembic revision --autogenerate -m "xxx"  # 從 SQLAlchemy model 產生 migration(需先在 app/models/ 定義好 model 並掛上 target_metadata)
```

需要本機先有 PostgreSQL(含 TimescaleDB extension)在跑,見根目錄 `docker-compose.yml`。
