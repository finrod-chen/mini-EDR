# 測試部署(整套服務用 docker compose 跑在 Synology NAS)

這份文件是「從零開始把整套服務跑起來」的操作順序,細節分散在別的文件,這裡
只負責把順序串起來:

- Velociraptor Server 本身的部署細節(首次啟動、改密碼、Sysmon、應變動作
  用的 exchange artifact)→ `deploy/velociraptor/README.md`
- 各項環境變數的意義 → 根目錄 `.env.example`
- 專案整體結構、Phase 對應 → 根目錄 `README.md`

沒有實機跑過這整套流程,以下步驟是依照程式碼/設定檔的邏輯推導出來的,
照著做時如果卡住,回報卡在哪一步比較好排查。

---

## 0. 前置需求

- Synology DS923+(或同等級)已安裝 Container Manager,SSH 存取權限
- 已在 <https://console.cloud.google.com/apis/credentials> 建立好 Google
  OAuth 2.0 用戶端(見下面步驟 2 需要用到的 client id/secret)
- 這台 NAS 在內網可以被瀏覽器連到的實際位址(IP 或內部 DNS 名稱)——後面
  好幾個環境變數都要填這個,不是 `localhost`

## 1. 取得程式碼

```bash
git clone https://github.com/finrod-chen/mini-EDR.git
cd mini-EDR
```

## 2. 設定環境變數

```bash
cp .env.example .env
```

編輯 `.env`,以下幾個值**一定要改**,其餘可以先留預設值:

| 變數 | 填什麼 |
|---|---|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google Cloud Console 建立的 OAuth 用戶端。Authorized redirect URI 要設成 `http://<NAS位址>:8080/auth/callback` |
| `FRONTEND_ORIGIN` | `http://<NAS位址>:8081`(frontend service 對外開的埠,見下面步驟 5) |
| `BACKEND_PUBLIC_URL` | `http://<NAS位址>:8080`(backend service 對外開的埠;frontend image build 時會把這個位址燒進靜態檔案,填錯的話瀏覽器連得到頁面但打不到 API) |
| `SESSION_SECRET_KEY` | 隨機字串,例如 `openssl rand -hex 32` 的輸出 |

`GOOGLE_HOSTED_DOMAIN` / `SEED_ADMIN_EMAILS` 已經是正確的預設值
(`xiyuebiomed.com.tw` / `finrodchen@xiyuebiomed.com.tw`),不用動。

## 3. 啟動資料庫

```bash
docker compose up -d db
docker compose ps   # 等 db 變成 healthy
```

## 4. 部署 Velociraptor Server

```bash
cp deploy/velociraptor/.env.example deploy/velociraptor/.env
# 編輯 deploy/velociraptor/.env:填 VELOCIRAPTOR_HOSTNAME(內部 DNS 名稱)

docker compose up -d velociraptor-server
```

接著照 `deploy/velociraptor/README.md` 第 2~6 節走完:改初始密碼、部署 Sysmon
(第 7 節)、產生 `deploy/velociraptor/etc/api_client.yaml`(第 6 節,backend
連 Velociraptor API 需要這個檔案)。**這步驟沒做完的話 backend 起得來,但資產
同步/事件同步/隔離主機都會失敗**,不是啟動就會出現的錯誤,先知道這個限制。

## 5. 套用資料庫 schema

backend image 裡有 alembic,但 Dockerfile 的啟動指令不會自動跑 migration
(正式環境的 schema 變更想人工控制,不想每次重啟 container 都自動跑一次)。
第一次部署跟之後每次有新 migration 都要手動跑:

```bash
docker compose build backend
docker compose run --rm backend uv run alembic upgrade head
```

## 6. 啟動 backend / frontend

```bash
docker compose up -d --build backend frontend
```

`--build` 是因為 frontend image 要把步驟 2 設定的 `BACKEND_PUBLIC_URL` 燒進
靜態檔案,改過 `.env` 之後一定要重新 build 才會生效,單純 `up -d` 不會重建
已經存在的 image。

## 7. 驗證

```text
□ docker compose ps 全部服務都是 running/healthy
□ http://<NAS位址>:8080/health 回 {"status":"ok"}
□ http://<NAS位址>:8081 開得出登入頁,「使用 Google 帳號登入」導去 Google
□ 用 finrodchen@xiyuebiomed.com.tw 登入成功,Dashboard 右上角顯示「管理員」
□ 告警佇列/應變紀錄/資產管理三個頁面都能開(內容目前會是空的,因為
  Velociraptor 那邊還沒有真實端點回報資料——這是預期的,不代表壞掉)
```

## 已知會卡住的地方(誠實列出來,不是憑空假設會順利)

- **Velociraptor API 的 `bind_address`**:`deploy/velociraptor/README.md`
  第 6 節提到 API 預設只 bind `127.0.0.1`,需要手動改
  `server.config.yaml` 才能讓 backend 這個獨立 container 連得到。這件事
  沒有實機驗證過,若 backend 的資產/事件同步 job 一直失敗,先檢查這裡。
- **`api_client.yaml` 裡的 `api_connection_string`**:這個欄位記錄的
  hostname 是產生當下 Velociraptor 自己決定的,不一定是
  `velociraptor-server:8001`(docker network 內的 service name)。如果
  backend 連不到,打開這個檔案確認欄位值,需要的話手動改成
  `velociraptor-server:8001`。
- **CORS**:`FRONTEND_ORIGIN` 沒填對(協定/主機/埠號要完全一致)的話,
  瀏覽器 fetch `/api/*` 會被 CORS 擋掉,瀏覽器 console 會看到明確的
  CORS 錯誤訊息,比對 `.env` 的值跟瀏覽器網址列一致。
