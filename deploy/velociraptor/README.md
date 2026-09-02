# deploy/velociraptor

Velociraptor Server 部署在 **Synology DS923+(8GB RAM,已加購 RAM)**,透過 Docker
(Synology Container Manager)跑官方容器映像,與約 100 台 Windows 端點在同一內網、
已有內部 DNS 可解析。PostgreSQL/backend/frontend 之後也會放同一台 NAS(見根目錄
`docker-compose.yml`),先以單一 docker-compose 堆疊起步,資源不夠再拆。

官方 Docker 部署文件:<https://docs.velociraptor.app/docs/deployment/server/docker/>,
本文件是針對「NAS + 內網 GPO 推送 100 台端點」情境調整過的版本。

---

## 1. 前置需求

- Synology DSM 已安裝 **Container Manager** 套件(DSM 7.2+ 內建的 Docker 管理工具)
- 內部 DNS 已有一筆 record 指向這台 NAS 的內網 IP,例如
  `velociraptor.internal.<你的網域>`(實際名稱由你們的 DNS 管理者決定,填入
  `deploy/velociraptor/.env` 的 `VELOCIRAPTOR_HOSTNAME`)
- NAS 防火牆 / 路由器需放行:
  - TCP 8000(端點 <-> Server,對內網開放)
  - TCP 8889(GUI,建議只給管理者所在網段或 VPN)
  - **不要**對外(Internet)開放這兩個埠——規格設計是純內網 EDR,沒有對外遠端管理需求
- DS923+ 8GB RAM 的資源分配提醒:DSM 本身會保留部分記憶體,Velociraptor Server
  + PostgreSQL/TimescaleDB(+ 之後的 backend/frontend)全部塞同一台 NAS 會偏緊。
  Phase 1 先只跑 Velociraptor Server + DB 觀察實際用量,backend/frontend 上線
  (Phase 4/5)前建議重新評估要不要精簡或加開一台機器。

## 2. 首次部署

```bash
cp deploy/velociraptor/.env.example deploy/velociraptor/.env
# 編輯 deploy/velociraptor/.env:填入 VELOCIRAPTOR_HOSTNAME(內部 DNS 名稱)

docker compose up -d velociraptor-server
```

若習慣用 DSM 圖形介面而非 SSH:Container Manager → 專案(Project) → 新增 →
從資料夾建立,指向這個 repo 的路徑,選擇根目錄的 `docker-compose.yml`。

第一次啟動時,容器會自動:
- 產生 `server.config.yaml`(自簽憑證)到 `deploy/velociraptor/etc/`(對應 volume)
- 用 `.env` 裡的 `VELOCIRAPTOR_INITIAL_ADMIN_PASSWORD` 建立 admin 帳號
- 在容器內建置 client 安裝包(MSI/DEB/RPM)的初始素材

### 驗證啟動成功

```text
□ docker compose ps 顯示 velociraptor-server 為 healthy/running
□ 瀏覽器開 https://<NAS內網IP或內部DNS名稱>:8889/,能看到登入畫面
□ 用 admin + .env 裡設定的密碼登入成功
□ 登入後「立刻」在 GUI 右上角帳號選單改掉 admin 密碼
```

---

## 3. 產生端點安裝包(MSI)

1. GUI 左側選單 → **Server Artifacts** → 新增 collection → 搜尋
   `Server.Utils.CreateMSI` → Launch
   (此 artifact 會從 GitHub 下載官方 release 的 64/32-bit MSI,並自動打包進
   目前 org 的 client 設定)
2. 等 collection 完成後,到該 collection 的 **Uploaded Files** 分頁下載重新打包好的
   `velociraptor_custom.msi`(64-bit 版本給一般 Windows 端點用)

> 若要手動核對 client 設定內容(例如確認 `server_urls` 指到正確的內部 DNS 名稱):
> GUI 首頁 → **Current Orgs** → 點檔名即可下載 client config YAML 檢視。

### 生產環境建議

MSI 重新打包後沒有簽章,正式大量部署前建議用貴公司的 code-signing 憑證簽過,
避免 Windows SmartScreen / AV 誤攔。

---

## 4. GPO 推送流程

```text
1. 把下載好的 velociraptor_custom.msi 放到網域內的共享目錄
   (例如 \\<檔案伺服器>\Deployment\velociraptor_custom.msi,
   需確認該目錄已通過網域驗證存取)
2. 網域控制器建立 GPO:「Velociraptor-Agent-Deploy」
3. Computer Configuration → Policies → Software Settings
   → Software Installation → New Package → 指向共享目錄上的 MSI
4. Deployment method: Assigned(開機自動安裝)
5. 先連結到 Pilot OU 測試,再擴大範圍到所有端點 OU
```

安裝後 Velociraptor 服務以 Local System 帳號執行、開機自動啟動(延遲啟動)。
靜默安裝指令(GPO 或手動測試皆可用):

```text
msiexec /i velociraptor_custom.msi
```

### 部署驗證 Checklist(對應規格)

```text
□ 端點重開機後,服務清單出現 "Velociraptor Client"
□ Server GUI(https://<NAS>:8889)的 Clients 列表出現該主機
□ 執行測試 Artifact: Generic.Client.Info,確認回報正常
□ 執行 Windows.EventLogs.Defender,確認能抓到歷史 Defender 事件
```

---

## 5. 核心 Artifact 清單

```text
Windows.Sys.Users
Windows.System.Amcache              # 軟體安裝歷史
Windows.Applications.Chrome.Extensions
Generic.System.Pstree                # 進程樹
Windows.EventLogs.Defender           # Defender 事件
Windows.Remediation.Quarantine       # 應變:網路隔離
Generic.Client.Info                  # 部署驗證用
```

---

## 6. 給 backend 用的 API Client(Phase 1 資產同步 job 需要)

backend 的資產/軟體清單同步 job(`app/jobs/sync_assets.py`)透過 Velociraptor 的
gRPC API(預設埠 8001,與 GUI/端點連線埠分開)呼叫,需要一組「API client」憑證,
**不是**拿 GUI 登入帳密。

### 建立 API client

```bash
docker compose exec velociraptor-server \
  velociraptor --config /etc/velociraptor/server.config.yaml \
  config api_client --name mini-edr-backend --role api \
  /etc/velociraptor/api_client.yaml
```

- `--role api`:只給執行 VQL 查詢需要的最小權限,不要用 `administrator`
- 產生的 `api_client.yaml`(含私鑰、憑證、連線資訊)會落在
  `deploy/velociraptor/etc/api_client.yaml`(對應到 volume),**這個檔案不進版控**
  (已在根目錄 `.gitignore` 排除),backend 透過 volume/複製這個檔案來連線

### 讓 backend 連得到 API

Velociraptor API 預設只 bind `127.0.0.1`(容器內部視角),同一 docker-compose
network 內的其他服務(如 backend)無法直接連。需要編輯
`deploy/velociraptor/etc/server.config.yaml` 裡 `API` 區塊的 `bind_address`
改成 `0.0.0.0`(允許同一個 Docker network 內的其他容器連,不代表對外網開放——
埠 8001 本來就沒有在 docker-compose 的 `ports:` 裡對外發布),改完
`docker compose restart velociraptor-server` 生效。

backend 端連線設定見 `app/core/config.py` 的
`velociraptor_api_url` / `velociraptor_api_token`——但走的是官方
`pyvelociraptor` 套件讀 `api_client.yaml` 的方式,不是單純 URL + token,
實際用法見 `app/services/velociraptor_client.py`。

---

## 7. 備份策略

`deploy/velociraptor/datastore/` 是 Velociraptor 的資料本體(端點資料、
collection 結果、hunt 紀錄),`deploy/velociraptor/etc/` 是伺服器設定與憑證。
建議直接用 Synology **Hyper Backup** 對這兩個資料夾(對應到 NAS 上的實際
volume 路徑)排程備份,不用額外自製備份腳本——這是選用 NAS 部署相對於
獨立 VM 的優勢之一。
