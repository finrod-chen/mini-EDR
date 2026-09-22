# deploy/asus-exporter

給沒有開 SNMP 服務的 ASUS 路由器用的資產監控來源。`asus-exporter.py` 是
vendor 自 [LaurentDumont/asus-router-exporter](https://github.com/LaurentDumont/asus-router-exporter)
(commit `8fd39180f21e2c0907a273ef8ad916d9e4fe0200`)的第三方程式碼,模擬
ASUS 官方 App 登入路由器管理介面(`login.cgi`/`appGet.cgi`),把
CPU/記憶體/uptime/連線裝置/WAN 狀態轉成 Prometheus 格式在 `:8000/metrics`
暴露出來。上游沒有附 LICENSE 檔,這裡僅供個人/內部使用,不對外散布。

backend 的 `app/jobs/sync_asus_exporter.py` 會定期打這個 `/metrics`,把
資料寫進 `asset_inventory`(跟 SNMP 監控裝置共用同一套
`monitor_type='snmp'` 資料模型與健康分數/資產管理頁 UI,細節見
`app/jobs/sync_snmp_assets.py` 的說明)。

## 一個 container 只認一台路由器

`login_router()` 是單一目標的無限迴圈,沒有「多目標」概念——監控幾台
ASUS 路由器,就要跑幾個這個 container 的實例,各自用不同的
`ASUS_USERNAME`/`ASUS_PASSWORD`/`ASUS_IP` 指到不同的路由器。根目錄
`docker-compose.yml` 目前已經起了 `asus-exporter-1`/`-2`/`-3` 三個實例
(對應 3 台路由器),都是同一份程式碼、同一個 build context,差別只在
各自的 env file。

## 網路拓樸:exporter 只能打路由器的 WAN 端

這幾台路由器是接在主網路下當「路由器模式」用(不是直接掛在同一個 LAN
的 SNMP 裝置那種),各自的 LAN 端(WiFi 客戶端連的)是獨立子網,exporter
container 跟這些子網不通,只能打得到路由器的 **WAN 端** IP。

多數消費型路由器(ASUS 也一樣)預設**不允許從 WAN 端存取網頁管理介面**
——就算這個「WAN」其實是你自己的內網、不是 Internet,路由器不會區分。
要監控就得去每台路由器的管理介面(從連上該路由器 WiFi 的裝置,例如
`https://192.168.50.1`)手動開:

**Administration → System → Enable Web Access from WAN**

⚠️ **安全性 trade-off,自己評估要不要開**:打開後,任何打得到路由器 WAN
端 IP 的裝置都能看到登入頁(帳密仍要正確才能登入,但攻擊面變大了)。
建議搭配 PA-410 防火牆加一條規則,只允許 NAS 的來源 IP 打這幾台路由器
WAN 端 IP 的管理 port,不要讓整個內網都碰得到。

開啟後,ASUS 韌體預設會把 WAN 端管理介面換成 **HTTPS + 8443**(不是
LAN 端預設的 HTTP:80),而且是自簽憑證——`asus-exporter.py` 已經改成
預設打 `https://<ip>:8443` 並關閉憑證驗證來配合這個限制(見檔案開頭的
差異說明,`ASUS_SCHEME`/`ASUS_PORT` 環境變數可以覆寫)。

## 首次部署

```bash
cp deploy/asus-exporter/router.env.example deploy/asus-exporter/router-1.env
cp deploy/asus-exporter/router.env.example deploy/asus-exporter/router-2.env
cp deploy/asus-exporter/router.env.example deploy/asus-exporter/router-3.env
# 編輯三個 router-N.env,各自填入該台路由器的管理介面帳密與「WAN 端」IP
# (ASUS_USERNAME / ASUS_PASSWORD / ASUS_IP——不是連上該路由器 WiFi 看到
# 的 LAN 閘道 IP,見上面「網路拓樸」一節)

cp deploy/asus_exporter/asus_targets.example.json deploy/asus_exporter/asus_targets.json
# 編輯 asus_targets.json:ip 要跟對應 router-N.env 的 ASUS_IP 一致,
# label 會直接當作資產管理頁面顯示的主機名(這類裝置沒有自報的
# hostname 可用)

docker compose up -d --build asus-exporter-1 asus-exporter-2 asus-exporter-3 backend
```

`router-N.env` 含明碼密碼,已加進 `.gitignore`,不要 commit。

## 新增第 4 台路由器

三個地方都要動,沒有自動發現機制:

1. `cp deploy/asus-exporter/router.env.example deploy/asus-exporter/router-4.env`,
   填入該台的帳密/IP
2. 根目錄 `docker-compose.yml` 仿照 `asus-exporter-1`/`-2`/`-3` 加一個
   `asus-exporter-4` service(套用同一個 `x-asus-exporter` anchor,
   `env_file` 指到 `router-4.env`)
3. `deploy/asus_exporter/asus_targets.json` 加一筆,`exporter_url` 指到
   `http://asus-exporter-4:8000/metrics`

跑 `docker compose up -d --build asus-exporter-4 backend`。

## 更新 vendor 進來的程式碼

上游之後如果修 bug,沒有自動同步機制——對照上游 `asus-exporter.py` 手動
重新複製,更新這個檔案開頭的來源註記(commit hash),必要時同步調整
`requirements.txt`(這裡只留執行期用得到的 `requests`/`prometheus_client`
兩個套件,不是照抄上游整包 dev lockfile)。
