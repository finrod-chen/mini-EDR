# deploy/syslog

PA-410 防火牆跟 Synology NAS(這台跑 mini-edr 的 NAS 本身)共用同一個
UDP port(預設 5514,見 `backend/app/core/config.py` 的
`syslog_listen_port`)送 syslog 過來,由 `app/services/syslog_listener.py`
統一接收:不管有沒有命中任何分析規則,原始內容一律先存進
`syslog_messages`(保留 30 天,見「Syslog 記錄」頁面),命中規則的另外
開一筆 alert。詳細的收送/分析邏輯見 `app/services/syslog_listener.py`/
`firewall_scan_detector.py`/`synology_log_analyzer.py` 的模組說明。

## PA-410

PA-410 端要在 syslog server profile 設定自訂 log 格式(`key="value"`,
不是版本敏感的預設 CSV),目的地是這台 NAS 的位址 + port 5514(UDP)。
Traffic/Threat log 都要送——Threat log 現在除了掃描/偵察特徵會觸發
alert,PAN-OS 自己判定 high/critical 的非掃描類 Threat log(真正的
惡意程式/漏洞攻擊命中)也會觸發 alert。

**選配**:如果之後想連防火牆本身的管理員登入/設定變更都收進來,可以在
PA-410 的 syslog server profile 額外加開 **System** log type——原始內容
一樣會被存進 `syslog_messages` 可查(`parse_line` 是格式無關的,不挑
log type),但目前**沒有**針對 System log 寫對應的即時偵測規則,要等
實際看過 PAN-OS System log 的 `subtype`/`eventid` 欄位長怎樣才補。

## Synology NAS

這台 NAS 把自己的 syslog 送給跑在自己身上的 container,同一個 port:

1. **控制台 → 記錄中心 → 記錄傳送設定**:目的地指到 NAS 自己的 LAN IP
   (不是 `localhost`/`127.0.0.1`)+ port 5514,協定用預設的 BSD
   syslog / UDP。記錄類別建議一開始只勾「連線」(登入相關),不要整台
   全送,量比較好控制。
2. **控制台 → 共用資料夾 → 選要監控的資料夾 → 編輯 → 記錄**:要偵測
   「大量刪除/搬移檔案」,需要另外對個別共用資料夾開啟檔案存取記錄
   ——這個記錄預設全部關閉,而且開了之後每個檔案操作都會送一行,建議
   先只對真的重要/敏感的資料夾開。
3. 後端 `.env` 補上一行,值填 NAS 自己的 LAN IP(跟步驟 1 同一個):
   ```
   SYNOLOGY_NAS_SYSLOG_SOURCE_IP=192.168.2.185
   ```
   這個設定是拿來判斷「這行 syslog 是不是 NAS 自己送的」(見
   `syslog_listener.py` 的 `classify_source()`)——PA-410 是靠內容判斷
   (`type="TRAFFIC"`/`type="THREAT"`),Synology 的內容格式完全不是
   key=value,只能靠來源 IP 認。沒填這個值的話,NAS 送來的內容一律歸類
   `other`,只會存原始 log、不會跑登入失敗/暴力破解/大量刪除搬移的分析。
4. `docker compose up -d --build backend` + `docker compose run --rm
   backend uv run alembic upgrade head`(新的 `syslog_messages` 表要跑
   migration 才會建出來)。

### 三種分析規則的確定性不一樣

- **登入失敗 / 暴力破解成功**:抓的是 DSM Connection log 公開文件、
  社群(含 fail2ban 的 Synology filter)廣泛驗證過的固定句型,相對有
  把握,但沒有拿實機真實輸出驗證過。
- **大量刪除/搬移檔案**:要靠 DSM 的 File log,句型比登入格式更沒把握
  (公開來源比較少可以交叉確認)。

部署後這兩類規則、尤其是檔案操作那條,大概率要照實際跑出來的 log 內容
再調整 `app/services/synology_log_analyzer.py` 裡的 regex,不會一次到位。
如果一開始誤判(例如管理員自己整理資料夾觸發「大量刪除/搬移」),用
告警佇列的「標記誤判」就會抑制同一條規則、同一個來源 14 天內不再開新
alert(見 `AlertSuppression`),不用急著改門檻。

### 排查:NAS 打自己對外發布的 port 不通

如果照上面設定完,「Syslog 記錄」頁面完全看不到 `source_type` 是
`synology_nas` 的資料,先排除「還沒做前置設定」之後,可以查一下 DSM
自己的防火牆設定有沒有擋到 NAS 對自己(經過 Docker 對外發布的 port)
這個路徑——有些環境對「NAS 打自己對外發布的 port」這種 hairpin 路徑
處理不太一致,不像單純的 LAN-to-LAN 那麼保證一定通。
