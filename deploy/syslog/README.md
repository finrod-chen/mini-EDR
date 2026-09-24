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
3. 後端 `.env` 補上兩行:
   ```
   SYNOLOGY_NAS_SYSLOG_HOSTNAME=Xiyue-NAS
   SYNOLOGY_NAS_IP=192.168.2.185
   ```
   `SYNOLOGY_NAS_SYSLOG_HOSTNAME` 填這台 NAS 在
   **控制台 → 網路 → 一般** 設定的伺服器名稱,是拿來判斷「這行 syslog
   是不是 NAS 自己送的」(見 `syslog_listener.py` 的
   `classify_source()`)。**原本設計是比對來源 IP,但實機測試發現
   Docker 會把進來的封包來源位址重寫成 docker bridge 的 gateway IP(不
   管哪個外部裝置送的,container 看到的來源 IP 全部一樣),完全不可靠
   ——改成比對 syslog 信封裡帶的主機名稱**,不受 Docker NAT 影響。沒填
   這個值的話,NAS 送來的內容一律歸類 `other`,只會存原始 log、不會跑
   登入失敗/暴力破解/大量刪除搬移的分析。

   `SYNOLOGY_NAS_IP` 填 NAS 自己的 LAN IP,單純是給「大量刪除/搬移
   檔案」這個 alert 的 `host` 欄位用(資產清單裡已有這筆資產,畫面上
   會自動顯示成對應的主機名),跟上面的來源判斷是兩件事。
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

如果照上面設定完,「Syslog 記錄」頁面完全看不到任何資料進來(連
`source_type=other` 都沒有),先排除「還沒做前置設定」之後,可以查一下
DSM 自己的防火牆設定有沒有擋到 NAS 對自己(經過 Docker 對外發布的
port)這個路徑——有些環境對「NAS 打自己對外發布的 port」這種 hairpin
路徑處理不太一致,不像單純的 LAN-to-LAN 那麼保證一定通。

### 已知現象:`source_ip` 欄位不是真正的發送端 IP

「Syslog 記錄」頁面/`syslog_messages` 表裡的 `source_ip` 欄位,實機測試
下來不管 PA-410 還是 Synology NAS 送的,看到的都是同一個 docker bridge
的 gateway IP(例如 `172.29.0.1`),不是 `192.168.2.200`/`192.168.2.185`
這種實際的發送端 IP——這是 Docker 的 NAT 行為,不是設定錯誤,**這個
欄位純粹是除錯輔助資訊,不會拿來判斷來源**(見上面 `classify_source()`
的說明,判斷來源是看 syslog 信封裡帶的主機名稱,不是這個欄位)。
