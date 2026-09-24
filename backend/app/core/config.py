from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "mini-edr-backend"
    database_url: str = "postgresql+psycopg://mini_edr:mini_edr@localhost:5432/mini_edr"

    # Velociraptor API 走 mutual TLS,認證資訊(CA/私鑰/憑證/連線字串)全部包在
    # `velociraptor config api_client` 產生的 api_client.yaml 裡,不是單純的
    # URL + token。這裡只存這個檔案的路徑,見 deploy/velociraptor/README.md
    # 第 6 節與 app/services/velociraptor_client.py。
    velociraptor_api_config_path: str = "../deploy/velociraptor/etc/api_client.yaml"

    # Google SSO(Dashboard 登入用,見 app/core/auth.py)
    google_client_id: str = ""
    google_client_secret: str = ""
    # 只允許這個 Google Workspace 網域的帳號登入(空字串 = 不限制)。預設值
    # 就是實際會用的網域,本機開發若要暫時放寬測試其他帳號,自己在 .env
    # 覆寫成空字串,不要改這裡的預設值。
    google_hosted_domain: str = "xiyuebiomed.com.tw"
    # 這些 email(逗號分隔)第一次登入時一定是 admin,且如果已存在但角色
    # 不是 admin 會被升級(只會升級,不會反向降級別人)。見
    # app/services/users.py 的 get_or_create_user。
    seed_admin_emails: str = "finrodchen@xiyuebiomed.com.tw"
    # Starlette SessionMiddleware 簽章用的密鑰,正式環境務必換成隨機字串並妥善保管
    # (改變這個值會讓所有人的登入 session 失效,相當於強制全體登出)。
    session_secret_key: str = "dev-only-change-me"
    frontend_origin: str = "http://localhost:5173"

    # SNMP v2c 資產監控(印表機/NAS/防火牆等裝不了 Velociraptor agent 的裝置,
    # 見 app/jobs/sync_snmp_assets.py)。v2c 是既定環境限制,community string
    # 明碼傳輸,靠網路區隔(SNMP 只開放給後端主機的來源 IP)緩解,不是這裡能
    # 解決的問題。
    #
    # 監控目標清單(IP/裝置類型)用靜態 JSON 檔案管理,不是 DB 表——裝置數量
    # 少、極少變動,比照 velociraptor_api_config_path 只存檔案路徑,格式見
    # deploy/snmp/snmp_targets.example.json。
    snmp_targets_config_path: str = "../deploy/snmp/snmp_targets.json"
    # 全域唯一的唯讀 community string,明碼存放——跟 llm_api_key/
    # google_client_secret 同一個安全假設(這個專案沒有密碼加密基礎設施)。
    snmp_community: str = ""
    # 單一裝置 SNMP GET 的逾時秒數與重試次數,裝置沒回應時不能卡住整個
    # 輪詢流程(見 sync_snmp_assets.py 的 per-target try/except)。
    snmp_timeout_seconds: float = 3.0
    snmp_retries: int = 1

    # ASUS 路由器資產監控(沒有 SNMP 服務的裝置,見 app/jobs/sync_asus_exporter.py)。
    # 資料來源不是 SNMP,是 deploy/asus-exporter/ 這個 vendor 進來的
    # Prometheus exporter(模擬 ASUS 官方 App 登入路由器管理介面);寫進
    # asset_inventory 時沿用跟 SNMP 裝置一樣的 monitor_type='snmp',所以
    # 設定風格也比照 snmp_targets_config_path——靜態 JSON 檔案,不是 DB
    # 表,一個 exporter container 只服務一台路由器,格式見
    # deploy/asus_exporter/asus_targets.example.json。
    asus_exporter_targets_config_path: str = "../deploy/asus_exporter/asus_targets.json"
    asus_exporter_timeout_seconds: float = 5.0

    # syslog 接收(見 app/services/syslog_listener.py)。同一個 UDP port
    # 現在收兩種來源:PA-410(掃描偵測 + 人工一鍵封鎖,見
    # firewall_scan_detector.py/pan_os_remediation.py)跟 Synology NAS
    # (登入失敗/暴力破解成功/大量刪除搬移檔案,見
    # synology_log_analyzer.py)。不管來源、也不管有沒有命中任何分析
    # 規則,原始內容一律先存進 syslog_messages(見
    # app/models/syslog_message.py)。
    #
    # 監聽 port 故意不用特權的 514(容器內不用 root 就能 bind),PA-410
    # 端的 syslog server profile、DSM 的記錄傳送設定都要指到這個 port。
    syslog_listen_host: str = "0.0.0.0"
    syslog_listen_port: int = 5514
    # PAN-OS User-ID API(封鎖動作用)。管理介面通常是自簽憑證,內網限定,
    # 跟這個專案既有的「沒有密碼/憑證加密基礎設施」立場一致,不為此新增
    # TLS 驗證機制。
    panos_api_base_url: str = "https://192.168.2.200"
    panos_api_key: str = ""
    panos_api_verify_tls: bool = False
    # 封鎖時打的 tag,必須跟 PA-410 上 Dynamic Address Group 比對的 tag
    # 完全一致(防火牆端的一次性設定,不是這裡的程式碼範圍)。
    panos_block_tag: str = "mini-edr-blocked"
    # 封鎖幾秒後自動解除(User-ID API 的 tag timeout)。實機上線後撞到真實
    # 教訓:PA-410 這種入門機型的 registered-IP 容量有限,PAN-OS 內建的
    # 另一個 auto-tagging 機制("Threat Alert")設成永久不過期(0),累積
    # 超過 1000 筆就把容量佔滿,連我們自己的 mini-edr-blocked 都註冊不進去
    # ——同一個坑我們自己的 tag 不該重蹈覆轍,預設改成 24 小時會自動過期,
    # 不要無限累積。設成 0 才是永久(照 PAN-OS 原本的語意),需要真的想永久
    # 封鎖再手動改。
    panos_block_timeout_seconds: int = 86400
    # 告警標記誤判後,同一 (rule_name, host) 抑制幾天不再開新 alert(見
    # app/models/alert.py 的 AlertSuppression、app/rules/engine.py)。給
    # 到期時間而不是永久 allowlist,避免同一條規則、同一台主機之後的真實
    # 事件被永久靜音。
    false_positive_suppression_days: int = 14
    # 即時掃描偵測門檻,走 Settings 不寫死常數——上線後很可能要依實際流量
    # 調整,不用改程式碼重新 build(比照 app/rules/definitions.py 對規則
    # 門檻值「預期之後要調」的既有態度)。
    syslog_port_scan_threshold: int = 15
    syslog_port_scan_window_seconds: int = 60
    syslog_host_sweep_threshold: int = 15
    syslog_host_sweep_window_seconds: int = 60
    # 記憶體內的來源 IP 追蹤狀態,超過這個秒數沒有新活動就清掉,避免無限
    # 累積。
    syslog_state_ttl_seconds: int = 300

    # Synology NAS 送過來的 syslog 判斷來源用(見 syslog_listener.py 的
    # classify_source())。原本想比對 UDP 封包的來源 IP,但實機測試發現
    # docker 會把進來的封包來源位址重寫成 docker bridge 的 gateway IP(不
    # 管哪個外部裝置送的,container 看到的 source_ip 全部一樣),這個判斷
    # 方式完全不可靠——改成比對 syslog 信封裡帶的主機名稱(DSM 自己在
    # BSD syslog 開頭固定會帶,例如 `<14>Sep 24 09:07:49 Xiyue-NAS
    # Connection: ...` 裡的 `Xiyue-NAS`,不受 Docker NAT 影響)。空字串 =
    # 不比對,送進來的非 PA-410 內容一律歸類 other(只存原始 log,不跑
    # 分析)。填這台 NAS 在 控制台 → 網路 → 一般 設定的伺服器名稱。
    synology_nas_syslog_hostname: str = ""
    # 大量刪除/搬移檔案的 alert host 用這個(不是拿來判斷來源,見上面
    # synology_nas_syslog_hostname)——填這台 NAS 的 IP,資產清單裡已有
    # 這筆資產,alert 畫面上的 IP→資產名稱對照會自動顯示成對應的主機名。
    synology_nas_ip: str = ""
    # 登入失敗次數異常(疑似暴力破解)的門檻/視窗。
    synology_login_failure_threshold: int = 5
    synology_login_failure_window_seconds: int = 300
    # 「先失敗好幾次接著成功」判定為暴力破解成功登入的門檻——刻意比上面
    # 的純失敗告警門檻低,因為這個模式本身就是更明確的危險訊號,不用等到
    # 失敗次數也達到 synology_login_failure_threshold。
    synology_malicious_login_recent_failures: int = 3
    # 大量刪除/搬移檔案的門檻/視窗。這是先抓的起始值,不同使用情境(例如
    # 管理員整理資料夾、備份工具跑批次刪除)可能誤判,預期上線後要依實際
    # 狀況調整——誤判可以用 mark_false_positive 的抑制機制降噪(見
    # app/models/alert.py 的 AlertSuppression),門檻本身不用急著改。
    synology_file_op_threshold: int = 20
    synology_file_op_window_seconds: int = 60
    # 跟 syslog_state_ttl_seconds 是同一種用途,獨立一個值是因為 Synology
    # 分析器(SynologyLogAnalyzer)是跟 ScanDetector 分開的物件、各自管理
    # 自己的記憶體內狀態,不共用同一個 TTL 設定也不影響正確性,只是剛好
    # 目前預設值一樣。
    synology_state_ttl_seconds: int = 300

    # AI Alert Explain(Phase 6,選配,見 app/services/ai_explain.py)。
    # 走 OpenAI-compatible 的 /chat/completions REST 介面,不綁定特定供應商
    # ——只要目標端點相容這個介面規格(OpenAI 本身、Azure OpenAI、內部自架的
    # 相容端點都算)就能用。三個值留空 = 停用,呼叫時會回錯誤而不是嘗試
    # 送出未設定的請求。
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""


settings = Settings()
