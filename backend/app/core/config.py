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

    # AI Alert Explain(Phase 6,選配,見 app/services/ai_explain.py)。
    # 走 OpenAI-compatible 的 /chat/completions REST 介面,不綁定特定供應商
    # ——只要目標端點相容這個介面規格(OpenAI 本身、Azure OpenAI、內部自架的
    # 相容端點都算)就能用。三個值留空 = 停用,呼叫時會回錯誤而不是嘗試
    # 送出未設定的請求。
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""


settings = Settings()
