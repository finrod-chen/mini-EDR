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
    # 只允許這個 Google Workspace 網域的帳號登入(空字串 = 不限制,本機開發方便用,
    # 正式環境務必填,否則任何 Google 帳號都能登入)。
    google_hosted_domain: str = ""
    # Starlette SessionMiddleware 簽章用的密鑰,正式環境務必換成隨機字串並妥善保管
    # (改變這個值會讓所有人的登入 session 失效,相當於強制全體登出)。
    session_secret_key: str = "dev-only-change-me"
    frontend_origin: str = "http://localhost:5173"

    # AI Alert Explain(Phase 6,選配,見 app/services/ai_explain.py)。
    # 走 OpenAI-compatible 的 /chat/completions REST 介面,不綁定特定供應商
    # ——只要目標端點相容這個介面規格(OpenAI 本身、Azure OpenAI、內部自架的
    # 相容端點都算)就能用。三個值留空 = 停用,呼叫時會回錯誤而不是嘗試
    # 送出未設定的請求。
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""


settings = Settings()
