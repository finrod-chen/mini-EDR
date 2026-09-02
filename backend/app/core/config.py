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


settings = Settings()
