from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IAM_", extra="ignore")

    database_url: str = "postgresql+psycopg://iam:iam@localhost:5435/iam"
    bootstrap_token: str = ""
    issuer: str = "http://localhost:8010"
    token_ttl_seconds: int = 300
    signing_private_key: str = ""
    signing_private_key_file: str = ""
    signing_key_id: str = "local-dev"
    create_schema_on_startup: bool = False

    def resolved_signing_private_key(self) -> str:
        if self.signing_private_key:
            return self.signing_private_key
        if self.signing_private_key_file:
            return Path(self.signing_private_key_file).read_text()
        return ""
