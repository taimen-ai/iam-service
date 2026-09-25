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
    # Platform Access Token: срок жизни самого PAT, потолок срока и предельный
    # возраст human authentication, при котором ещё разрешён выпуск.
    pat_default_ttl_seconds: int = 2592000
    pat_max_ttl_seconds: int = 31536000
    pat_max_authentication_age_seconds: int = 300
    # Окно совместимости для перенесённых Control Plane API keys.
    legacy_credential_max_ttl_seconds: int = 7776000
    # SCIM provisioning: отдельный audience и scope confidential service
    # identity SCIM-клиента, плюс предел страницы выдачи.
    scim_audience: str = "iam-scim"
    scim_scope: str = "scim:write"
    scim_max_page_size: int = 200
    # Каналы как способ входа (Telegram): audience самого IAM, которому
    # предъявляют токены человек и адаптер канала; scope адаптера; срок кода
    # привязки и предельный возраст входа человека, создающего код.
    channel_audience: str = "iam"
    channel_scope: str = "iam:channel-links"
    channel_link_code_ttl_seconds: int = 600
    channel_link_max_authentication_age_seconds: int = 300
    # Assertion канала обменивается ровно на один audience и один scope, срок
    # токена — минута: это подтверждение одного решения, а не сессия.
    channel_assertion_audience: str = "control-plane"
    channel_assertion_scope: str = "control-plane:decide"
    channel_assertion_ttl_seconds: int = 60
    # Лимиты частоты: число событий в скользящем окне.
    channel_link_intent_limit: int = 5
    channel_link_intent_window_seconds: int = 600
    channel_confirm_failure_limit: int = 10
    channel_confirm_failure_window_seconds: int = 600
    channel_assertion_limit: int = 10
    channel_assertion_window_seconds: int = 60

    def resolved_signing_private_key(self) -> str:
        if self.signing_private_key:
            return self.signing_private_key
        if self.signing_private_key_file:
            return Path(self.signing_private_key_file).read_text()
        return ""
