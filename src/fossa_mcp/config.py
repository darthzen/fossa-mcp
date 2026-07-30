"""Configuration settings for the FOSSA MCP server."""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import logging

class Settings(BaseSettings):
    """Settings for the FOSSA MCP server."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # API credentials and connection
    fossa_api_token: str | None = Field(default=None, description="FOSSA API token")
    fossa_base_url: str = Field(default="https://app.fossa.com/api", description="Base FOSSA API URL")
    fossa_timeout_seconds: float = Field(default=20.0, ge=0, description="Timeout for FOSSA requests in seconds")
    fossa_verify_tls: bool = Field(default=True, description="Verify TLS certificates")

    # Page size limits
    fossa_max_page_size: int = Field(default=100, ge=1, le=1000, description="Maximum page size for API calls")
    fossa_report_max_chars: int = Field(default=200000, ge=1000, le=1000000, description="Maximum characters in attribution reports")

    # Logging
    fossa_log_level: str = Field(default=logging.INFO, description="Log level for the application")

    # HTTP transport
    fossa_http_host: str = Field(default="127.0.0.1", description="HTTP host for streamable HTTP transport")
    fossa_http_port: int = Field(default=8000, ge=1, le=65535, description="HTTP port for streamable HTTP transport")

    @property
    def base_url(self) -> str:
        """Get the base URL without trailing slash."""
        return self.fossa_base_url.rstrip("/")

    @property
    def api_base_url(self) -> str:
        """Get the full API base URL."""
        return f"{self.base_url}/api"