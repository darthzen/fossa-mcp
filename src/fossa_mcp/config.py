"""Configuration settings for the FOSSA MCP server."""

import logging

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class Settings(BaseSettings):
    """Settings for the FOSSA MCP server."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # API credentials and connection
    fossa_api_token: str | None = Field(default=None, description="FOSSA API token")
    fossa_base_url: str = Field(
        default="https://app.fossa.com/api", description="Base FOSSA API URL"
    )
    fossa_timeout_seconds: float = Field(
        default=20.0, gt=0, description="Timeout for FOSSA requests in seconds"
    )
    fossa_verify_tls: bool = Field(default=True, description="Verify TLS certificates")

    # Page size limits
    fossa_max_page_size: int = Field(
        default=100, ge=1, le=1000, description="Maximum page size for API calls"
    )
    fossa_report_max_chars: int = Field(
        default=200000,
        ge=1000,
        le=1000000,
        description="Maximum characters in attribution reports",
    )

    # Logging
    fossa_log_level: str = Field(default="INFO", description="Log level for the application")

    # HTTP transport
    fossa_http_host: str = Field(
        default="127.0.0.1", description="HTTP host for streamable HTTP transport"
    )
    fossa_http_port: int = Field(
        default=8000, ge=1, le=65535, description="HTTP port for streamable HTTP transport"
    )

    @field_validator("fossa_log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        """Ensure the configured log level is a valid Python log level name."""
        normalized = value.upper()
        if normalized not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"fossa_log_level must be one of {sorted(_VALID_LOG_LEVELS)}, got {value!r}"
            )
        return normalized

    @field_validator("fossa_base_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("fossa_api_token")
    @classmethod
    def _strip_token_whitespace(cls, value: str | None) -> str | None:
        """Tolerate surrounding whitespace in the supplied token.

        Tokens routinely arrive from a file or a Kubernetes Secret created with
        `--from-file`, both of which keep the trailing newline. Sending that
        newline in the Authorization header fails every request with a 401 that
        looks like a bad token rather than a bad newline. An empty or
        whitespace-only value is treated as absent.
        """
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @property
    def base_url(self) -> str:
        """Get the base URL without a trailing slash. Already includes `/api`."""
        return self.fossa_base_url

    @property
    def log_level_int(self) -> int:
        """Resolve the configured log level name to its numeric value."""
        return logging.getLevelNamesMapping()[self.fossa_log_level]
