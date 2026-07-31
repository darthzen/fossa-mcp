"""Custom exceptions for the FOSSA MCP server."""


class FossaError(Exception):
    """Base exception for FOSSA errors."""

    pass


class FossaConfigurationError(FossaError):
    """Exception raised when there's a configuration error."""

    pass


class FossaPolicyError(FossaError):
    """Exception raised when the local policy overlay is missing or invalid."""

    pass


class FossaWriteNotPermittedError(FossaError):
    """Exception raised when a write tool runs without `FOSSA_ALLOW_WRITES` enabled."""

    pass


class FossaApiError(FossaError):
    """Exception raised when the FOSSA API returns an error."""

    def __init__(
        self,
        status_code: int,
        message: str,
        method: str,
        path: str,
        error_name: str | None = None,
        fossa_code: int | None = None,
        reference_uuid: str | None = None,
    ):
        """Initialize a FossaApiError."""
        self.status_code = status_code
        self.message = message
        self.error_name = error_name
        self.fossa_code = fossa_code
        self.reference_uuid = reference_uuid
        self.method = method
        self.path = path

        # Create a human-readable message
        if error_name:
            super().__init__(f"FOSSA API returned {status_code} {error_name}: {message}")
        else:
            super().__init__(f"FOSSA API returned {status_code}: {message}")
