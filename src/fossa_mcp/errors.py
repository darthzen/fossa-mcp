"""Custom exceptions for the FOSSA MCP server."""

from typing import Optional


class FossaError(Exception):
    """Base exception for FOSSA errors."""
    pass


class FossaConfigurationError(FossaError):
    """Exception raised when there's a configuration error."""
    pass


class FossaApiError(FossaError):
    """Exception raised when the FOSSA API returns an error."""

    def __init__(
        self,
        status_code: int,
        message: str,
        error_name: Optional[str] = None,
        fossa_code: Optional[int] = None,
        reference_uuid: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
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