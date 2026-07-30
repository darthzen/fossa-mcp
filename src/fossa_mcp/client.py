"""FOSSA API client for the MCP server."""

import asyncio
import json
import logging
from typing import Any

import httpx

from . import __version__
from .config import Settings
from .errors import FossaApiError

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS_CODES = {502, 503, 504}
_MAX_RETRIES = 2
_BACKOFF_SECONDS = (0.25, 0.75)
_MAX_RETRY_AFTER_SECONDS = 10.0


class FossaClient:
    """Asynchronous FOSSA API client.

    Owns a single reusable `httpx.AsyncClient` and connection pool for the
    lifetime of the server process.
    """

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        """
        Initialize the FOSSA client.

        Args:
            settings: Application settings
            transport: Optional HTTP transport for testing
        """
        self.settings = settings

        headers = {
            "User-Agent": f"fossa-mcp/{__version__}",
            "Accept": "application/json",
        }
        if settings.fossa_api_token:
            headers["Authorization"] = f"Bearer {settings.fossa_api_token}"

        self._client = httpx.AsyncClient(
            base_url=settings.base_url,
            timeout=settings.fossa_timeout_seconds,
            verify=settings.fossa_verify_tls,
            transport=transport,
            headers=headers,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        params: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """
        Make an HTTP request and return the parsed JSON response.

        Raises:
            FossaApiError: If the API returns an error or an invalid JSON body.
        """
        _, body = await self.request_json_with_status(method, path, params=params)
        return body

    async def request_json_with_status(
        self,
        method: str,
        path: str,
        *,
        params: list[tuple[str, str]] | None = None,
    ) -> tuple[int, dict[str, Any] | list[Any]]:
        """
        Make an HTTP request and return `(status_code, parsed_json)`.

        Useful for endpoints where a specific 2xx status code (e.g. FOSSA's
        `202` "analysis in progress") is distinct from ordinary success and
        must not be discarded.

        Raises:
            FossaApiError: If the API returns an error or an invalid JSON body.
        """
        response = await self._request(method, path, params=params)

        if 200 <= response.status_code < 300:
            try:
                return response.status_code, response.json()
            except json.JSONDecodeError as exc:
                raise FossaApiError(
                    status_code=response.status_code,
                    message="Invalid JSON response from FOSSA API",
                    method=method,
                    path=path,
                ) from exc

        raise self._build_error(response, method, path)

    async def request_text(
        self,
        method: str,
        path: str,
        *,
        params: list[tuple[str, str]] | None = None,
    ) -> tuple[str, str | None]:
        """
        Make an HTTP request and return the raw text response.

        Raises:
            FossaApiError: If the API returns an error.
        """
        response = await self._request(method, path, params=params)

        if 200 <= response.status_code < 300:
            return response.text, response.headers.get("content-type")

        raise self._build_error(response, method, path)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: list[tuple[str, str]] | None = None,
    ) -> httpx.Response:
        """Perform the HTTP call, retrying transient failures per the retry policy."""
        # httpx's QueryParamTypes list branch is invariant on
        # list[tuple[str, str]]; its homogeneous-tuple branch is covariant, so
        # pass a plain tuple instead of relying on structural list compatibility.
        httpx_params = tuple(params) if params else None

        attempt = 0
        while True:
            try:
                response = await self._client.request(method, path, params=httpx_params)
            except httpx.TimeoutException as exc:
                if attempt < _MAX_RETRIES:
                    await self._sleep_backoff(attempt)
                    attempt += 1
                    continue
                raise FossaApiError(
                    status_code=0,
                    message=(
                        f"FOSSA request timed out after {self.settings.fossa_timeout_seconds} "
                        f"seconds while calling {method} {path}."
                    ),
                    method=method,
                    path=path,
                ) from exc
            except httpx.TransportError as exc:
                if attempt < _MAX_RETRIES:
                    await self._sleep_backoff(attempt)
                    attempt += 1
                    continue
                raise FossaApiError(
                    status_code=0,
                    message=f"FOSSA request failed while calling {method} {path}: {exc}",
                    method=method,
                    path=path,
                ) from exc

            logger.info(
                "FOSSA %s %s -> %d%s",
                method,
                path,
                response.status_code,
                self._elapsed_suffix(response),
            )

            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < _MAX_RETRIES:
                await self._sleep_backoff(attempt, response)
                attempt += 1
                continue

            return response

    async def _sleep_backoff(self, attempt: int, response: httpx.Response | None = None) -> None:
        """Sleep for the backoff delay, honoring a safe, short `Retry-After` if present."""
        delay = _BACKOFF_SECONDS[attempt]

        if response is not None:
            retry_after = response.headers.get("retry-after")
            if retry_after is not None:
                try:
                    seconds = float(retry_after)
                except ValueError:
                    seconds = None
                if seconds is not None and 0 <= seconds <= _MAX_RETRY_AFTER_SECONDS:
                    delay = seconds

        logger.info("FOSSA retrying (attempt %d) after %.2fs", attempt + 1, delay)
        await asyncio.sleep(delay)

    @staticmethod
    def _elapsed_suffix(response: httpx.Response) -> str:
        """Format elapsed time for logging; absent under mock transports."""
        try:
            elapsed_ms = response.elapsed.total_seconds() * 1000
        except RuntimeError:
            return ""
        return f" in {elapsed_ms:.0f}ms"

    @staticmethod
    def _build_error(response: httpx.Response, method: str, path: str) -> FossaApiError:
        """Build a FossaApiError from an error response, parsing FOSSA's JSON error shape."""
        try:
            error_data = response.json()
        except json.JSONDecodeError:
            return FossaApiError(
                status_code=response.status_code,
                message=response.text or "Unknown error",
                method=method,
                path=path,
            )

        return FossaApiError(
            status_code=response.status_code,
            message=error_data.get("message", "Unknown error"),
            error_name=error_data.get("name"),
            fossa_code=error_data.get("code"),
            reference_uuid=error_data.get("uuid"),
            method=method,
            path=path,
        )

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
