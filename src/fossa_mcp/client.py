"""FOSSA API client for the MCP server."""

import asyncio
import httpx
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import quote

from .config import Settings
from .errors import FossaApiError
from .query import bool_to_str

logger = logging.getLogger(__name__)


class FossaClient:
    """Asynchronous FOSSA API client."""

    def __init__(self, settings: Settings, transport: Optional[httpx.AsyncBaseTransport] = None):
        """
        Initialize the FOSSA client.

        Args:
            settings: Application settings
            transport: Optional HTTP transport for testing
        """
        self.settings = settings

        # Create async HTTP client with configured timeout and transport
        self._client = httpx.AsyncClient(
            base_url=settings.api_base_url,
            timeout=settings.fossa_timeout_seconds,
            verify=settings.fossa_verify_tls,
            transport=transport,
            headers={
                "User-Agent": f"fossa-mcp/{__import__('fossa_mcp').__version__ or '0.1.0'}",
                "Accept": "application/json",
            }
        )

        # Add authorization header if token is provided
        if settings.fossa_api_token:
            self._client.headers["Authorization"] = f"Bearer {settings.fossa_api_token}"

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[List[Tuple[str, str]]] = None,
    ) -> Union[Dict[str, Any], List[Any]]:
        """
        Make an HTTP request and return JSON response.

        Args:
            method: HTTP method
            path: API endpoint path
            params: Query parameters

        Returns:
            Parsed JSON response

        Raises:
            FossaApiError: If the API returns an error
        """
        # Build full URL with query parameters
        url = path

        # Add query parameters if provided
        if params:
            query_string = "&".join([f"{k}={v}" for k, v in params])
            if query_string:
                url += f"?{query_string}"

        logger.info(f"FOSSA {method} {url}")

        try:
            response = await self._client.request(method, url)

            # Log the request details
            logger.info(
                f"FOSSA {method} {url} -> {response.status_code} in {response.elapsed.total_seconds() * 1000:.0f}ms"
            )

            # Handle different response status codes
            if 200 <= response.status_code < 300:
                # Success - parse JSON
                try:
                    return response.json()
                except json.JSONDecodeError:
                    raise FossaApiError(
                        status_code=response.status_code,
                        message="Invalid JSON response from FOSSA API",
                        method=method,
                        path=path
                    )
            else:
                # Error - attempt to parse FOSSA error format
                try:
                    error_data = response.json()
                    # Extract FOSSA-specific error fields
                    error_name = error_data.get("name")
                    fossa_code = error_data.get("code")
                    reference_uuid = error_data.get("uuid")

                    raise FossaApiError(
                        status_code=response.status_code,
                        message=error_data.get("message", "Unknown error"),
                        error_name=error_name,
                        fossa_code=fossa_code,
                        reference_uuid=reference_uuid,
                        method=method,
                        path=path
                    )
                except json.JSONDecodeError:
                    # If we can't parse the JSON, raise a generic error
                    raise FossaApiError(
                        status_code=response.status_code,
                        message=response.text or "Unknown error",
                        method=method,
                        path=path
                    )

        except httpx.TimeoutException:
            raise FossaApiError(
                status_code=0,
                message=f"FOSSA request timed out after {self.settings.fossa_timeout_seconds} seconds while calling {method} {path}.",
                method=method,
                path=path
            )
        except httpx.RequestError as e:
            # Handle connection errors
            raise FossaApiError(
                status_code=0,
                message=f"FOSSA request failed: {str(e)}",
                method=method,
                path=path
            )

    async def request_text(
        self,
        method: str,
        path: str,
        *,
        params: Optional[List[Tuple[str, str]]] = None,
    ) -> Tuple[str, Optional[str]]:
        """
        Make an HTTP request and return text response.

        Args:
            method: HTTP method
            path: API endpoint path
            params: Query parameters

        Returns:
            Tuple of (text_content, content_type)

        Raises:
            FossaApiError: If the API returns an error
        """
        # Build full URL with query parameters
        url = path

        # Add query parameters if provided
        if params:
            query_string = "&".join([f"{k}={v}" for k, v in params])
            if query_string:
                url += f"?{query_string}"

        logger.info(f"FOSSA {method} {url}")

        try:
            response = await self._client.request(method, url)

            # Log the request details
            logger.info(
                f"FOSSA {method} {url} -> {response.status_code} in {response.elapsed.total_seconds() * 1000:.0f}ms"
            )

            # Handle different response status codes
            if 200 <= response.status_code < 300:
                # Success - return content and content type
                return response.text, response.headers.get("content-type")
            else:
                # Error - attempt to parse FOSSA error format
                try:
                    error_data = response.json()
                    # Extract FOSSA-specific error fields
                    error_name = error_data.get("name")
                    fossa_code = error_data.get("code")
                    reference_uuid = error_data.get("uuid")

                    raise FossaApiError(
                        status_code=response.status_code,
                        message=error_data.get("message", "Unknown error"),
                        error_name=error_name,
                        fossa_code=fossa_code,
                        reference_uuid=reference_uuid,
                        method=method,
                        path=path
                    )
                except json.JSONDecodeError:
                    # If we can't parse the JSON, raise a generic error
                    raise FossaApiError(
                        status_code=response.status_code,
                        message=response.text or "Unknown error",
                        method=method,
                        path=path
                    )

        except httpx.TimeoutException:
            raise FossaApiError(
                status_code=0,
                message=f"FOSSA request timed out after {self.settings.fossa_timeout_seconds} seconds while calling {method} {path}.",
                method=method,
                path=path
            )
        except httpx.RequestError as e:
            # Handle connection errors
            raise FossaApiError(
                status_code=0,
                message=f"FOSSA request failed: {str(e)}",
                method=method,
                path=path
            )

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()