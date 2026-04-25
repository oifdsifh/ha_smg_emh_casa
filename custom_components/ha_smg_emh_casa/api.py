"""API client for the EMH CASA gateway."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any
from urllib.parse import urlsplit
from urllib.request import parse_http_list, parse_keqv_list

import httpx

REQUEST_RETRIES = 3
REQUEST_RETRY_BASE_DELAY = 1.0
METER_REQUEST_DELAY = 0.5


class EMHCASAApiClientError(Exception):
    """Exception to indicate a general API error."""


class EMHCASAApiClientCommunicationError(
    EMHCASAApiClientError,
):
    """Exception to indicate a communication error."""


class EMHCASAApiClientAuthenticationError(
    EMHCASAApiClientError,
):
    """Exception to indicate an authentication error."""


def _build_exception_message(prefix: str, exception: Exception) -> str:
    """Build a useful log/error message from an exception."""
    details = str(exception).strip()
    if not details:
        details = repr(exception)

    cause = exception.__cause__
    if cause is not None:
        cause_details = str(cause).strip() or repr(cause)
        details = f"{details} (caused by {cause_details})"

    return f"{prefix} - {exception.__class__.__name__}: {details}"


def _verify_response_or_raise(response: httpx.Response) -> None:
    """Verify that the response is valid."""
    if response.status_code in (401, 403):
        msg = "Invalid credentials"
        raise EMHCASAApiClientAuthenticationError(
            msg,
        )
    response.raise_for_status()


def _extract_digest_realm(www_authenticate: str) -> str | None:
    """Extract the Digest realm from a WWW-Authenticate challenge."""
    if not www_authenticate.lower().startswith("digest "):
        return None

    challenge = www_authenticate[7:].strip()
    params = parse_keqv_list(parse_http_list(challenge))
    realm = params.get("realm")
    return str(realm) if realm else None


class EMHCASAClient:
    """Client for the EMH CASA gateway API."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        client: httpx.AsyncClient,
    ) -> None:
        """Initialize the client."""
        self._host = host
        self._username = username
        self._password = password
        self._client = client
        self._auth = httpx.DigestAuth(username=username, password=password)

    async def async_close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def async_get_meters(self) -> list[str]:
        """Fetch the list of meters connected to the gateway."""
        response = await self._api_wrapper(
            method="get",
            path="/json/metering/origin/",
        )
        if not isinstance(response, list):
            msg = "Unexpected meter discovery response"
            raise EMHCASAApiClientError(msg)

        return [str(meter_id) for meter_id in response]

    async def async_get_meter_data(self, meter_id: str) -> dict[str, Any]:
        """Fetch the extended readings for a single meter."""
        response = await self._api_wrapper(
            method="get",
            path=f"/json/metering/origin/{meter_id}/extended",
        )
        if not isinstance(response, dict):
            msg = f"Unexpected response for meter {meter_id}"
            raise EMHCASAApiClientError(msg)

        return response

    async def async_get_data(self) -> dict[str, dict[str, Any]]:
        """Fetch all connected meters and their latest readings."""
        meter_ids = await self.async_get_meters()
        meter_payloads: dict[str, dict[str, Any]] = {}

        # The gateway appears to be sensitive to overlapping TLS connections,
        # so fetch each meter one at a time.
        for index, meter_id in enumerate(meter_ids):
            meter_payloads[meter_id] = await self.async_get_meter_data(meter_id)
            if index < len(meter_ids) - 1:
                await asyncio.sleep(METER_REQUEST_DELAY)

        return meter_payloads

    async def async_get_gateway_id(self) -> str | None:
        """Fetch the gateway identifier from the Digest authentication realm."""
        response = await self._request_without_auth(
            method="get",
            path="/json/metering/origin/",
        )
        for header_value in response.headers.get_list("WWW-Authenticate"):
            if realm := _extract_digest_realm(header_value):
                return realm

        return None

    def _build_url(self, path: str) -> str:
        """Build a URL relative to the configured host."""
        if "://" in self._host:
            base_url = self._host
        else:
            base_url = f"https://{self._format_host(self._host)}"

        return f"{base_url.rstrip('/')}{path}"

    @staticmethod
    def _format_host(host: str) -> str:
        """Wrap raw IPv6 hosts for URL usage."""
        if host.startswith("["):
            return host

        parsed_host = urlsplit(f"//{host}").hostname
        if parsed_host is not None and ":" in parsed_host:
            return f"[{host}]"

        return host

    async def _api_wrapper(
        self,
        method: str,
        path: str,
        data: dict | None = None,
        headers: dict | None = None,
    ) -> Any:
        """Perform a single API request."""
        last_exception: Exception | None = None
        url = self._build_url(path)

        for attempt in range(REQUEST_RETRIES):
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=data,
                    auth=self._auth,
                )
                _verify_response_or_raise(response)
                return response.json()

            except httpx.TimeoutException as exception:
                msg = _build_exception_message(
                    "Timeout error fetching information",
                    exception,
                )
                raise EMHCASAApiClientCommunicationError(
                    msg,
                ) from exception
            except httpx.HTTPStatusError as exception:
                response = exception.response
                response_text = response.text.strip()
                if response_text:
                    response_text = f": {response_text[:200]}"

                msg = (
                    f"HTTP error fetching information - "
                    f"{response.status_code} {response.reason_phrase}"
                    f"{response_text}"
                )
                raise EMHCASAApiClientCommunicationError(
                    msg,
                ) from exception
            except (httpx.RequestError, socket.gaierror) as exception:
                last_exception = exception
                if attempt < REQUEST_RETRIES - 1:
                    await asyncio.sleep(REQUEST_RETRY_BASE_DELAY * (attempt + 1))
                    continue

                break
            except json.JSONDecodeError as exception:
                msg = _build_exception_message(
                    "Invalid JSON returned by gateway",
                    exception,
                )
                raise EMHCASAApiClientError(
                    msg,
                ) from exception
            except EMHCASAApiClientError:
                raise
            except Exception as exception:  # pylint: disable=broad-except
                msg = _build_exception_message(
                    "Something really wrong happened",
                    exception,
                )
                raise EMHCASAApiClientError(
                    msg,
                ) from exception

        msg = _build_exception_message(
            "Error fetching information",
            last_exception or Exception("Unknown request failure"),
        )
        raise EMHCASAApiClientCommunicationError(msg)

    async def _request_without_auth(
        self,
        method: str,
        path: str,
    ) -> httpx.Response:
        """Perform an unauthenticated request used to inspect auth challenges."""
        last_exception: Exception | None = None
        url = self._build_url(path)

        try:
            return await self._client.request(
                method=method,
                url=url,
            )
        except httpx.TimeoutException as exception:
            msg = _build_exception_message(
                "Timeout error fetching information",
                exception,
            )
            raise EMHCASAApiClientCommunicationError(
                msg,
            ) from exception
        except (httpx.RequestError, socket.gaierror) as exception:
            last_exception = exception

        msg = _build_exception_message(
            "Error fetching information",
            last_exception or Exception("Unknown request failure"),
        )
        raise EMHCASAApiClientCommunicationError(msg)
