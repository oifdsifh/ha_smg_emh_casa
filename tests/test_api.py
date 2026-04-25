"""Tests for the EMH CASA API client."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from custom_components.ha_smg_emh_casa.api import (
    METER_REQUEST_DELAY,
    REQUEST_RETRY_BASE_DELAY,
    EMHCASAApiClientCommunicationError,
    EMHCASAClient,
)

from .const import MOCK_CONFIG, MOCK_GATEWAY_ID

RETRY_SUCCESS_ATTEMPT = 3
CONNECT_ERROR_MESSAGE = "boom"


async def test_async_get_gateway_id_reads_digest_realm() -> None:
    """The gateway identifier should come from the Digest auth challenge."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": (
                    f'Digest realm="{MOCK_GATEWAY_ID}", '
                    'nonce="abc", algorithm=SHA-256, qop="auth"'
                )
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
    ) as http_client:
        client = EMHCASAClient(
            host="192.0.2.25",
            username="user",
            password=MOCK_CONFIG["password"],
            client=http_client,
        )

        assert await client.async_get_gateway_id() == MOCK_GATEWAY_ID


async def test_async_get_gateway_id_returns_none_without_digest_realm() -> None:
    """Missing Digest metadata should not break setup."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="login"'})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
    ) as http_client:
        client = EMHCASAClient(
            host="192.0.2.25",
            username="user",
            password=MOCK_CONFIG["password"],
            client=http_client,
        )

        assert await client.async_get_gateway_id() is None


async def test_async_get_data_fetches_meter_payloads_sequentially() -> None:
    """Meter payload requests should not overlap."""
    concurrent_requests = 0
    max_concurrent_requests = 0
    payloads = {
        "meter-a": {"value": 1},
        "meter-b": {"value": 2},
    }

    async def mock_get_meter_data(meter_id: str) -> dict:
        nonlocal concurrent_requests, max_concurrent_requests
        concurrent_requests += 1
        max_concurrent_requests = max(max_concurrent_requests, concurrent_requests)
        await asyncio.sleep(0)
        concurrent_requests -= 1
        return payloads[meter_id]

    async with httpx.AsyncClient() as http_client:
        client = EMHCASAClient(
            host="192.0.2.25",
            username="user",
            password=MOCK_CONFIG["password"],
            client=http_client,
        )

        with (
            patch.object(
                client,
                "async_get_meters",
                AsyncMock(return_value=list(payloads)),
            ),
            patch.object(client, "async_get_meter_data", mock_get_meter_data),
        ):
            assert await client.async_get_data() == payloads

    assert max_concurrent_requests == 1


async def test_async_get_data_pauses_between_meter_requests() -> None:
    """A short delay should be inserted between sequential meter requests."""
    meter_ids = ["meter-a", "meter-b", "meter-c"]
    sleep_calls: list[float] = []

    async def mock_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    async with httpx.AsyncClient() as http_client:
        client = EMHCASAClient(
            host="192.0.2.25",
            username="user",
            password=MOCK_CONFIG["password"],
            client=http_client,
        )

        with (
            patch.object(
                client,
                "async_get_meters",
                AsyncMock(return_value=meter_ids),
            ),
            patch.object(
                client,
                "async_get_meter_data",
                AsyncMock(side_effect=[{"value": 1}, {"value": 2}, {"value": 3}]),
            ),
            patch("custom_components.ha_smg_emh_casa.api.asyncio.sleep", mock_sleep),
        ):
            assert await client.async_get_data() == {
                "meter-a": {"value": 1},
                "meter-b": {"value": 2},
                "meter-c": {"value": 3},
            }

    assert sleep_calls == [METER_REQUEST_DELAY, METER_REQUEST_DELAY]


async def test_api_wrapper_uses_gentler_retry_backoff() -> None:
    """Transport retries should use the configured backoff delay."""
    sleep_calls: list[float] = []
    attempts = 0

    async def mock_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < RETRY_SUCCESS_ATTEMPT:
            raise httpx.ConnectError(CONNECT_ERROR_MESSAGE)

        return httpx.Response(200, json=["meter-a"])

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
    ) as http_client:
        client = EMHCASAClient(
            host="192.0.2.25",
            username="user",
            password=MOCK_CONFIG["password"],
            client=http_client,
        )

        with patch("custom_components.ha_smg_emh_casa.api.asyncio.sleep", mock_sleep):
            assert await client.async_get_meters() == ["meter-a"]

    assert sleep_calls == [REQUEST_RETRY_BASE_DELAY, REQUEST_RETRY_BASE_DELAY * 2]


async def test_api_wrapper_uses_httpx_timeout_errors() -> None:
    """HTTPX timeout exceptions should surface as communication errors."""

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(CONNECT_ERROR_MESSAGE)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
    ) as http_client:
        client = EMHCASAClient(
            host="192.0.2.25",
            username="user",
            password=MOCK_CONFIG["password"],
            client=http_client,
        )

        with pytest.raises(EMHCASAApiClientCommunicationError) as err:
            await client.async_get_meters()

    assert "Timeout error fetching information" in str(err.value)
