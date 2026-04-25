"""Fixtures for ha_smg_emh_casa tests."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from custom_components.ha_smg_emh_casa.const import DOMAIN
from pytest_homeassistant_custom_component.common import MockConfigEntry

from .const import MOCK_API_DATA, MOCK_CONFIG, MOCK_GATEWAY_ID

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Enable loading integrations from the local custom_components folder."""


@pytest.fixture(name="mock_config_entry")
def mock_config_entry_fixture() -> MockConfigEntry:
    """Return a mocked config entry."""
    return MockConfigEntry(
        domain=DOMAIN,
        title=MOCK_CONFIG["username"],
        data={**MOCK_CONFIG, "gateway_id": MOCK_GATEWAY_ID},
    )


@pytest.fixture
def mock_async_get_data() -> Generator[AsyncMock]:
    """Mock successful data retrieval for tests that exercise the integration."""
    with patch(
        "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_data",
        new=AsyncMock(return_value=MOCK_API_DATA),
    ) as mock_async_get_data:
        yield mock_async_get_data
