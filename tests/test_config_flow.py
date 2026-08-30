"""Tests for the ha_smg_emh_casa config flow."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
import voluptuous as vol
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.data_entry_flow import FlowResultType, InvalidData
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from custom_components.ha_smg_emh_casa.api import (
    EMHCASAApiClientAuthenticationError,
    EMHCASAApiClientCommunicationError,
    EMHCASAApiClientError,
)
from custom_components.ha_smg_emh_casa.const import DOMAIN

from .const import MOCK_CONFIG, MOCK_GATEWAY_HOST, MOCK_GATEWAY_ID

ZEROCONF_DISCOVERY = ZeroconfServiceInfo(
    ip_address=IPv4Address(MOCK_GATEWAY_HOST),
    ip_addresses=[IPv4Address(MOCK_GATEWAY_HOST)],
    port=443,
    hostname="smgw.local.",
    type="_http._tcp.local.",
    name="smgw consumerinterface._http._tcp.local.",
    properties={},
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant_custom_component.common import MockConfigEntry


async def test_user_step_shows_form(hass: HomeAssistant) -> None:
    """The user step should present the credentials form."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "user"},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"


@pytest.mark.usefixtures("mock_async_get_data")
async def test_user_step_creates_entry(
    hass: HomeAssistant,
) -> None:
    """A valid submission should create a config entry."""
    with patch(
        "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
        new=AsyncMock(return_value=MOCK_GATEWAY_ID),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "user"},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input=MOCK_CONFIG,
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == MOCK_GATEWAY_ID
    assert result["data"] == {**MOCK_CONFIG, "gateway_id": MOCK_GATEWAY_ID}

    config_entry = hass.config_entries.async_entries(DOMAIN)[0]
    assert config_entry.unique_id == MOCK_GATEWAY_ID


async def test_user_step_requires_host(hass: HomeAssistant) -> None:
    """Manual setup should require the host field."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "user"},
    )

    with pytest.raises(InvalidData):
        await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                key: value for key, value in MOCK_CONFIG.items() if key != CONF_HOST
            },
        )


async def test_user_step_auth_error(hass: HomeAssistant) -> None:
    """Authentication failures should stay on the form."""
    with (
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_data",
            new=AsyncMock(
                side_effect=EMHCASAApiClientAuthenticationError(
                    "Invalid credentials",
                ),
            ),
        ),
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "user"},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input=MOCK_CONFIG,
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "auth"}


@pytest.mark.usefixtures("mock_async_get_data")
async def test_zeroconf_step_creates_entry(
    hass: HomeAssistant,
) -> None:
    """A zeroconf discovery should seed the gateway host."""
    with patch(
        "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
        new=AsyncMock(return_value=MOCK_GATEWAY_ID),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "zeroconf"},
            data=ZEROCONF_DISCOVERY,
        )

        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "user"

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={
                key: value for key, value in MOCK_CONFIG.items() if key != CONF_HOST
            },
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_HOST] == MOCK_GATEWAY_HOST
    assert result["data"]["gateway_id"] == MOCK_GATEWAY_ID


@pytest.mark.usefixtures("mock_async_get_data")
async def test_user_step_falls_back_to_host_when_gateway_id_missing(
    hass: HomeAssistant,
) -> None:
    """Manual setup should still succeed without a Digest realm."""
    with patch(
        "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
        new=AsyncMock(return_value=None),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "user"},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input=MOCK_CONFIG,
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == MOCK_CONFIG

    config_entry = hass.config_entries.async_entries(DOMAIN)[0]
    assert config_entry.unique_id == "192-0-2-25"


async def test_reauth_form_uses_effective_settings_and_clears_password(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Reauth should prefill effective settings but not the stored password."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={
            CONF_HOST: "198.51.100.20",
            CONF_USERNAME: "updated-user@example.com",
            CONF_PASSWORD: "stored-option-password",
            CONF_SCAN_INTERVAL: 45,
        },
    )

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={
            "source": "reauth",
            "entry_id": mock_config_entry.entry_id,
            "unique_id": mock_config_entry.unique_id,
        },
        data=mock_config_entry.data,
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"
    with pytest.raises(vol.Invalid):
        result["data_schema"]({})
    assert result["data_schema"]({CONF_PASSWORD: "replacement-password"}) == {
        CONF_HOST: "198.51.100.20",
        CONF_USERNAME: "updated-user@example.com",
        CONF_PASSWORD: "replacement-password",
        CONF_SCAN_INTERVAL: 45,
    }


@pytest.mark.usefixtures("mock_async_get_data")
async def test_reauth_updates_options_and_reloads(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Valid reauth settings should be merged into options and reloaded."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={"future_option": "preserved"},
    )
    updated_config = {
        CONF_HOST: "198.51.100.20",
        CONF_USERNAME: "updated-user@example.com",
        CONF_PASSWORD: "replacement-password",
        CONF_SCAN_INTERVAL: 45,
    }

    with (
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch.object(
            hass.config_entries,
            "async_schedule_reload",
        ) as mock_schedule_reload,
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={
                "source": "reauth",
                "entry_id": mock_config_entry.entry_id,
                "unique_id": mock_config_entry.unique_id,
            },
            data=mock_config_entry.data,
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input=updated_config,
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert mock_config_entry.options == {
        "future_option": "preserved",
        **updated_config,
    }
    mock_schedule_reload.assert_called_once_with(mock_config_entry.entry_id)


@pytest.mark.usefixtures("mock_async_get_data")
async def test_reauth_allows_missing_gateway_id(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Reauth should retain the existing identity if no gateway ID is available."""
    mock_config_entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
            new=AsyncMock(return_value=None),
        ),
        patch.object(hass.config_entries, "async_schedule_reload"),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={
                "source": "reauth",
                "entry_id": mock_config_entry.entry_id,
                "unique_id": mock_config_entry.unique_id,
            },
            data=mock_config_entry.data,
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={**MOCK_CONFIG, CONF_PASSWORD: "replacement-password"},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert mock_config_entry.unique_id == MOCK_GATEWAY_ID


@pytest.mark.usefixtures("mock_async_get_data")
async def test_reauth_rejects_different_gateway(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Reauth should not repoint an entry to a different gateway."""
    mock_config_entry.add_to_hass(hass)
    original_options = dict(mock_config_entry.options)

    with patch(
        "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
        new=AsyncMock(return_value="different-gateway"),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={
                "source": "reauth",
                "entry_id": mock_config_entry.entry_id,
                "unique_id": mock_config_entry.unique_id,
            },
            data=mock_config_entry.data,
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={**MOCK_CONFIG, CONF_PASSWORD: "replacement-password"},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "wrong_gateway"
    assert mock_config_entry.options == original_options


@pytest.mark.parametrize(
    ("exception", "expected_error"),
    [
        (EMHCASAApiClientAuthenticationError("Invalid credentials"), "auth"),
        (EMHCASAApiClientCommunicationError("Cannot connect"), "connection"),
        (EMHCASAApiClientError("Unexpected response"), "unknown"),
    ],
)
async def test_reauth_validation_error_stays_on_form(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    exception: EMHCASAApiClientError,
    expected_error: str,
) -> None:
    """Reauth validation errors should not modify the config entry."""
    mock_config_entry.add_to_hass(hass)
    original_options = dict(mock_config_entry.options)

    with (
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_data",
            new=AsyncMock(side_effect=exception),
        ),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={
                "source": "reauth",
                "entry_id": mock_config_entry.entry_id,
                "unique_id": mock_config_entry.unique_id,
            },
            data=mock_config_entry.data,
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={**MOCK_CONFIG, CONF_PASSWORD: "replacement-password"},
        )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"
    assert result["errors"] == {"base": expected_error}
    assert mock_config_entry.options == original_options
    with pytest.raises(vol.Invalid):
        result["data_schema"]({})


@pytest.mark.usefixtures("mock_async_get_data")
async def test_options_flow_updates_full_configuration(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """The options flow should allow changing the full configuration."""
    mock_config_entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch.object(
            hass.config_entries,
            "async_schedule_reload",
        ) as mock_schedule_reload,
    ):
        result = await hass.config_entries.options.async_init(
            mock_config_entry.entry_id,
        )

        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "init"

        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            user_input={
                CONF_HOST: "198.51.100.20",
                CONF_USERNAME: "updated-user@example.com",
                CONF_PASSWORD: "even-more-secret",
                CONF_SCAN_INTERVAL: 45,
            },
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.options == {
        CONF_HOST: "198.51.100.20",
        CONF_USERNAME: "updated-user@example.com",
        CONF_PASSWORD: "even-more-secret",
        CONF_SCAN_INTERVAL: 45,
    }
    mock_schedule_reload.assert_called_once_with(mock_config_entry.entry_id)


async def test_options_flow_auth_error_stays_on_form(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Invalid options credentials should keep the user on the form."""
    mock_config_entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_data",
            new=AsyncMock(
                side_effect=EMHCASAApiClientAuthenticationError(
                    "Invalid credentials",
                ),
            ),
        ),
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_gateway_id",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
    ):
        result = await hass.config_entries.options.async_init(
            mock_config_entry.entry_id,
        )
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            user_input={
                CONF_HOST: "198.51.100.20",
                CONF_USERNAME: "updated-user@example.com",
                CONF_PASSWORD: "even-more-secret",
                CONF_SCAN_INTERVAL: 45,
            },
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "auth"}
