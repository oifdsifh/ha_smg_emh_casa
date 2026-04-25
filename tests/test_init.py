"""Tests for integration setup."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.helpers import device_registry as dr

from .const import MOCK_CONFIG, MOCK_METER_ID

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant_custom_component.common import MockConfigEntry


@pytest.mark.usefixtures("mock_async_get_data")
async def test_setup_and_unload_entry(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """The config entry should set up and unload cleanly."""
    mock_config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED
    assert mock_config_entry.runtime_data.coordinator.update_interval == timedelta(
        seconds=60
    )

    import_state = hass.states.get(f"sensor.{MOCK_METER_ID}_total_import")
    assert import_state is not None
    assert import_state.state == "1682.6471"
    assert import_state.attributes["device_class"] == "energy"
    assert import_state.attributes["state_class"] == "total_increasing"
    assert import_state.attributes["meter_id"] == MOCK_METER_ID

    export_state = hass.states.get(f"sensor.{MOCK_METER_ID}_total_export")
    assert export_state is not None
    assert export_state.state == "0.1271"
    assert export_state.attributes["meter_id"] == MOCK_METER_ID

    device_registry = dr.async_get(hass)
    sensor_entity = device_registry.async_get_device(
        identifiers={
            (
                mock_config_entry.domain,
                f"{mock_config_entry.entry_id}_{MOCK_METER_ID}",
            )
        }
    )
    assert sensor_entity is not None
    assert sensor_entity.serial_number == MOCK_METER_ID

    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.NOT_LOADED


@pytest.mark.usefixtures("mock_async_get_data")
async def test_setup_uses_configured_scan_interval(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """The coordinator should honor the configured scan interval."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={CONF_SCAN_INTERVAL: 45},
    )

    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.runtime_data.coordinator.update_interval == timedelta(
        seconds=45
    )


@pytest.mark.usefixtures("mock_async_get_data")
async def test_setup_uses_option_overrides_for_connection_details(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """The runtime client should use connection settings saved in options."""
    updated_value = f"{MOCK_CONFIG[CONF_PASSWORD]}-updated"

    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={
            CONF_HOST: "198.51.100.20",
            CONF_USERNAME: "updated-user@example.com",
            CONF_PASSWORD: updated_value,
            CONF_SCAN_INTERVAL: 45,
        },
    )

    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    client = mock_config_entry.runtime_data.client
    assert client._host == "198.51.100.20"  # noqa: SLF001
    assert client._username == "updated-user@example.com"  # noqa: SLF001
    assert client._password == updated_value  # noqa: SLF001
    assert mock_config_entry.runtime_data.coordinator.update_interval == timedelta(
        seconds=45
    )


@pytest.mark.usefixtures("mock_async_get_data")
async def test_setup_uses_meter_id_as_serial_number_without_gateway_id(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Meter devices should keep their own serial number without gateway metadata."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        data={
            key: value
            for key, value in mock_config_entry.data.items()
            if key != "gateway_id"
        },
        unique_id="192-0-2-25",
    )

    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    device_registry = dr.async_get(hass)
    sensor_entity = device_registry.async_get_device(
        identifiers={
            (
                mock_config_entry.domain,
                f"{mock_config_entry.entry_id}_{MOCK_METER_ID}",
            )
        }
    )
    assert sensor_entity is not None
    assert sensor_entity.serial_number == MOCK_METER_ID
