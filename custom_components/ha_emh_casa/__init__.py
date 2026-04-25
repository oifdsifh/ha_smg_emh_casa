"""
Custom integration to integrate ha_smg_emh_casa with Home Assistant.

For more details about this integration, please refer to
https://github.com/oifdsifh/ha_smg_emh_casa
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    Platform,
)
from homeassistant.helpers.httpx_client import create_async_httpx_client
from homeassistant.loader import async_get_loaded_integration

from .api import EMHCASAClient
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN, LOGGER
from .coordinator import EMHCASADataUpdateCoordinator
from .data import EMHCASAData

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .data import EMHCASAConfigEntry

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
]


# https://developers.home-assistant.io/docs/config_entries_index/#setting-up-an-entry
async def async_setup_entry(
    hass: HomeAssistant,
    entry: EMHCASAConfigEntry,
) -> bool:
    """Set up this integration using UI."""
    host = entry.options.get(CONF_HOST, entry.data[CONF_HOST])
    username = entry.options.get(CONF_USERNAME, entry.data[CONF_USERNAME])
    password = entry.options.get(CONF_PASSWORD, entry.data[CONF_PASSWORD])
    scan_interval_seconds = entry.options.get(
        CONF_SCAN_INTERVAL,
        entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
    )
    http_client = create_async_httpx_client(
        hass,
        verify_ssl=False,
        timeout=20,
        headers={"Connection": "close"},
    )
    coordinator = EMHCASADataUpdateCoordinator(
        hass=hass,
        logger=LOGGER,
        name=DOMAIN,
        update_interval=timedelta(seconds=scan_interval_seconds),
    )
    coordinator.config_entry = entry
    entry.runtime_data = EMHCASAData(
        client=EMHCASAClient(
            host=host,
            username=username,
            password=password,
            client=http_client,
        ),
        integration=async_get_loaded_integration(hass, entry.domain),
        coordinator=coordinator,
    )

    # https://developers.home-assistant.io/docs/integration_fetching_data#coordinated-single-api-poll-for-data-for-all-entities
    await coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    return True


async def async_unload_entry(
    hass: HomeAssistant,
    entry: EMHCASAConfigEntry,
) -> bool:
    """Handle removal of an entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_reload_entry(
    hass: HomeAssistant,
    entry: EMHCASAConfigEntry,
) -> None:
    """Reload config entry."""
    await hass.config_entries.async_reload(entry.entry_id)
