"""
Custom integration to integrate ha_smg_emh_casa with Home Assistant.

For more details about this integration, please refer to
https://github.com/oifdsifh/ha_smg_emh_casa
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from homeassistant.components import persistent_notification
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    Platform,
)
from homeassistant.exceptions import ConfigEntryError
from homeassistant.helpers import issue_registry as ir
from homeassistant.loader import async_get_loaded_integration

from .api import EMHCASAClient
from .const import (
    CONF_TLS_CERTIFICATE,
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    CONFIG_ENTRY_MINOR_VERSION,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    ISSUE_CERTIFICATE_CHANGED,
    ISSUE_CERTIFICATE_INVALID,
    ISSUE_HTTPS_MIGRATION_FAILED,
    LOGGER,
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODE_TRUSTED_CERTIFICATE,
)
from .coordinator import EMHCASADataUpdateCoordinator
from .data import EMHCASAData
from .tls import (
    EMHCASATlsError,
    EMHCASATlsVerificationError,
    async_probe_certificate,
    async_test_trusted_certificate,
    create_httpx_client,
    normalize_legacy_host,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .data import EMHCASAConfigEntry

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
]


async def async_migrate_entry(
    hass: HomeAssistant,
    entry: EMHCASAConfigEntry,
) -> bool:
    """Migrate an existing entry to an explicit TLS trust mode."""
    if entry.version != 1:
        LOGGER.error("Cannot migrate config entry from version %s", entry.version)
        return False
    if entry.minor_version >= CONFIG_ENTRY_MINOR_VERSION:
        return True

    data = dict(entry.data)
    options = dict(entry.options)
    values = data | options
    try:
        host, upgraded_http = normalize_legacy_host(values[CONF_HOST])
        try:
            await async_test_trusted_certificate(host)
        except EMHCASATlsVerificationError as verification_error:
            certificate = await async_probe_certificate(host)
            if reason := certificate.validity_error:
                msg = f"Cannot pin a certificate that is {reason}"
                raise EMHCASATlsError(msg) from verification_error
            tls_values = {
                CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
                CONF_TLS_CERTIFICATE: certificate.pem,
                CONF_TLS_FINGERPRINT: certificate.fingerprint,
            }
            migration_description = (
                "The existing entry now remembers the gateway certificate. "
                "Home Assistant will stop and ask for approval if it changes."
            )
        else:
            tls_values = {CONF_TLS_MODE: TLS_MODE_TRUSTED_CERTIFICATE}
            migration_description = (
                "The existing entry now verifies the gateway certificate using "
                "Home Assistant's trusted certificate authorities and hostname checks."
            )
    except EMHCASATlsError as exception:
        LOGGER.error("Unable to migrate TLS settings: %s", exception)
        ir.async_create_issue(
            hass,
            DOMAIN,
            f"{ISSUE_HTTPS_MIGRATION_FAILED}_{entry.entry_id}",
            is_fixable=False,
            is_persistent=True,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_HTTPS_MIGRATION_FAILED,
            translation_placeholders={"entry_title": entry.title},
            data={"entry_id": entry.entry_id},
        )
        return False

    if CONF_HOST in options:
        options[CONF_HOST] = host
    else:
        data[CONF_HOST] = host
    data.update(tls_values)
    hass.config_entries.async_update_entry(
        entry,
        data=data,
        options=options,
        minor_version=CONFIG_ENTRY_MINOR_VERSION,
    )
    ir.async_delete_issue(
        hass,
        DOMAIN,
        f"{ISSUE_HTTPS_MIGRATION_FAILED}_{entry.entry_id}",
    )
    persistent_notification.async_create(
        hass,
        (
            f"{migration_description} You can change this under the EMH CASA "
            "integration options."
            + (
                " The stored HTTP address was upgraded to HTTPS."
                if upgraded_http
                else ""
            )
        ),
        title="EMH CASA TLS security updated",
        notification_id=f"{DOMAIN}_tls_migration_{entry.entry_id}",
    )
    return True


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
    tls_mode = entry.options.get(CONF_TLS_MODE, entry.data[CONF_TLS_MODE])
    certificate_pem = entry.options.get(
        CONF_TLS_CERTIFICATE,
        entry.data.get(CONF_TLS_CERTIFICATE),
    )
    try:
        http_client = create_httpx_client(tls_mode, certificate_pem)
    except EMHCASATlsError as exception:
        raise ConfigEntryError(str(exception)) from exception
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
    try:
        await coordinator.async_config_entry_first_refresh()
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except Exception:
        await entry.runtime_data.client.async_close()
        raise

    for issue_key in (ISSUE_CERTIFICATE_CHANGED, ISSUE_CERTIFICATE_INVALID):
        ir.async_delete_issue(hass, DOMAIN, f"{issue_key}_{entry.entry_id}")

    return True


async def async_unload_entry(
    hass: HomeAssistant,
    entry: EMHCASAConfigEntry,
) -> bool:
    """Handle removal of an entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.client.async_close()
    return unloaded
