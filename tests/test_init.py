"""Tests for integration setup."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import ANY, AsyncMock, patch

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ha_smg_emh_casa import async_migrate_entry
from custom_components.ha_smg_emh_casa.api import (
    EMHCASAApiClientAuthenticationError,
    EMHCASAClient,
)
from custom_components.ha_smg_emh_casa.const import (
    CONF_TLS_CERTIFICATE,
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    CONFIG_ENTRY_MINOR_VERSION,
    DOMAIN,
    ISSUE_CERTIFICATE_CHANGED,
    ISSUE_CERTIFICATE_INVALID,
    ISSUE_HTTPS_MIGRATION_FAILED,
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODE_TRUSTED_CERTIFICATE,
)
from custom_components.ha_smg_emh_casa.tls import (
    EMHCASATlsConnectionError,
    EMHCASATlsVerificationError,
    GatewayCertificate,
)

from .const import MOCK_API_DATA, MOCK_CONFIG, MOCK_GATEWAY_ID, MOCK_METER_ID

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

NOW = datetime.now(UTC)
OLD_CERTIFICATE = GatewayCertificate(
    pem="old certificate",
    fingerprint="12" * 32,
    not_valid_before=NOW - timedelta(days=1),
    not_valid_after=NOW + timedelta(days=30),
)
NEW_CERTIFICATE = GatewayCertificate(
    pem="new certificate",
    fingerprint="34" * 32,
    not_valid_before=NOW - timedelta(days=1),
    not_valid_after=NOW + timedelta(days=30),
)


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

    mock_config_entry.runtime_data.coordinator.async_set_updated_data(
        {
            MOCK_METER_ID: {
                **MOCK_API_DATA[MOCK_METER_ID],
                "capture_time": "2026-04-03T18:15:43+02:00",
                "values": [
                    {
                        **MOCK_API_DATA[MOCK_METER_ID]["values"][0],
                        "value": "16826472",
                    },
                    MOCK_API_DATA[MOCK_METER_ID]["values"][1],
                ],
            }
        }
    )
    await hass.async_block_till_done()

    import_state = hass.states.get(f"sensor.{MOCK_METER_ID}_total_import")
    assert import_state is not None
    assert import_state.state == "1682.6472"
    assert import_state.attributes["capture_time"] == "2026-04-03T18:15:43+02:00"

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

    with patch(
        "custom_components.ha_smg_emh_casa.EMHCASAClient",
        wraps=EMHCASAClient,
    ) as client_class:
        assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    client_class.assert_called_once_with(
        host="198.51.100.20",
        username="updated-user@example.com",
        password=updated_value,
        client=ANY,
    )
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


async def test_auth_failure_starts_reauth_flow(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """An authentication failure should start an actionable reauth flow."""
    mock_config_entry.add_to_hass(hass)

    with patch(
        "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_data",
        new=AsyncMock(
            side_effect=EMHCASAApiClientAuthenticationError("Invalid credentials"),
        ),
    ):
        assert not await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.SETUP_ERROR
    reauth_flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert len(reauth_flows) == 1
    reauth_flow = reauth_flows[0]
    context = reauth_flow.get("context", {})
    assert context.get("source") == "reauth"
    assert context.get("entry_id") == mock_config_entry.entry_id
    assert reauth_flow.get("step_id") == "reauth_confirm"


async def test_migration_uses_trusted_mode_when_normal_verification_succeeds(
    hass: HomeAssistant,
) -> None:
    """Existing entries should prefer normal certificate verification."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Legacy gateway",
        data={key: value for key, value in MOCK_CONFIG.items() if key != CONF_TLS_MODE},
        unique_id=MOCK_GATEWAY_ID,
        minor_version=1,
    )
    entry.add_to_hass(hass)
    ir.async_create_issue(
        hass,
        DOMAIN,
        f"{ISSUE_HTTPS_MIGRATION_FAILED}_{entry.entry_id}",
        is_fixable=False,
        is_persistent=True,
        severity=ir.IssueSeverity.ERROR,
        translation_key=ISSUE_HTTPS_MIGRATION_FAILED,
        translation_placeholders={"entry_title": entry.title},
    )

    with (
        patch(
            "custom_components.ha_smg_emh_casa.async_test_trusted_certificate",
            new=AsyncMock(),
        ) as trusted_probe,
        patch(
            "custom_components.ha_smg_emh_casa.persistent_notification.async_create"
        ) as create_notification,
    ):
        assert await async_migrate_entry(hass, entry)

    assert entry.minor_version == CONFIG_ENTRY_MINOR_VERSION
    assert entry.data[CONF_TLS_MODE] == TLS_MODE_TRUSTED_CERTIFICATE
    assert CONF_TLS_CERTIFICATE not in entry.data
    trusted_probe.assert_awaited_once_with(MOCK_CONFIG[CONF_HOST])
    create_notification.assert_called_once()
    assert (
        ir.async_get(hass).async_get_issue(
            DOMAIN,
            f"{ISSUE_HTTPS_MIGRATION_FAILED}_{entry.entry_id}",
        )
        is None
    )


async def test_migration_falls_back_to_pinning_without_credentials(
    hass: HomeAssistant,
) -> None:
    """An untrusted existing endpoint should be pinned before authentication."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Legacy gateway",
        data={key: value for key, value in MOCK_CONFIG.items() if key != CONF_TLS_MODE},
        unique_id=MOCK_GATEWAY_ID,
        minor_version=1,
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.ha_smg_emh_casa.async_test_trusted_certificate",
            new=AsyncMock(side_effect=EMHCASATlsVerificationError("self-signed")),
        ),
        patch(
            "custom_components.ha_smg_emh_casa.async_probe_certificate",
            new=AsyncMock(return_value=OLD_CERTIFICATE),
        ) as certificate_probe,
    ):
        assert await async_migrate_entry(hass, entry)

    assert entry.data[CONF_TLS_MODE] == TLS_MODE_PINNED_CERTIFICATE
    assert entry.data[CONF_TLS_CERTIFICATE] == OLD_CERTIFICATE.pem
    assert entry.data[CONF_TLS_FINGERPRINT] == OLD_CERTIFICATE.fingerprint
    certificate_probe.assert_awaited_once_with(MOCK_CONFIG[CONF_HOST])


async def test_migration_upgrades_explicit_http_address(hass: HomeAssistant) -> None:
    """A legacy HTTP URL should be normalized when its HTTPS endpoint works."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Legacy gateway",
        data={
            **{
                key: value for key, value in MOCK_CONFIG.items() if key != CONF_TLS_MODE
            },
            CONF_HOST: "http://192.0.2.25",
        },
        unique_id=MOCK_GATEWAY_ID,
        minor_version=1,
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.ha_smg_emh_casa.async_test_trusted_certificate",
        new=AsyncMock(),
    ):
        assert await async_migrate_entry(hass, entry)

    assert entry.data[CONF_HOST] == MOCK_CONFIG[CONF_HOST]
    assert entry.data[CONF_TLS_MODE] == TLS_MODE_TRUSTED_CERTIFICATE


async def test_migration_failure_creates_https_repair(hass: HomeAssistant) -> None:
    """Migration should fail without sending credentials when HTTPS is unavailable."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Legacy gateway",
        data={
            **{
                key: value for key, value in MOCK_CONFIG.items() if key != CONF_TLS_MODE
            },
            CONF_HOST: "http://192.0.2.25",
        },
        unique_id=MOCK_GATEWAY_ID,
        minor_version=1,
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.ha_smg_emh_casa.async_test_trusted_certificate",
        new=AsyncMock(side_effect=EMHCASATlsConnectionError("offline")),
    ):
        assert not await async_migrate_entry(hass, entry)

    issue = ir.async_get(hass).async_get_issue(
        DOMAIN,
        f"{ISSUE_HTTPS_MIGRATION_FAILED}_{entry.entry_id}",
    )
    assert issue is not None
    assert issue.is_persistent
    assert entry.data[CONF_HOST] == "http://192.0.2.25"
    assert entry.minor_version == 1


async def test_changed_pinned_certificate_creates_fixable_repair(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """A rejected replacement certificate should create an actionable Repair."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        data={
            **dict(mock_config_entry.data),
            CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
            CONF_TLS_CERTIFICATE: OLD_CERTIFICATE.pem,
            CONF_TLS_FINGERPRINT: OLD_CERTIFICATE.fingerprint,
        },
    )
    http_client = AsyncMock()
    get_data = AsyncMock()

    with (
        patch(
            "custom_components.ha_smg_emh_casa.create_httpx_client",
            return_value=http_client,
        ),
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_data",
            new=get_data,
        ),
        patch(
            "custom_components.ha_smg_emh_casa.coordinator.async_probe_certificate",
            new=AsyncMock(return_value=NEW_CERTIFICATE),
        ),
    ):
        assert not await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    issue = ir.async_get(hass).async_get_issue(
        DOMAIN,
        f"{ISSUE_CERTIFICATE_CHANGED}_{mock_config_entry.entry_id}",
    )
    assert issue is not None
    assert issue.is_fixable
    assert issue.data == {
        "entry_id": mock_config_entry.entry_id,
        "new_fingerprint": NEW_CERTIFICATE.fingerprint,
    }
    get_data.assert_not_awaited()
    http_client.aclose.assert_awaited_once()


async def test_unchanged_pinned_certificate_allows_authenticated_poll(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_async_get_data: AsyncMock,
) -> None:
    """The exact valid remembered certificate should allow data retrieval."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        data={
            **dict(mock_config_entry.data),
            CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
            CONF_TLS_CERTIFICATE: OLD_CERTIFICATE.pem,
            CONF_TLS_FINGERPRINT: OLD_CERTIFICATE.fingerprint,
        },
    )
    http_client = AsyncMock()

    with (
        patch(
            "custom_components.ha_smg_emh_casa.create_httpx_client",
            return_value=http_client,
        ),
        patch(
            "custom_components.ha_smg_emh_casa.coordinator.async_probe_certificate",
            new=AsyncMock(return_value=OLD_CERTIFICATE),
        ) as probe,
    ):
        assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    probe.assert_awaited_once_with(MOCK_CONFIG[CONF_HOST])
    mock_async_get_data.assert_awaited_once()

    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    http_client.aclose.assert_awaited_once()


async def test_expired_unchanged_pinned_certificate_creates_nonfixable_repair(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """An expired remembered certificate must be renewed, not reaccepted."""
    expired = GatewayCertificate(
        pem=OLD_CERTIFICATE.pem,
        fingerprint=OLD_CERTIFICATE.fingerprint,
        not_valid_before=NOW - timedelta(days=30),
        not_valid_after=NOW - timedelta(days=1),
    )
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        data={
            **dict(mock_config_entry.data),
            CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
            CONF_TLS_CERTIFICATE: OLD_CERTIFICATE.pem,
            CONF_TLS_FINGERPRINT: OLD_CERTIFICATE.fingerprint,
        },
    )
    http_client = AsyncMock()
    get_data = AsyncMock()

    with (
        patch(
            "custom_components.ha_smg_emh_casa.create_httpx_client",
            return_value=http_client,
        ),
        patch(
            "custom_components.ha_smg_emh_casa.api.EMHCASAClient.async_get_data",
            new=get_data,
        ),
        patch(
            "custom_components.ha_smg_emh_casa.coordinator.async_probe_certificate",
            new=AsyncMock(return_value=expired),
        ),
    ):
        assert not await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    issue = ir.async_get(hass).async_get_issue(
        DOMAIN,
        f"{ISSUE_CERTIFICATE_INVALID}_{mock_config_entry.entry_id}",
    )
    assert issue is not None
    assert not issue.is_fixable
    assert issue.translation_placeholders is not None
    assert issue.translation_placeholders["reason"] == "expired"
    assert issue.data == {"entry_id": mock_config_entry.entry_id}
    get_data.assert_not_awaited()
    http_client.aclose.assert_awaited_once()
