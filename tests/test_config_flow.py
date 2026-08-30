"""Tests for the EMH CASA config flow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Any, cast
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
    EMHCASAApiClientCertificateError,
    EMHCASAApiClientCommunicationError,
    EMHCASAApiClientError,
)
from custom_components.ha_smg_emh_casa.const import (
    CONF_TLS_CERTIFICATE,
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    DOMAIN,
    TLS_MODE_INSECURE,
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODE_TRUSTED_CERTIFICATE,
)
from custom_components.ha_smg_emh_casa.tls import GatewayCertificate

from .const import MOCK_CONFIG, MOCK_GATEWAY_HOST, MOCK_GATEWAY_ID

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant_custom_component.common import MockConfigEntry

NOW = datetime.now(UTC)
EXPECTED_PIN_PROBES = 2
pytestmark = pytest.mark.usefixtures("mock_async_get_data")

MOCK_CERTIFICATE = GatewayCertificate(
    pem="mock gateway certificate",
    fingerprint="12" * 32,
    not_valid_before=NOW - timedelta(days=1),
    not_valid_after=NOW + timedelta(days=365),
)
REPLACEMENT_CERTIFICATE = GatewayCertificate(
    pem="replacement gateway certificate",
    fingerprint="34" * 32,
    not_valid_before=NOW - timedelta(days=1),
    not_valid_after=NOW + timedelta(days=365),
)

ZEROCONF_DISCOVERY = ZeroconfServiceInfo(
    ip_address=IPv4Address(MOCK_GATEWAY_HOST),
    ip_addresses=[IPv4Address(MOCK_GATEWAY_HOST)],
    port=443,
    hostname="smgw.local.",
    type="_http._tcp.local.",
    name="smgw consumerinterface._http._tcp.local.",
    properties={},
)


async def _start_user_flow(
    hass: HomeAssistant,
    tls_mode: str,
) -> tuple[str, Any]:
    """Start a user flow and submit the connection settings."""
    result: Any = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "user"},
    )
    flow_id = result["flow_id"]
    result = await hass.config_entries.flow.async_configure(
        flow_id,
        user_input={CONF_HOST: MOCK_GATEWAY_HOST, CONF_TLS_MODE: tls_mode},
    )
    return flow_id, result


def _credentials(password: str = MOCK_CONFIG[CONF_PASSWORD]) -> dict:
    """Return a credential-step submission."""
    return {
        CONF_USERNAME: MOCK_CONFIG[CONF_USERNAME],
        CONF_PASSWORD: password,
        CONF_SCAN_INTERVAL: MOCK_CONFIG[CONF_SCAN_INTERVAL],
    }


async def test_user_step_shows_tls_choices(hass: HomeAssistant) -> None:
    """The first step should collect only the host and TLS trust choice."""
    result: Any = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "user"},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["data_schema"]({CONF_HOST: MOCK_GATEWAY_HOST}) == {
        CONF_HOST: MOCK_GATEWAY_HOST,
        CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
    }


async def test_pinned_setup_confirms_certificate_before_credentials(
    hass: HomeAssistant,
) -> None:
    """Pinned setup should not validate credentials before certificate approval."""
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_probe_certificate",
            new=AsyncMock(return_value=MOCK_CERTIFICATE),
        ) as probe,
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ) as validate,
    ):
        flow_id, result = await _start_user_flow(
            hass,
            TLS_MODE_PINNED_CERTIFICATE,
        )

        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "confirm_certificate"
        assert result["description_placeholders"]["fingerprint"] == (
            MOCK_CERTIFICATE.formatted_fingerprint
        )
        validate.assert_not_awaited()

        result = cast(
            "Any",
            await hass.config_entries.flow.async_configure(
                flow_id,
                user_input={},
            ),
        )
        assert result["step_id"] == "credentials"
        validate.assert_not_awaited()

        result = cast(
            "Any",
            await hass.config_entries.flow.async_configure(
                flow_id,
                user_input=_credentials(),
            ),
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == MOCK_GATEWAY_ID
    assert result["data"] == {
        **MOCK_CONFIG,
        CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
        CONF_TLS_CERTIFICATE: MOCK_CERTIFICATE.pem,
        CONF_TLS_FINGERPRINT: MOCK_CERTIFICATE.fingerprint,
        "gateway_id": MOCK_GATEWAY_ID,
    }
    assert probe.await_count == EXPECTED_PIN_PROBES
    validate.assert_awaited_once()


@pytest.mark.parametrize(
    "tls_mode",
    [TLS_MODE_TRUSTED_CERTIFICATE, TLS_MODE_INSECURE],
)
async def test_non_pinned_setup_goes_directly_to_credentials(
    hass: HomeAssistant,
    tls_mode: str,
) -> None:
    """Trusted and insecure modes should not require pin confirmation."""
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_probe_certificate",
            new=AsyncMock(),
        ) as probe,
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
    ):
        flow_id, result = await _start_user_flow(hass, tls_mode)
        assert result["step_id"] == "credentials"
        result = cast(
            "Any",
            await hass.config_entries.flow.async_configure(
                flow_id,
                user_input=_credentials(),
            ),
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_TLS_MODE] == tls_mode
    assert CONF_TLS_CERTIFICATE not in result["data"]
    probe.assert_not_awaited()


async def test_certificate_change_during_setup_requires_new_confirmation(
    hass: HomeAssistant,
) -> None:
    """A changing first-use certificate should never reach credential entry."""
    with patch(
        "custom_components.ha_smg_emh_casa.config_flow.async_probe_certificate",
        new=AsyncMock(
            side_effect=[MOCK_CERTIFICATE, REPLACEMENT_CERTIFICATE],
        ),
    ):
        flow_id, _ = await _start_user_flow(hass, TLS_MODE_PINNED_CERTIFICATE)
        result: Any = await hass.config_entries.flow.async_configure(
            flow_id,
            user_input={},
        )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "confirm_certificate"
    assert result["errors"] == {"base": "certificate_changed_during_setup"}
    assert result["description_placeholders"]["fingerprint"] == (
        REPLACEMENT_CERTIFICATE.formatted_fingerprint
    )


async def test_expired_certificate_is_rejected_before_credentials(
    hass: HomeAssistant,
) -> None:
    """An expired certificate cannot be accepted as a new pin."""
    expired = GatewayCertificate(
        pem="expired",
        fingerprint="56" * 32,
        not_valid_before=NOW - timedelta(days=10),
        not_valid_after=NOW - timedelta(days=1),
    )
    with patch(
        "custom_components.ha_smg_emh_casa.config_flow.async_probe_certificate",
        new=AsyncMock(return_value=expired),
    ):
        _, result = await _start_user_flow(hass, TLS_MODE_PINNED_CERTIFICATE)

    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "certificate_expired"}


@pytest.mark.parametrize(
    ("host", "expected_error"),
    [
        ("http://192.0.2.25", "http_not_allowed"),
        ("https://user:password@example.com", "invalid_host"),
        ("https://example.com/path", "invalid_host"),
    ],
)
async def test_user_step_rejects_unsafe_host_values(
    hass: HomeAssistant,
    host: str,
    expected_error: str,
) -> None:
    """New entries should only accept a clean HTTPS authority."""
    result: Any = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "user"},
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={CONF_HOST: host, CONF_TLS_MODE: TLS_MODE_INSECURE},
    )

    assert result["step_id"] == "user"
    assert result["errors"] == {"base": expected_error}


async def test_user_step_requires_host(hass: HomeAssistant) -> None:
    """Manual setup should require the host field."""
    result: Any = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "user"},
    )

    with pytest.raises(InvalidData):
        await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={CONF_TLS_MODE: TLS_MODE_INSECURE},
        )


@pytest.mark.parametrize(
    ("exception", "expected_error"),
    [
        (EMHCASAApiClientAuthenticationError("Invalid credentials"), "auth"),
        (
            EMHCASAApiClientCertificateError("Certificate rejected"),
            "certificate_untrusted",
        ),
        (EMHCASAApiClientCommunicationError("Cannot connect"), "connection"),
        (EMHCASAApiClientError("Unexpected response"), "unknown"),
    ],
)
async def test_credentials_error_stays_on_form(
    hass: HomeAssistant,
    exception: EMHCASAApiClientError,
    expected_error: str,
) -> None:
    """Connection failures should remain actionable on the credential form."""
    with patch(
        "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
        new=AsyncMock(side_effect=exception),
    ):
        flow_id, _ = await _start_user_flow(hass, TLS_MODE_TRUSTED_CERTIFICATE)
        result: Any = await hass.config_entries.flow.async_configure(
            flow_id,
            user_input=_credentials(),
        )

    assert result["step_id"] == "credentials"
    assert result["errors"] == {"base": expected_error}


async def test_zeroconf_seeds_host(hass: HomeAssistant) -> None:
    """Zeroconf discovery should seed the gateway host."""
    result: Any = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "zeroconf"},
        data=ZEROCONF_DISCOVERY,
    )

    assert result["step_id"] == "user"
    assert result["data_schema"]({CONF_TLS_MODE: TLS_MODE_INSECURE}) == {
        CONF_HOST: MOCK_GATEWAY_HOST,
        CONF_TLS_MODE: TLS_MODE_INSECURE,
    }


async def test_reauth_form_uses_effective_settings_and_clears_password(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Reauth should prefill settings but require the password again."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={
            CONF_HOST: "198.51.100.20",
            CONF_USERNAME: "updated-user@example.com",
            CONF_PASSWORD: "stored-option-password",
            CONF_SCAN_INTERVAL: 45,
            CONF_TLS_MODE: TLS_MODE_INSECURE,
        },
    )

    result: Any = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={
            "source": "reauth",
            "entry_id": mock_config_entry.entry_id,
            "unique_id": mock_config_entry.unique_id,
        },
        data=mock_config_entry.data,
    )

    assert result["step_id"] == "reauth_confirm"
    with pytest.raises(vol.Invalid):
        result["data_schema"]({})
    assert result["data_schema"]({CONF_PASSWORD: "replacement-password"}) == {
        CONF_HOST: "198.51.100.20",
        CONF_TLS_MODE: TLS_MODE_INSECURE,
        CONF_USERNAME: "updated-user@example.com",
        CONF_PASSWORD: "replacement-password",
        CONF_SCAN_INTERVAL: 45,
    }


async def test_reauth_updates_options_and_reloads(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Valid reauthentication settings should be saved and reloaded."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={"future_option": "preserved"},
    )
    updated_config = {
        **MOCK_CONFIG,
        CONF_HOST: "198.51.100.20",
        CONF_PASSWORD: "replacement-password",
    }

    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch.object(
            hass.config_entries,
            "async_schedule_reload",
        ) as schedule_reload,
    ):
        result: Any = await hass.config_entries.flow.async_init(
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
    schedule_reload.assert_called_once_with(mock_config_entry.entry_id)


async def test_reauth_rejects_different_gateway(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Reauthentication should not repoint an entry to another gateway."""
    mock_config_entry.add_to_hass(hass)
    with patch(
        "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
        new=AsyncMock(return_value="different-gateway"),
    ):
        result: Any = await hass.config_entries.flow.async_init(
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


async def test_options_flow_updates_configuration(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Options should expose and save the TLS mode with connection settings."""
    mock_config_entry.add_to_hass(hass)
    updated_config = {
        **MOCK_CONFIG,
        CONF_HOST: "198.51.100.20",
        CONF_PASSWORD: "even-more-secret",
        CONF_TLS_MODE: TLS_MODE_TRUSTED_CERTIFICATE,
    }
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch.object(
            hass.config_entries,
            "async_schedule_reload",
        ) as schedule_reload,
    ):
        result: Any = await hass.config_entries.options.async_init(
            mock_config_entry.entry_id,
        )
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            user_input=updated_config,
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.options == updated_config
    schedule_reload.assert_called_once_with(mock_config_entry.entry_id)


async def test_options_flow_confirms_new_pin(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Switching to pinning should require certificate confirmation."""
    mock_config_entry.add_to_hass(hass)
    pinned_config = {**MOCK_CONFIG, CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE}
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_probe_certificate",
            new=AsyncMock(return_value=MOCK_CERTIFICATE),
        ),
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ) as validate,
        patch.object(hass.config_entries, "async_schedule_reload"),
    ):
        result: Any = await hass.config_entries.options.async_init(
            mock_config_entry.entry_id,
        )
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            user_input=pinned_config,
        )
        assert result["step_id"] == "confirm_certificate"
        validate.assert_not_awaited()

        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            user_input={},
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.options[CONF_TLS_CERTIFICATE] == MOCK_CERTIFICATE.pem
    assert mock_config_entry.options[CONF_TLS_FINGERPRINT] == (
        MOCK_CERTIFICATE.fingerprint
    )
    validate.assert_awaited_once()
