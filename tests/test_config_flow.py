"""Tests for the EMH CASA config flow."""

from __future__ import annotations

import json
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
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ha_smg_emh_casa.api import (
    EMHCASAApiClientAuthenticationError,
    EMHCASAApiClientCertificateError,
    EMHCASAApiClientCommunicationError,
    EMHCASAApiClientError,
)
from custom_components.ha_smg_emh_casa.config_flow import async_validate_connection
from custom_components.ha_smg_emh_casa.const import (
    CONF_GATEWAY_ID,
    CONF_TLS_CERTIFICATE,
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    CONFIG_ENTRY_MINOR_VERSION,
    DOMAIN,
    TLS_MODE_INSECURE,
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODE_TRUSTED_CERTIFICATE,
)
from custom_components.ha_smg_emh_casa.tls import GatewayCertificate

from .const import MOCK_CONFIG, MOCK_GATEWAY_HOST, MOCK_GATEWAY_ID

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

EXPECTED_PIN_PROBES = 2
pytestmark = pytest.mark.usefixtures("mock_async_get_data")

MOCK_CERTIFICATE = GatewayCertificate(
    pem="mock gateway certificate",
    fingerprint="12" * 32,
)
REPLACEMENT_CERTIFICATE = GatewayCertificate(
    pem="replacement gateway certificate",
    fingerprint="34" * 32,
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
    assert result["title"] == f"{MOCK_GATEWAY_ID} ({MOCK_CONFIG[CONF_USERNAME]})"
    assert json.loads(result["result"].unique_id) == [
        MOCK_GATEWAY_ID,
        MOCK_CONFIG[CONF_USERNAME],
    ]
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


async def test_invalid_certificate_is_rejected_during_connection_validation(
    hass: HomeAssistant,
) -> None:
    """An approved fingerprint must not bypass TLS certificate verification."""
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_probe_certificate",
            new=AsyncMock(return_value=MOCK_CERTIFICATE),
        ),
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(
                side_effect=EMHCASAApiClientCertificateError("certificate has expired")
            ),
        ),
    ):
        flow_id, result = await _start_user_flow(hass, TLS_MODE_PINNED_CERTIFICATE)
        assert result["step_id"] == "confirm_certificate"
        assert set(result["description_placeholders"]) == {"host", "fingerprint"}
        result = await hass.config_entries.flow.async_configure(flow_id, {})
        assert result["step_id"] == "credentials"
        result = await hass.config_entries.flow.async_configure(
            flow_id,
            {
                CONF_USERNAME: MOCK_CONFIG[CONF_USERNAME],
                CONF_PASSWORD: MOCK_CONFIG[CONF_PASSWORD],
                CONF_SCAN_INTERVAL: MOCK_CONFIG[CONF_SCAN_INTERVAL],
            },
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "certificate_untrusted"}
    assert not hass.config_entries.async_entries(DOMAIN)


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


async def _submit_account_flow(
    hass: HomeAssistant,
    source: str,
    entry: MockConfigEntry,
    settings: dict,
) -> tuple[Any, Any]:
    """Submit connection settings through one of the three account flows."""
    if source == "user":
        manager = hass.config_entries.flow
        flow_id, result = await _start_user_flow(hass, settings[CONF_TLS_MODE])
        if result["step_id"] == "confirm_certificate":
            await manager.async_configure(flow_id, {})
        return manager, await manager.async_configure(
            flow_id, {key: settings[key] for key in _credentials()}
        )
    if source == "options":
        manager = hass.config_entries.options
        result = await manager.async_init(entry.entry_id)
    else:
        manager = hass.config_entries.flow
        result = await manager.async_init(
            DOMAIN,
            context={
                "source": "reauth",
                "entry_id": entry.entry_id,
                "unique_id": entry.unique_id,
            },
            data=entry.data,
        )
    result = await manager.async_configure(result["flow_id"], settings)
    if result.get("step_id") in {"confirm_certificate", "reauth_confirm_certificate"}:
        result = await manager.async_configure(result["flow_id"], {})
    return manager, result


@pytest.mark.parametrize("source", ["user", "options", "reauth"])
@pytest.mark.parametrize("tls_mode", [TLS_MODE_INSECURE, TLS_MODE_PINNED_CERTIFICATE])
async def test_missing_gateway_id_requires_revalidated_manual_identity(
    hass: HomeAssistant,
    source: str,
    tls_mode: str,
) -> None:
    """Manual identity must be nonblank, match discovery and pass validation."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=MOCK_GATEWAY_HOST,
        data=MOCK_CONFIG,
        unique_id="192-0-2-25",
        minor_version=CONFIG_ENTRY_MINOR_VERSION,
    )
    if source != "user":
        entry.add_to_hass(hass)
    settings = {**MOCK_CONFIG, CONF_TLS_MODE: tls_mode}
    original = (dict(entry.data), dict(entry.options), entry.title, entry.unique_id)
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_probe_certificate",
            new=AsyncMock(return_value=MOCK_CERTIFICATE),
        ),
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=None),
        ) as validate,
        patch("custom_components.ha_smg_emh_casa.async_setup_entry", return_value=True),
        patch.object(hass.config_entries, "async_schedule_reload") as reload_entry,
    ):
        manager, result = await _submit_account_flow(hass, source, entry, settings)
        assert result["step_id"] == "gateway_id"
        flow_id = result["flow_id"]
        result = await manager.async_configure(flow_id, {CONF_GATEWAY_ID: "  "})
        assert result["errors"] == {CONF_GATEWAY_ID: "gateway_id_required"}
        validate.assert_awaited_once()

        validate.return_value = MOCK_GATEWAY_ID
        result = await manager.async_configure(flow_id, {CONF_GATEWAY_ID: "wrong-id"})
        assert result["errors"] == {CONF_GATEWAY_ID: "gateway_id_mismatch"}

        validate.side_effect = EMHCASAApiClientCommunicationError("Disconnected")
        result = await manager.async_configure(
            flow_id, {CONF_GATEWAY_ID: MOCK_GATEWAY_ID}
        )
        assert result["errors"] == {"base": "connection"}
        assert (
            dict(entry.data),
            dict(entry.options),
            entry.title,
            entry.unique_id,
        ) == original
        reload_entry.assert_not_called()
        if source == "user":
            assert not hass.config_entries.async_entries(DOMAIN)

        validate.side_effect = None
        validate.return_value = None
        result = await manager.async_configure(
            flow_id, {CONF_GATEWAY_ID: f"  {MOCK_GATEWAY_ID}  "}
        )

    if source == "user":
        entry = result["result"]
    elif source == "reauth":
        assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_GATEWAY_ID] == MOCK_GATEWAY_ID
    assert entry.title == (
        f"{MOCK_GATEWAY_ID} ({MOCK_CONFIG[CONF_USERNAME]})"
        if source == "user"
        else MOCK_GATEWAY_HOST
    )
    assert json.loads(entry.unique_id) == [MOCK_GATEWAY_ID, MOCK_CONFIG[CONF_USERNAME]]


@pytest.mark.parametrize(
    ("existing_username", "new_username", "host", "expected"),
    [
        ("user-a", "user-b", MOCK_GATEWAY_HOST, "create_entry"),
        ("user-a", "user-a", MOCK_GATEWAY_HOST, "abort"),
        ("user-a", "user-a", "gateway.example.test", "abort"),
        ("user-a", "user_a", MOCK_GATEWAY_HOST, "create_entry"),
        ("User-A", "user-a", MOCK_GATEWAY_HOST, "create_entry"),
    ],
)
async def test_account_setup_distinguishes_exact_users_on_one_gateway(
    hass: HomeAssistant,
    existing_username: str,
    new_username: str,
    host: str,
    expected: str,
) -> None:
    """Permit separate users while catching legacy accounts and host aliases."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={**MOCK_CONFIG, CONF_GATEWAY_ID: MOCK_GATEWAY_ID},
        options={CONF_HOST: host, CONF_USERNAME: existing_username},
        unique_id=MOCK_GATEWAY_ID,
        minor_version=CONFIG_ENTRY_MINOR_VERSION,
    )
    entry.add_to_hass(hass)
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch("custom_components.ha_smg_emh_casa.async_setup_entry", return_value=True),
    ):
        flow_id, _ = await _start_user_flow(hass, TLS_MODE_INSECURE)
        result = await hass.config_entries.flow.async_configure(
            flow_id, {**_credentials(), CONF_USERNAME: new_username}
        )
    assert result["type"] == expected
    if expected == "abort":
        assert result["reason"] == "already_configured"
    else:
        assert json.loads(result["result"].unique_id) == [MOCK_GATEWAY_ID, new_username]
        assert entry.unique_id == MOCK_GATEWAY_ID


@pytest.mark.parametrize("source", ["options", "reauth"])
@pytest.mark.parametrize("change_username", [False, True])
async def test_account_edits_reject_duplicates_without_mutation(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    source: str,
    *,
    change_username: bool,
) -> None:
    """Effective account settings must block conflicting changes atomically."""
    mock_config_entry.add_to_hass(hass)
    other = MockConfigEntry(
        domain=DOMAIN,
        data={**MOCK_CONFIG, CONF_GATEWAY_ID: MOCK_GATEWAY_ID},
        options={
            CONF_HOST: "gateway.example.test",
            CONF_USERNAME: "other-user"
            if change_username
            else MOCK_CONFIG[CONF_USERNAME],
        },
        unique_id="other-entry",
        minor_version=CONFIG_ENTRY_MINOR_VERSION,
    )
    other.add_to_hass(hass)
    settings = {
        **MOCK_CONFIG,
        CONF_USERNAME: other.options[CONF_USERNAME],
        CONF_PASSWORD: "replacement",
    }
    original = (
        dict(mock_config_entry.data),
        dict(mock_config_entry.options),
        mock_config_entry.title,
        mock_config_entry.unique_id,
    )
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch.object(hass.config_entries, "async_schedule_reload") as reload_entry,
    ):
        _, result = await _submit_account_flow(
            hass, source, mock_config_entry, settings
        )
    assert result["reason"] == "already_configured"
    assert (
        dict(mock_config_entry.data),
        dict(mock_config_entry.options),
        mock_config_entry.title,
        mock_config_entry.unique_id,
    ) == original
    reload_entry.assert_not_called()


@pytest.mark.parametrize("source", ["options", "reauth"])
@pytest.mark.parametrize("host_changed", [False, True])
async def test_existing_huid_is_reused_only_for_unchanged_host(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    source: str,
    *,
    host_changed: bool,
) -> None:
    """A new host needs explicit identity confirmation if discovery fails."""
    mock_config_entry.add_to_hass(hass)
    settings = {
        **MOCK_CONFIG,
        CONF_HOST: "other.example.test" if host_changed else MOCK_GATEWAY_HOST,
    }
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=None),
        ),
        patch.object(hass.config_entries, "async_schedule_reload"),
    ):
        manager, result = await _submit_account_flow(
            hass, source, mock_config_entry, settings
        )
        if host_changed:
            assert result["step_id"] == "gateway_id"
            assert result["data_schema"]({}) == {CONF_GATEWAY_ID: MOCK_GATEWAY_ID}
            result = await manager.async_configure(
                result["flow_id"], {CONF_GATEWAY_ID: MOCK_GATEWAY_ID}
            )
    assert result["type"] == ("abort" if source == "reauth" else "create_entry")
    assert mock_config_entry.unique_id == MOCK_GATEWAY_ID
    assert (
        mock_config_entry.title == f"{MOCK_GATEWAY_ID} ({MOCK_CONFIG[CONF_USERNAME]})"
    )


@pytest.mark.parametrize("source", ["options", "reauth"])
async def test_username_changes_refresh_identity(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    source: str,
) -> None:
    """Renaming an account should free its old identity without replacing the entry."""
    mock_config_entry.add_to_hass(hass)
    original_entry_id = mock_config_entry.entry_id
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch.object(hass.config_entries, "async_schedule_reload"),
    ):
        await _submit_account_flow(
            hass,
            source,
            mock_config_entry,
            {**MOCK_CONFIG, CONF_USERNAME: "replacement-user"},
        )
        flow_id, _ = await _start_user_flow(hass, TLS_MODE_INSECURE)
        with patch(
            "custom_components.ha_smg_emh_casa.async_setup_entry", return_value=True
        ):
            result = await hass.config_entries.flow.async_configure(
                flow_id, _credentials()
            )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.entry_id == original_entry_id
    assert json.loads(mock_config_entry.unique_id) == [
        MOCK_GATEWAY_ID,
        "replacement-user",
    ]


async def test_zeroconf_suppresses_configured_gateway(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Additional accounts must not create recurring gateway discovery prompts."""
    mock_config_entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "zeroconf"},
        data=ZEROCONF_DISCOVERY,
    )
    assert result["reason"] == "already_configured"


@pytest.mark.parametrize(
    "effective_override",
    [
        {CONF_HOST: "other.example.test"},
        {CONF_USERNAME: "other-user"},
        {CONF_HOST: "http://broken.example.test/path"},
    ],
)
async def test_duplicate_checks_ignore_overridden_and_invalid_legacy_hosts(
    hass: HomeAssistant,
    effective_override: dict,
) -> None:
    """Stale data and broken legacy hosts must not prevent another account setup."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={**MOCK_CONFIG, CONF_GATEWAY_ID: "another-gateway"},
        options=effective_override,
        unique_id="another-gateway",
        minor_version=CONFIG_ENTRY_MINOR_VERSION,
    )
    entry.add_to_hass(hass)
    with (
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.async_validate_connection",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch("custom_components.ha_smg_emh_casa.async_setup_entry", return_value=True),
    ):
        flow_id, _ = await _start_user_flow(hass, TLS_MODE_INSECURE)
        result = await hass.config_entries.flow.async_configure(flow_id, _credentials())
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_certificate_errors_in_identity_lookup_block_credentials() -> None:
    """An identity TLS failure must never turn into manual identity or data access."""
    client = AsyncMock()
    client.async_get_gateway_id.side_effect = EMHCASAApiClientCertificateError(
        "bad TLS"
    )
    with (
        patch("custom_components.ha_smg_emh_casa.config_flow.create_httpx_client"),
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.EMHCASAClient",
            return_value=client,
        ),
        pytest.raises(EMHCASAApiClientCertificateError),
    ):
        await async_validate_connection(MOCK_CONFIG)
    client.async_get_data.assert_not_awaited()
    client.async_close.assert_awaited_once()


@pytest.mark.parametrize("lookup_fails", [False, True])
async def test_missing_identity_still_requires_successful_meter_access(
    *,
    lookup_fails: bool,
) -> None:
    """Manual identity is possible only after the credentials and data validate."""
    client = AsyncMock()
    client.async_get_gateway_id.return_value = None
    if lookup_fails:
        client.async_get_gateway_id.side_effect = EMHCASAApiClientCommunicationError(
            "no ID"
        )
    client.async_get_data.side_effect = EMHCASAApiClientAuthenticationError("bad login")
    with (
        patch("custom_components.ha_smg_emh_casa.config_flow.create_httpx_client"),
        patch(
            "custom_components.ha_smg_emh_casa.config_flow.EMHCASAClient",
            return_value=client,
        ),
        pytest.raises(EMHCASAApiClientAuthenticationError),
    ):
        await async_validate_connection(MOCK_CONFIG)
    client.async_close.assert_awaited_once()
