"""Tests for EMH CASA certificate repair flows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ha_smg_emh_casa.const import (
    CONF_GATEWAY_ID,
    CONF_TLS_CERTIFICATE,
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    CONFIG_ENTRY_MINOR_VERSION,
    DOMAIN,
    ISSUE_CERTIFICATE_CHANGED,
    TLS_MODE_PINNED_CERTIFICATE,
)
from custom_components.ha_smg_emh_casa.repairs import (
    CertificateChangedRepairFlow,
    async_create_fix_flow,
)
from custom_components.ha_smg_emh_casa.tls import (
    EMHCASATlsConnectionError,
    GatewayCertificate,
)

from .const import MOCK_CONFIG, MOCK_GATEWAY_ID

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

NOW = datetime.now(UTC)
EXPECTED_STABILITY_PROBES = 2
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


def _pinned_entry(hass: HomeAssistant) -> MockConfigEntry:
    """Create an entry with a stored certificate pin."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Gateway",
        data={
            **MOCK_CONFIG,
            CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
            CONF_TLS_CERTIFICATE: OLD_CERTIFICATE.pem,
            CONF_TLS_FINGERPRINT: OLD_CERTIFICATE.fingerprint,
            CONF_GATEWAY_ID: MOCK_GATEWAY_ID,
        },
        unique_id=MOCK_GATEWAY_ID,
        minor_version=CONFIG_ENTRY_MINOR_VERSION,
    )
    entry.add_to_hass(hass)
    return entry


async def test_repair_accepts_stable_certificate_for_same_gateway(
    hass: HomeAssistant,
) -> None:
    """A stable replacement for the known gateway should replace the pin."""
    entry = _pinned_entry(hass)
    issue_id = f"{ISSUE_CERTIFICATE_CHANGED}_{entry.entry_id}"
    flow = CertificateChangedRepairFlow(
        entry,
        issue_id,
        NEW_CERTIFICATE.fingerprint,
    )
    flow.hass = hass
    http_client = AsyncMock()

    with (
        patch(
            "custom_components.ha_smg_emh_casa.repairs.async_probe_certificate",
            new=AsyncMock(return_value=NEW_CERTIFICATE),
        ) as probe,
        patch(
            "custom_components.ha_smg_emh_casa.repairs.create_httpx_client",
            return_value=http_client,
        ),
        patch(
            "custom_components.ha_smg_emh_casa.repairs.EMHCASAClient.async_get_gateway_id",
            new=AsyncMock(return_value=MOCK_GATEWAY_ID),
        ),
        patch.object(
            hass.config_entries,
            "async_reload",
            new=AsyncMock(return_value=True),
        ) as reload_entry,
    ):
        result: Any = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.data[CONF_TLS_CERTIFICATE] == NEW_CERTIFICATE.pem
    assert entry.data[CONF_TLS_FINGERPRINT] == NEW_CERTIFICATE.fingerprint
    assert probe.await_count == EXPECTED_STABILITY_PROBES
    reload_entry.assert_awaited_once_with(entry.entry_id)
    http_client.aclose.assert_awaited_once()


async def test_repair_form_does_not_change_pin_before_confirmation(
    hass: HomeAssistant,
) -> None:
    """Opening or abandoning the repair must leave the old pin unchanged."""
    entry = _pinned_entry(hass)
    flow = CertificateChangedRepairFlow(
        entry,
        f"{ISSUE_CERTIFICATE_CHANGED}_{entry.entry_id}",
        NEW_CERTIFICATE.fingerprint,
    )
    flow.hass = hass

    result: Any = await flow.async_step_confirm()

    assert result["type"] is FlowResultType.FORM
    assert entry.data[CONF_TLS_FINGERPRINT] == OLD_CERTIFICATE.fingerprint


async def test_repair_rejects_unstable_certificate(hass: HomeAssistant) -> None:
    """The repair should not accept a certificate that changes again."""
    entry = _pinned_entry(hass)
    another = GatewayCertificate(
        pem="another certificate",
        fingerprint="56" * 32,
        not_valid_before=NOW - timedelta(days=1),
        not_valid_after=NOW + timedelta(days=30),
    )
    flow = CertificateChangedRepairFlow(
        entry,
        f"{ISSUE_CERTIFICATE_CHANGED}_{entry.entry_id}",
        NEW_CERTIFICATE.fingerprint,
    )
    flow.hass = hass

    with patch(
        "custom_components.ha_smg_emh_casa.repairs.async_probe_certificate",
        new=AsyncMock(side_effect=[NEW_CERTIFICATE, another]),
    ):
        result: Any = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "certificate_changed_again"}
    assert entry.data[CONF_TLS_FINGERPRINT] == OLD_CERTIFICATE.fingerprint


async def test_repair_rejects_different_gateway(hass: HomeAssistant) -> None:
    """A replacement certificate must still expose the known Digest realm."""
    entry = _pinned_entry(hass)
    flow = CertificateChangedRepairFlow(
        entry,
        f"{ISSUE_CERTIFICATE_CHANGED}_{entry.entry_id}",
        NEW_CERTIFICATE.fingerprint,
    )
    flow.hass = hass
    http_client = AsyncMock()

    with (
        patch(
            "custom_components.ha_smg_emh_casa.repairs.async_probe_certificate",
            new=AsyncMock(return_value=NEW_CERTIFICATE),
        ),
        patch(
            "custom_components.ha_smg_emh_casa.repairs.create_httpx_client",
            return_value=http_client,
        ),
        patch(
            "custom_components.ha_smg_emh_casa.repairs.EMHCASAClient.async_get_gateway_id",
            new=AsyncMock(return_value="another-gateway"),
        ),
    ):
        result: Any = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "wrong_gateway"}
    assert entry.data[CONF_TLS_FINGERPRINT] == OLD_CERTIFICATE.fingerprint


async def test_repair_rejects_expired_replacement(hass: HomeAssistant) -> None:
    """An expired stable replacement certificate cannot be reaccepted."""
    entry = _pinned_entry(hass)
    expired = GatewayCertificate(
        pem=NEW_CERTIFICATE.pem,
        fingerprint=NEW_CERTIFICATE.fingerprint,
        not_valid_before=NOW - timedelta(days=30),
        not_valid_after=NOW - timedelta(days=1),
    )
    flow = CertificateChangedRepairFlow(
        entry,
        f"{ISSUE_CERTIFICATE_CHANGED}_{entry.entry_id}",
        expired.fingerprint,
    )
    flow.hass = hass

    with patch(
        "custom_components.ha_smg_emh_casa.repairs.async_probe_certificate",
        new=AsyncMock(return_value=expired),
    ):
        result: Any = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "certificate_expired"}
    assert entry.data[CONF_TLS_FINGERPRINT] == OLD_CERTIFICATE.fingerprint


async def test_repair_reports_certificate_probe_failure(hass: HomeAssistant) -> None:
    """A temporary TLS probe failure should keep the repair flow usable."""
    entry = _pinned_entry(hass)
    flow = CertificateChangedRepairFlow(
        entry,
        f"{ISSUE_CERTIFICATE_CHANGED}_{entry.entry_id}",
        NEW_CERTIFICATE.fingerprint,
    )
    flow.hass = hass

    with patch(
        "custom_components.ha_smg_emh_casa.repairs.async_probe_certificate",
        new=AsyncMock(side_effect=EMHCASATlsConnectionError("offline")),
    ):
        result: Any = await flow.async_step_confirm({})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "connection"}
    assert entry.data[CONF_TLS_FINGERPRINT] == OLD_CERTIFICATE.fingerprint


async def test_create_fix_flow_resolves_entry(hass: HomeAssistant) -> None:
    """Issue metadata should create the certificate replacement flow."""
    entry = _pinned_entry(hass)
    flow = await async_create_fix_flow(
        hass,
        f"{ISSUE_CERTIFICATE_CHANGED}_{entry.entry_id}",
        {
            "entry_id": entry.entry_id,
            "new_fingerprint": NEW_CERTIFICATE.fingerprint,
        },
    )

    assert isinstance(flow, CertificateChangedRepairFlow)
