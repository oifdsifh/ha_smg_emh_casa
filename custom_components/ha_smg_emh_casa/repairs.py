"""Repair flows for the EMH CASA integration."""

from __future__ import annotations

from typing import TYPE_CHECKING

import voluptuous as vol
from homeassistant.components.repairs import (
    ConfirmRepairFlow,
    RepairsFlow,
    RepairsFlowResult,
)
from homeassistant.const import CONF_HOST
from homeassistant.helpers import issue_registry as ir

from .api import EMHCASAApiClientError, EMHCASAClient
from .const import (
    CONF_GATEWAY_ID,
    CONF_TLS_CERTIFICATE,
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    DOMAIN,
    ISSUE_CERTIFICATE_CHANGED,
    TLS_MODE_PINNED_CERTIFICATE,
)
from .tls import (
    EMHCASATlsError,
    GatewayCertificate,
    async_probe_certificate,
    create_httpx_client,
)

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant


class _RepairValidationError(Exception):
    """A repair validation error with a translation key."""

    def __init__(self, error_key: str) -> None:
        """Initialize the repair error."""
        super().__init__(error_key)
        self.error_key = error_key


class CertificateChangedRepairFlow(RepairsFlow):
    """Confirm and save a replacement gateway certificate."""

    def __init__(
        self,
        entry: ConfigEntry,
        issue_id: str,
        expected_fingerprint: str,
    ) -> None:
        """Initialize the certificate repair flow."""
        self._entry = entry
        self._issue_id = issue_id
        self._expected_fingerprint = expected_fingerprint

    async def async_step_init(
        self,
        _: dict[str, str] | None = None,
    ) -> RepairsFlowResult:
        """Handle the first repair step."""
        return await self.async_step_confirm()

    async def async_step_confirm(
        self,
        user_input: dict[str, str] | None = None,
    ) -> RepairsFlowResult:
        """Recheck and accept the replacement certificate."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                certificate = await self._async_validate_candidate()
            except _RepairValidationError as exception:
                errors["base"] = exception.error_key
            else:
                if CONF_TLS_MODE in self._entry.options:
                    options = dict(self._entry.options) | {
                        CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
                        CONF_TLS_CERTIFICATE: certificate.pem,
                        CONF_TLS_FINGERPRINT: certificate.fingerprint,
                    }
                    self.hass.config_entries.async_update_entry(
                        self._entry,
                        options=options,
                    )
                else:
                    data = dict(self._entry.data) | {
                        CONF_TLS_MODE: TLS_MODE_PINNED_CERTIFICATE,
                        CONF_TLS_CERTIFICATE: certificate.pem,
                        CONF_TLS_FINGERPRINT: certificate.fingerprint,
                    }
                    self.hass.config_entries.async_update_entry(
                        self._entry,
                        data=data,
                    )
                ir.async_delete_issue(self.hass, DOMAIN, self._issue_id)
                await self.hass.config_entries.async_reload(self._entry.entry_id)
                return self.async_create_entry(data={})

        values = self._entry.data | self._entry.options
        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema({}),
            description_placeholders={
                "entry_title": self._entry.title,
                "old_fingerprint": _format_fingerprint(
                    values.get(CONF_TLS_FINGERPRINT)
                ),
                "new_fingerprint": _format_fingerprint(self._expected_fingerprint),
            },
            errors=errors,
        )

    async def _async_validate_candidate(self) -> GatewayCertificate:
        """Verify that the replacement certificate and gateway are stable."""
        values = self._entry.data | self._entry.options
        if values.get(CONF_TLS_MODE) != TLS_MODE_PINNED_CERTIFICATE:
            error_key = "mode_changed"
            raise _RepairValidationError(error_key)

        host = values[CONF_HOST]
        try:
            first = await async_probe_certificate(host)
            second = await async_probe_certificate(host)
        except EMHCASATlsError as exception:
            error_key = "connection"
            raise _RepairValidationError(error_key) from exception
        if (
            first.fingerprint != second.fingerprint
            or first.fingerprint != self._expected_fingerprint
        ):
            error_key = "certificate_changed_again"
            raise _RepairValidationError(error_key)
        if first.validity_error:
            raise _RepairValidationError(first.validity_error)

        http_client = create_httpx_client(
            TLS_MODE_PINNED_CERTIFICATE,
            first.pem,
        )
        client = EMHCASAClient(
            host=host,
            username="",
            password="",
            client=http_client,
        )
        try:
            gateway_id = await client.async_get_gateway_id()
        except EMHCASAApiClientError as exception:
            error_key = "connection"
            raise _RepairValidationError(error_key) from exception
        finally:
            await client.async_close()

        if (expected_gateway_id := values.get(CONF_GATEWAY_ID)) and (
            gateway_id != expected_gateway_id
        ):
            error_key = "wrong_gateway"
            raise _RepairValidationError(error_key)
        return first


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, str | int | float | None] | None,
) -> RepairsFlow:
    """Create a repair flow for a certificate-change issue."""
    if (
        issue_id.startswith(f"{ISSUE_CERTIFICATE_CHANGED}_")
        and data is not None
        and isinstance(entry_id := data.get("entry_id"), str)
        and isinstance(fingerprint := data.get("new_fingerprint"), str)
        and (entry := hass.config_entries.async_get_entry(entry_id)) is not None
    ):
        return CertificateChangedRepairFlow(entry, issue_id, fingerprint)
    return ConfirmRepairFlow()


def _format_fingerprint(fingerprint: object) -> str:
    """Format a SHA-256 fingerprint for display."""
    if not isinstance(fingerprint, str):
        return "unknown"
    return ":".join(
        fingerprint[index : index + 2].upper()
        for index in range(0, len(fingerprint), 2)
    )
