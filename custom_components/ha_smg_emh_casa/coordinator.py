"""DataUpdateCoordinator for ha_smg_emh_casa."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.const import CONF_HOST
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    EMHCASAApiClientAuthenticationError,
    EMHCASAApiClientCertificateError,
    EMHCASAApiClientError,
)
from .const import (
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    DOMAIN,
    ISSUE_CERTIFICATE_CHANGED,
    ISSUE_CERTIFICATE_INVALID,
    TLS_MODE_PINNED_CERTIFICATE,
)
from .tls import EMHCASATlsError, GatewayCertificate, async_probe_certificate

if TYPE_CHECKING:
    from .data import EMHCASAConfigEntry


# https://developers.home-assistant.io/docs/integration_fetching_data#coordinated-single-api-poll-for-data-for-all-entities
class EMHCASADataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    config_entry: EMHCASAConfigEntry

    async def _async_update_data(self) -> Any:
        """Update data via library."""
        await self._async_validate_pinned_certificate()
        try:
            return await self.config_entry.runtime_data.client.async_get_data()
        except EMHCASAApiClientAuthenticationError as exception:
            raise ConfigEntryAuthFailed(exception) from exception
        except EMHCASAApiClientCertificateError as exception:
            await self._async_create_certificate_issue()
            raise UpdateFailed(exception) from exception
        except EMHCASAApiClientError as exception:
            raise UpdateFailed(exception) from exception

    async def _async_validate_pinned_certificate(self) -> None:
        """Check the exact remembered certificate before sending credentials."""
        values = self.config_entry.data | self.config_entry.options
        if values.get(CONF_TLS_MODE) != TLS_MODE_PINNED_CERTIFICATE:
            return

        try:
            certificate = await async_probe_certificate(values[CONF_HOST])
        except EMHCASATlsError as exception:
            raise UpdateFailed(exception) from exception

        old_fingerprint = values.get(CONF_TLS_FINGERPRINT)
        if old_fingerprint != certificate.fingerprint:
            self._create_changed_certificate_issue(certificate, old_fingerprint)
            msg = "The gateway certificate changed"
            raise UpdateFailed(msg)

        if validity_error := certificate.validity_error:
            self._create_invalid_certificate_issue(certificate, validity_error)
            msg = f"The gateway certificate is {validity_error}"
            raise UpdateFailed(msg)

    async def _async_create_certificate_issue(self) -> None:
        """Create a specific repair issue for a rejected pinned certificate."""
        values = self.config_entry.data | self.config_entry.options
        if values.get(CONF_TLS_MODE) != TLS_MODE_PINNED_CERTIFICATE:
            return

        try:
            certificate = await async_probe_certificate(values[CONF_HOST])
        except EMHCASATlsError:
            return

        old_fingerprint = values.get(CONF_TLS_FINGERPRINT)
        if old_fingerprint != certificate.fingerprint:
            self._create_changed_certificate_issue(certificate, old_fingerprint)
            return

        if validity_error := certificate.validity_error:
            self._create_invalid_certificate_issue(certificate, validity_error)

    def _create_changed_certificate_issue(
        self,
        certificate: GatewayCertificate,
        old_fingerprint: object,
    ) -> None:
        """Create a fixable issue for a changed pinned certificate."""
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            f"{ISSUE_CERTIFICATE_CHANGED}_{self.config_entry.entry_id}",
            is_fixable=True,
            is_persistent=True,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_CERTIFICATE_CHANGED,
            translation_placeholders={
                "entry_title": self.config_entry.title,
                "old_fingerprint": _format_fingerprint(old_fingerprint),
                "new_fingerprint": certificate.formatted_fingerprint,
            },
            data={
                "entry_id": self.config_entry.entry_id,
                "new_fingerprint": certificate.fingerprint,
            },
        )

    def _create_invalid_certificate_issue(
        self,
        certificate: GatewayCertificate,
        validity_error: str,
    ) -> None:
        """Create a non-fixable issue for an invalid remembered certificate."""
        reason = validity_error.removeprefix("certificate_").replace("_", " ")
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            f"{ISSUE_CERTIFICATE_INVALID}_{self.config_entry.entry_id}",
            is_fixable=False,
            is_persistent=True,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_CERTIFICATE_INVALID,
            translation_placeholders={
                "entry_title": self.config_entry.title,
                "fingerprint": certificate.formatted_fingerprint,
                "reason": reason,
                "valid_from": certificate.not_valid_before.isoformat(),
                "valid_until": certificate.not_valid_after.isoformat(),
            },
            data={"entry_id": self.config_entry.entry_id},
        )


def _format_fingerprint(fingerprint: object) -> str:
    """Format a stored SHA-256 fingerprint for display."""
    if not isinstance(fingerprint, str):
        return "unknown"
    return ":".join(
        fingerprint[index : index + 2].upper()
        for index in range(0, len(fingerprint), 2)
    )
