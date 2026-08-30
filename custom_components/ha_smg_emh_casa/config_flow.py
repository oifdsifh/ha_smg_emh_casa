"""Config flow for the EMH CASA integration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.loader import async_get_loaded_integration
from slugify import slugify

from .api import (
    EMHCASAApiClientAuthenticationError,
    EMHCASAApiClientCertificateError,
    EMHCASAApiClientCommunicationError,
    EMHCASAApiClientError,
    EMHCASAClient,
)
from .const import (
    CONF_GATEWAY_ID,
    CONF_TLS_CERTIFICATE,
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    CONFIG_ENTRY_MINOR_VERSION,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TLS_MODE,
    DOMAIN,
    LOGGER,
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODES,
)
from .tls import (
    EMHCASACertificateValidityError,
    EMHCASAHttpNotAllowedError,
    EMHCASAInvalidHostError,
    EMHCASATlsConnectionError,
    EMHCASATlsError,
    GatewayCertificate,
    async_probe_certificate,
    create_httpx_client,
    normalize_host,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo


async def async_validate_connection(
    settings: Mapping[str, Any],
) -> str | None:
    """Validate credentials and return a stable gateway identifier if available."""
    http_client = create_httpx_client(
        settings[CONF_TLS_MODE],
        settings.get(CONF_TLS_CERTIFICATE),
    )
    client = EMHCASAClient(
        host=settings[CONF_HOST],
        username=settings[CONF_USERNAME],
        password=settings[CONF_PASSWORD],
        client=http_client,
    )
    try:
        try:
            gateway_id = await client.async_get_gateway_id()
        except EMHCASAApiClientError:
            gateway_id = None
        await client.async_get_data()
        return gateway_id
    finally:
        await client.async_close()


def _raise_for_certificate_validity(certificate: GatewayCertificate) -> None:
    """Reject a certificate that is not currently valid."""
    if reason := certificate.validity_error:
        raise EMHCASACertificateValidityError(reason)


def _certificate_data(certificate: GatewayCertificate) -> dict[str, str]:
    """Return config-entry values for a pinned certificate."""
    return {
        CONF_TLS_CERTIFICATE: certificate.pem,
        CONF_TLS_FINGERPRINT: certificate.fingerprint,
    }


def _tls_selector() -> selector.SelectSelector:
    """Return the translated TLS-mode selector."""
    return selector.SelectSelector(
        selector.SelectSelectorConfig(
            options=list(TLS_MODES),
            translation_key=CONF_TLS_MODE,
            mode=selector.SelectSelectorMode.DROPDOWN,
        )
    )


def _error_key(exception: EMHCASAApiClientError | EMHCASATlsError) -> str:
    """Map a connection exception to a config-flow error key."""
    if isinstance(exception, EMHCASAApiClientAuthenticationError):
        LOGGER.warning(exception)
        error_key = "auth"
    elif isinstance(exception, EMHCASAApiClientCertificateError):
        LOGGER.warning(exception)
        error_key = "certificate_untrusted"
    elif isinstance(exception, EMHCASACertificateValidityError):
        error_key = exception.reason
    elif isinstance(exception, EMHCASAHttpNotAllowedError):
        error_key = "http_not_allowed"
    elif isinstance(exception, EMHCASAInvalidHostError):
        error_key = "invalid_host"
    elif isinstance(
        exception,
        (EMHCASAApiClientCommunicationError, EMHCASATlsConnectionError),
    ):
        LOGGER.error(exception)
        error_key = "connection"
    else:
        LOGGER.exception(exception)
        error_key = "unknown"
    return error_key


class EMHCASAFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for EMH CASA."""

    VERSION = 1
    MINOR_VERSION = CONFIG_ENTRY_MINOR_VERSION

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovered_host: str | None = None
        self._connection_settings: dict[str, Any] = {}
        self._pending_certificate: GatewayCertificate | None = None
        self._pending_reauth: dict[str, Any] | None = None

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> EMHCASAOptionsFlowHandler:
        """Return the options flow handler."""
        return EMHCASAOptionsFlowHandler(config_entry)

    async def async_step_zeroconf(
        self,
        discovery_info: ZeroconfServiceInfo,
    ) -> config_entries.ConfigFlowResult:
        """Handle a flow initialized by zeroconf discovery."""
        self._discovered_host = discovery_info.host
        self._async_abort_entries_match({CONF_HOST: self._discovered_host})
        return await self.async_step_user()

    async def async_step_user(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Collect the gateway address and TLS trust choice."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                host = normalize_host(user_input[CONF_HOST])
                tls_mode = user_input[CONF_TLS_MODE]
                self._connection_settings = {
                    CONF_HOST: host,
                    CONF_TLS_MODE: tls_mode,
                }
                if tls_mode == TLS_MODE_PINNED_CERTIFICATE:
                    certificate = await async_probe_certificate(host)
                    _raise_for_certificate_validity(certificate)
                    self._pending_certificate = certificate
                    return await self.async_step_confirm_certificate()
                return await self.async_step_credentials()
            except (EMHCASAApiClientError, EMHCASATlsError) as exception:
                errors["base"] = _error_key(exception)

        integration = async_get_loaded_integration(self.hass, DOMAIN)
        return self.async_show_form(
            step_id="user",
            description_placeholders={
                "documentation_url": cast("str", integration.documentation),
            },
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_HOST,
                        default=(user_input or {}).get(
                            CONF_HOST,
                            self._discovered_host or vol.UNDEFINED,
                        ),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.TEXT,
                        )
                    ),
                    vol.Required(
                        CONF_TLS_MODE,
                        default=(user_input or {}).get(
                            CONF_TLS_MODE,
                            DEFAULT_TLS_MODE,
                        ),
                    ): _tls_selector(),
                }
            ),
            errors=errors,
        )

    async def async_step_confirm_certificate(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Ask the user to accept the first gateway certificate."""
        certificate = self._pending_certificate
        if certificate is None:
            return self.async_abort(reason="unknown")

        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                current = await async_probe_certificate(
                    self._connection_settings[CONF_HOST]
                )
                _raise_for_certificate_validity(current)
                if current.fingerprint != certificate.fingerprint:
                    self._pending_certificate = current
                    certificate = current
                    errors["base"] = "certificate_changed_during_setup"
                else:
                    self._connection_settings.update(_certificate_data(current))
                    return await self.async_step_credentials()
            except (EMHCASAApiClientError, EMHCASATlsError) as exception:
                errors["base"] = _error_key(exception)

        return self._show_certificate_form(
            "confirm_certificate",
            self._connection_settings[CONF_HOST],
            certificate,
            errors,
        )

    async def async_step_credentials(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Collect and validate the Digest credentials."""
        if not self._connection_settings:
            return await self.async_step_user()

        errors: dict[str, str] = {}
        if user_input is not None:
            entry_data = self._connection_settings | user_input
            try:
                gateway_id = await async_validate_connection(entry_data)
            except (EMHCASAApiClientError, EMHCASATlsError) as exception:
                errors["base"] = _error_key(exception)
            else:
                host = entry_data[CONF_HOST]
                await self.async_set_unique_id(gateway_id or slugify(host))
                self._async_abort_entries_match({CONF_HOST: host})
                self._abort_if_unique_id_configured()
                if gateway_id is not None:
                    entry_data[CONF_GATEWAY_ID] = gateway_id
                return self.async_create_entry(
                    title=gateway_id or host,
                    data=entry_data,
                )

        return self.async_show_form(
            step_id="credentials",
            data_schema=self._credentials_schema(user_input),
            errors=errors,
        )

    async def async_step_reauth(
        self,
        _: Mapping[str, Any],
    ) -> config_entries.ConfigFlowResult:
        """Handle a reauthentication request."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Validate and save updated gateway settings."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                (
                    prepared,
                    certificate,
                    needs_confirmation,
                ) = await self._async_prepare_existing_input(user_input)
                if needs_confirmation:
                    self._pending_reauth = prepared
                    self._pending_certificate = certificate
                    return await self.async_step_reauth_confirm_certificate()
                gateway_id = await self._async_validate_prepared(prepared)
            except (EMHCASAApiClientError, EMHCASATlsError) as exception:
                errors["base"] = _error_key(exception)
            else:
                return await self._async_finish_reauth(prepared, gateway_id)

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self._existing_schema(user_input, password_default=False),
            errors=errors,
        )

    async def async_step_reauth_confirm_certificate(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Confirm a new pin while reauthenticating."""
        pending = self._pending_reauth
        certificate = self._pending_certificate
        if pending is None or certificate is None:
            return self.async_abort(reason="unknown")
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                current = await async_probe_certificate(pending[CONF_HOST])
                _raise_for_certificate_validity(current)
                if current.fingerprint != certificate.fingerprint:
                    self._pending_certificate = current
                    certificate = current
                    errors["base"] = "certificate_changed_during_setup"
                else:
                    pending.update(_certificate_data(current))
                    gateway_id = await self._async_validate_prepared(pending)
                    return await self._async_finish_reauth(pending, gateway_id)
            except (EMHCASAApiClientError, EMHCASATlsError) as exception:
                errors["base"] = _error_key(exception)

        return self._show_certificate_form(
            "reauth_confirm_certificate",
            pending[CONF_HOST],
            certificate,
            errors,
        )

    async def _async_prepare_existing_input(
        self,
        user_input: dict[str, Any],
    ) -> tuple[dict[str, Any], GatewayCertificate | None, bool]:
        """Normalize existing-entry input and prepare its TLS settings."""
        prepared = dict(user_input)
        prepared[CONF_HOST] = normalize_host(prepared[CONF_HOST])
        if prepared[CONF_TLS_MODE] != TLS_MODE_PINNED_CERTIFICATE:
            return prepared, None, False

        certificate = await async_probe_certificate(prepared[CONF_HOST])
        _raise_for_certificate_validity(certificate)
        entry = self._get_reauth_entry()
        values = entry.data | entry.options
        unchanged = (
            prepared[CONF_HOST] == values[CONF_HOST]
            and values.get(CONF_TLS_MODE) == TLS_MODE_PINNED_CERTIFICATE
            and values.get(CONF_TLS_FINGERPRINT) == certificate.fingerprint
        )
        if unchanged:
            prepared.update(_certificate_data(certificate))
        return prepared, certificate, not unchanged

    async def _async_validate_prepared(self, prepared: dict[str, Any]) -> str | None:
        """Validate a normalized existing-entry submission."""
        return await async_validate_connection(prepared)

    async def _async_finish_reauth(
        self,
        prepared: dict[str, Any],
        gateway_id: str | None,
    ) -> config_entries.ConfigFlowResult:
        """Save a successfully validated reauthentication submission."""
        reauth_entry = self._get_reauth_entry()
        if gateway_id is not None:
            await self.async_set_unique_id(gateway_id)
            self._abort_if_unique_id_mismatch(reason="wrong_gateway")

        options = dict(reauth_entry.options) | prepared
        data = dict(reauth_entry.data)
        if prepared[CONF_TLS_MODE] != TLS_MODE_PINNED_CERTIFICATE:
            for key in (CONF_TLS_CERTIFICATE, CONF_TLS_FINGERPRINT):
                options.pop(key, None)
                data.pop(key, None)
        self.hass.config_entries.async_update_entry(reauth_entry, data=data)
        return self.async_update_reload_and_abort(reauth_entry, options=options)

    def _existing_schema(
        self,
        user_input: dict[str, Any] | None,
        *,
        password_default: bool,
    ) -> vol.Schema:
        """Build the reauthentication schema."""
        entry = self._get_reauth_entry()
        values = entry.data | entry.options | (user_input or {})
        password_marker: vol.Marker
        if password_default:
            password_marker = vol.Required(
                CONF_PASSWORD,
                default=values[CONF_PASSWORD],
            )
        else:
            password_marker = vol.Required(CONF_PASSWORD)
        return vol.Schema(
            {
                vol.Required(
                    CONF_HOST, default=values[CONF_HOST]
                ): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                ),
                vol.Required(
                    CONF_TLS_MODE,
                    default=values.get(CONF_TLS_MODE, DEFAULT_TLS_MODE),
                ): _tls_selector(),
                vol.Required(
                    CONF_USERNAME,
                    default=values[CONF_USERNAME],
                ): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                ),
                password_marker: selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=values.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): _scan_interval_selector(),
            }
        )

    @staticmethod
    def _credentials_schema(user_input: dict[str, Any] | None) -> vol.Schema:
        """Build the credential step schema."""
        values = user_input or {}
        return vol.Schema(
            {
                vol.Required(
                    CONF_USERNAME,
                    default=values.get(CONF_USERNAME, vol.UNDEFINED),
                ): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                ),
                vol.Required(CONF_PASSWORD): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=values.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): _scan_interval_selector(),
            }
        )

    def _show_certificate_form(
        self,
        step_id: str,
        host: str,
        certificate: GatewayCertificate,
        errors: dict[str, str],
    ) -> config_entries.ConfigFlowResult:
        """Show a certificate confirmation form."""
        return self.async_show_form(
            step_id=step_id,
            data_schema=vol.Schema({}),
            description_placeholders={
                "host": host,
                "fingerprint": certificate.formatted_fingerprint,
                "valid_from": certificate.not_valid_before.isoformat(),
                "valid_until": certificate.not_valid_after.isoformat(),
            },
            errors=errors,
        )


class EMHCASAOptionsFlowHandler(config_entries.OptionsFlowWithReload):
    """Handle EMH CASA options."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize the options flow."""
        self._config_entry = config_entry
        self._pending_input: dict[str, Any] | None = None
        self._pending_certificate: GatewayCertificate | None = None

    async def async_step_init(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Manage the integration options."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                (
                    prepared,
                    certificate,
                    needs_confirmation,
                ) = await self._async_prepare_input(user_input)
                if needs_confirmation:
                    self._pending_input = prepared
                    self._pending_certificate = certificate
                    return await self.async_step_confirm_certificate()
                await self._async_validate(prepared)
            except (EMHCASAApiClientError, EMHCASATlsError) as exception:
                errors["base"] = _error_key(exception)
            else:
                return self._save_options(prepared)

        return self.async_show_form(
            step_id="init",
            data_schema=self._options_schema(user_input),
            errors=errors,
        )

    async def async_step_confirm_certificate(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Confirm a new certificate pin in the options flow."""
        pending = self._pending_input
        certificate = self._pending_certificate
        if pending is None or certificate is None:
            return self.async_abort(reason="unknown")
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                current = await async_probe_certificate(pending[CONF_HOST])
                _raise_for_certificate_validity(current)
                if current.fingerprint != certificate.fingerprint:
                    self._pending_certificate = current
                    certificate = current
                    errors["base"] = "certificate_changed_during_setup"
                else:
                    pending.update(_certificate_data(current))
                    await self._async_validate(pending)
                    return self._save_options(pending)
            except (EMHCASAApiClientError, EMHCASATlsError) as exception:
                errors["base"] = _error_key(exception)

        return self.async_show_form(
            step_id="confirm_certificate",
            data_schema=vol.Schema({}),
            description_placeholders={
                "host": pending[CONF_HOST],
                "fingerprint": certificate.formatted_fingerprint,
                "valid_from": certificate.not_valid_before.isoformat(),
                "valid_until": certificate.not_valid_after.isoformat(),
            },
            errors=errors,
        )

    async def _async_prepare_input(
        self,
        user_input: dict[str, Any],
    ) -> tuple[dict[str, Any], GatewayCertificate | None, bool]:
        """Normalize option input and prepare its TLS settings."""
        prepared = dict(user_input)
        prepared[CONF_HOST] = normalize_host(prepared[CONF_HOST])
        if prepared[CONF_TLS_MODE] != TLS_MODE_PINNED_CERTIFICATE:
            return prepared, None, False

        certificate = await async_probe_certificate(prepared[CONF_HOST])
        _raise_for_certificate_validity(certificate)
        values = self._config_entry.data | self._config_entry.options
        unchanged = (
            prepared[CONF_HOST] == values[CONF_HOST]
            and values.get(CONF_TLS_MODE) == TLS_MODE_PINNED_CERTIFICATE
            and values.get(CONF_TLS_FINGERPRINT) == certificate.fingerprint
        )
        if unchanged:
            prepared.update(_certificate_data(certificate))
        return prepared, certificate, not unchanged

    async def _async_validate(self, prepared: dict[str, Any]) -> None:
        """Validate a normalized option submission."""
        await async_validate_connection(prepared)

    def _save_options(
        self,
        prepared: dict[str, Any],
    ) -> config_entries.ConfigFlowResult:
        """Save validated options and remove obsolete pin data."""
        options = dict(self._config_entry.options) | prepared
        data = dict(self._config_entry.data)
        if prepared[CONF_TLS_MODE] != TLS_MODE_PINNED_CERTIFICATE:
            for key in (CONF_TLS_CERTIFICATE, CONF_TLS_FINGERPRINT):
                options.pop(key, None)
                data.pop(key, None)
        self.hass.config_entries.async_update_entry(self._config_entry, data=data)
        return self.async_create_entry(title="", data=options)

    def _options_schema(self, user_input: dict[str, Any] | None) -> vol.Schema:
        """Build the options schema."""
        values = (
            self._config_entry.data | self._config_entry.options | (user_input or {})
        )
        return vol.Schema(
            {
                vol.Required(
                    CONF_HOST, default=values[CONF_HOST]
                ): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                ),
                vol.Required(
                    CONF_TLS_MODE,
                    default=values.get(CONF_TLS_MODE, DEFAULT_TLS_MODE),
                ): _tls_selector(),
                vol.Required(
                    CONF_USERNAME,
                    default=values[CONF_USERNAME],
                ): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT)
                ),
                vol.Required(
                    CONF_PASSWORD,
                    default=values[CONF_PASSWORD],
                ): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=values.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): _scan_interval_selector(),
            }
        )


def _scan_interval_selector() -> selector.NumberSelector:
    """Return the scan interval selector."""
    return selector.NumberSelector(
        selector.NumberSelectorConfig(
            min=1,
            max=3600,
            step=1,
            mode=selector.NumberSelectorMode.BOX,
            unit_of_measurement="s",
        )
    )
