"""Adds config flow for EMHCASA."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
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
    EMHCASAApiClientCommunicationError,
    EMHCASAApiClientError,
    EMHCASAClient,
)
from .const import CONF_GATEWAY_ID, DEFAULT_SCAN_INTERVAL, DOMAIN, LOGGER

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo


async def async_validate_connection(
    host: str,
    username: str,
    password: str,
) -> str | None:
    """Validate credentials and return a stable gateway identifier if available."""
    async with httpx.AsyncClient(
        verify=False,  # noqa: S501 Gateway uses a self-signed local certificate.
        timeout=20,
        headers={"Connection": "close"},
    ) as http_client:
        client = EMHCASAClient(
            host=host,
            username=username,
            password=password,
            client=http_client,
        )
        try:
            gateway_id = await client.async_get_gateway_id()
        except EMHCASAApiClientError:
            gateway_id = None
        await client.async_get_data()
        return gateway_id


class EMHCASAFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for EMHCASA."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovered_host: str | None = None
        self._discovery_attempted = False

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
        self._discovery_attempted = True
        self._async_abort_entries_match({CONF_HOST: self._discovered_host})
        return await self.async_step_user()

    async def async_step_user(
        self,
        user_input: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Handle a flow initialized by the user."""
        _errors = {}
        if user_input is not None:
            host = user_input[CONF_HOST]
            try:
                gateway_id = await async_validate_connection(
                    host=host,
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                )
            except EMHCASAApiClientAuthenticationError as exception:
                LOGGER.warning(exception)
                _errors["base"] = "auth"
            except EMHCASAApiClientCommunicationError as exception:
                LOGGER.error(exception)
                _errors["base"] = "connection"
            except EMHCASAApiClientError as exception:
                LOGGER.exception(exception)
                _errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(unique_id=gateway_id or slugify(host))
                self._async_abort_entries_match({CONF_HOST: user_input[CONF_HOST]})
                self._abort_if_unique_id_configured()

                entry_data = dict(user_input)
                if gateway_id is not None:
                    entry_data[CONF_GATEWAY_ID] = gateway_id

                return self.async_create_entry(
                    title=gateway_id or host,
                    data=entry_data,
                )

        integration = async_get_loaded_integration(self.hass, DOMAIN)
        assert integration.documentation is not None, (  # noqa: S101
            "Integration documentation URL is not set in manifest.json"
        )

        return self.async_show_form(
            step_id="user",
            description_placeholders={
                "documentation_url": integration.documentation,
            },
            data_schema=self._async_get_user_schema(user_input),
            errors=_errors,
        )

    def _async_get_user_schema(
        self,
        user_input: dict | None,
    ) -> vol.Schema:
        """Build the user step schema."""
        schema: dict[vol.Marker, selector.TextSelector | selector.NumberSelector] = {
            vol.Required(
                CONF_HOST,
                default=(user_input or {}).get(
                    CONF_HOST,
                    self._discovered_host or vol.UNDEFINED,
                ),
            ): selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.TEXT,
                ),
            ),
            vol.Required(
                CONF_USERNAME,
                default=(user_input or {}).get(CONF_USERNAME, vol.UNDEFINED),
            ): selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.TEXT,
                ),
            ),
            vol.Required(CONF_PASSWORD): selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.PASSWORD,
                ),
            ),
            vol.Required(
                CONF_SCAN_INTERVAL,
                default=(user_input or {}).get(
                    CONF_SCAN_INTERVAL,
                    DEFAULT_SCAN_INTERVAL,
                ),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=1,
                    max=3600,
                    step=1,
                    mode=selector.NumberSelectorMode.BOX,
                    unit_of_measurement="s",
                ),
            ),
        }

        return vol.Schema(schema)


class EMHCASAOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle EMH CASA options."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize the options flow."""
        self._config_entry = config_entry

    async def async_step_init(
        self,
        user_input: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Manage the integration options."""
        _errors = {}
        if user_input is not None:
            try:
                await async_validate_connection(
                    host=user_input[CONF_HOST],
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                )
            except EMHCASAApiClientAuthenticationError as exception:
                LOGGER.warning(exception)
                _errors["base"] = "auth"
            except EMHCASAApiClientCommunicationError as exception:
                LOGGER.error(exception)
                _errors["base"] = "connection"
            except EMHCASAApiClientError as exception:
                LOGGER.exception(exception)
                _errors["base"] = "unknown"
            else:
                return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=self._async_get_options_schema(user_input),
            errors=_errors,
        )

    def _async_get_options_schema(
        self,
        user_input: dict | None,
    ) -> vol.Schema:
        """Build the options schema."""
        options = user_input or self._config_entry.options
        schema: dict[vol.Marker, selector.TextSelector | selector.NumberSelector] = {
            vol.Required(
                CONF_HOST,
                default=options.get(
                    CONF_HOST,
                    self._config_entry.data[CONF_HOST],
                ),
            ): selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.TEXT,
                ),
            ),
            vol.Required(
                CONF_USERNAME,
                default=options.get(
                    CONF_USERNAME,
                    self._config_entry.data[CONF_USERNAME],
                ),
            ): selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.TEXT,
                ),
            ),
            vol.Required(
                CONF_PASSWORD,
                default=options.get(
                    CONF_PASSWORD,
                    self._config_entry.data[CONF_PASSWORD],
                ),
            ): selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.PASSWORD,
                ),
            ),
            vol.Required(
                CONF_SCAN_INTERVAL,
                default=options.get(
                    CONF_SCAN_INTERVAL,
                    self._config_entry.data.get(
                        CONF_SCAN_INTERVAL,
                        DEFAULT_SCAN_INTERVAL,
                    ),
                ),
            ): selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=1,
                    max=3600,
                    step=1,
                    mode=selector.NumberSelectorMode.BOX,
                    unit_of_measurement="s",
                ),
            ),
        }
        return vol.Schema(schema)
