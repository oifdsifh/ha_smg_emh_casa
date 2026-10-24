"""Gateway and HAN account identities shared by configuration flows."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import SOURCE_IGNORE
from homeassistant.const import CONF_HOST, CONF_USERNAME

from .const import (
    CONF_GATEWAY_ID,
    CONF_TLS_CERTIFICATE,
    CONF_TLS_FINGERPRINT,
    CONF_TLS_MODE,
    DOMAIN,
    TLS_MODE_PINNED_CERTIFICATE,
)
from .tls import EMHCASAInvalidHostError, normalize_legacy_host

if TYPE_CHECKING:
    from collections.abc import Mapping

    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant


def account_unique_id(settings: Mapping[str, Any]) -> str:
    """Encode the gateway and exact username without delimiter collisions."""
    return json.dumps(
        [settings[CONF_GATEWAY_ID], settings[CONF_USERNAME]],
        separators=(",", ":"),
    )


def account_title(settings: Mapping[str, Any]) -> str:
    """Return the initial hub name for one HAN account."""
    return f"{settings[CONF_GATEWAY_ID]} ({settings[CONF_USERNAME]})"


def same_gateway_host(first: str, second: str) -> bool:
    """Compare normalized hosts without blocking repairs of invalid old settings."""
    try:
        return normalize_legacy_host(first)[0] == normalize_legacy_host(second)[0]
    except EMHCASAInvalidHostError:
        return False


def is_duplicate_account(
    hass: HomeAssistant,
    settings: Mapping[str, Any],
    current_entry: ConfigEntry | None = None,
) -> bool:
    """Compare effective accounts, including legacy entries and host aliases."""
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry is current_entry or entry.source == SOURCE_IGNORE:
            continue
        values = entry.data | entry.options
        if values.get(CONF_USERNAME) != settings[CONF_USERNAME]:
            continue
        if values.get(CONF_GATEWAY_ID) == settings[CONF_GATEWAY_ID]:
            return True
        if same_gateway_host(values[CONF_HOST], settings[CONF_HOST]):
            return True
    return False


def account_entry_updates(
    entry: ConfigEntry,
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    """Prepare an identity/settings update without changing titles or entity IDs."""
    values = entry.data | entry.options
    data = dict(entry.data)
    data[CONF_GATEWAY_ID] = settings[CONF_GATEWAY_ID]
    options = dict(entry.options) | dict(settings)
    options.pop(CONF_GATEWAY_ID, None)
    if settings[CONF_TLS_MODE] != TLS_MODE_PINNED_CERTIFICATE:
        for key in (CONF_TLS_CERTIFICATE, CONF_TLS_FINGERPRINT):
            options.pop(key, None)
            data.pop(key, None)
    updates: dict[str, Any] = {
        "data": data,
        "options": options,
    }
    if (
        values.get(CONF_GATEWAY_ID) != settings[CONF_GATEWAY_ID]
        or values[CONF_USERNAME] != settings[CONF_USERNAME]
    ):
        updates["unique_id"] = account_unique_id(settings)
    return updates
