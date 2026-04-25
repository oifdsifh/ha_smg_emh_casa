"""Custom types for ha_smg_emh_casa."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.loader import Integration

    from .api import EMHCASAClient
    from .coordinator import EMHCASADataUpdateCoordinator


type EMHCASAConfigEntry = ConfigEntry[EMHCASAData]


@dataclass
class EMHCASAData:
    """Runtime data for the EMHCASA integration."""

    client: EMHCASAClient
    coordinator: EMHCASADataUpdateCoordinator
    integration: Integration
