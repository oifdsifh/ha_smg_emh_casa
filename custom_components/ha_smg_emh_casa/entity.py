"""Base entity for the EMHCASA integration."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import ATTRIBUTION
from .coordinator import EMHCASADataUpdateCoordinator


class EMHCASAEntity(CoordinatorEntity[EMHCASADataUpdateCoordinator]):
    """Shared entity implementation for EMHCASA."""

    _attr_attribution = ATTRIBUTION

    def __init__(
        self,
        coordinator: EMHCASADataUpdateCoordinator,
        meter_id: str,
    ) -> None:
        """Initialize."""
        super().__init__(coordinator)
        self.meter_id = meter_id
        self._attr_device_info = DeviceInfo(
            identifiers={
                (
                    coordinator.config_entry.domain,
                    f"{coordinator.config_entry.entry_id}_{meter_id}",
                ),
            },
            manufacturer="EMH metering GmbH & Co. KG",
            model="CASA",
            name=meter_id,
            serial_number=meter_id,
        )
