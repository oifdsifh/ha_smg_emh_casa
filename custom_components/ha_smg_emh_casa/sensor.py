"""Sensor platform for ha_smg_emh_casa."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import UnitOfEnergy

from .const import OBIS_SENSOR_METADATA, UNIT_CODE_NORMALIZERS
from .entity import EMHCASAEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import EMHCASADataUpdateCoordinator
    from .data import EMHCASAConfigEntry


@dataclass(frozen=True, slots=True)
class MeterValueDescription:
    """Metadata used to describe a meter reading entity."""

    logical_name: str
    obis_code: str
    name: str
    native_unit_of_measurement: str | None
    device_class: SensorDeviceClass | None
    state_class: SensorStateClass | None
    suggested_display_precision: int | None


def _extract_obis_code(logical_name: str) -> str:
    """Return the OBIS code prefix from a logical name."""
    return logical_name.split(".", maxsplit=1)[0]


def _build_value_description(value: dict[str, Any]) -> MeterValueDescription | None:
    """Build entity metadata for a meter value."""
    logical_name = value.get("logical_name")
    if not isinstance(logical_name, str):
        return None

    obis_code = _extract_obis_code(logical_name)
    metadata = OBIS_SENSOR_METADATA.get(obis_code, {})

    native_unit_of_measurement = None
    suggested_display_precision = None
    device_class = metadata.get("device_class")
    state_class = metadata.get("state_class")

    unit_code = value.get("unit")
    if isinstance(unit_code, int) and unit_code in UNIT_CODE_NORMALIZERS:
        native_unit_of_measurement = UNIT_CODE_NORMALIZERS[unit_code][0]
        if native_unit_of_measurement == UnitOfEnergy.KILO_WATT_HOUR:
            suggested_display_precision = 4
        elif native_unit_of_measurement in {"A", "V", "Hz"}:
            suggested_display_precision = 2

    name = str(metadata.get("name") or f"Reading {obis_code}")

    return MeterValueDescription(
        logical_name=logical_name,
        obis_code=obis_code,
        name=name,
        native_unit_of_measurement=native_unit_of_measurement,
        device_class=(
            device_class if isinstance(device_class, SensorDeviceClass) else None
        ),
        state_class=state_class if isinstance(state_class, SensorStateClass) else None,
        suggested_display_precision=suggested_display_precision,
    )


def _discover_meter_descriptions(
    coordinator: EMHCASADataUpdateCoordinator,
) -> dict[tuple[str, str], MeterValueDescription]:
    """Collect all known meter values from coordinator data."""
    descriptions: dict[tuple[str, str], MeterValueDescription] = {}
    data = coordinator.data or {}

    for meter_id, meter_data in data.items():
        values = meter_data.get("values", [])
        if not isinstance(values, list):
            continue

        for value in values:
            if not isinstance(value, dict):
                continue

            description = _build_value_description(value)
            if description is None:
                continue

            descriptions[(meter_id, description.logical_name)] = description

    return descriptions


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001 Unused function argument: `hass`
    entry: EMHCASAConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the sensor platform."""
    coordinator = entry.runtime_data.coordinator
    known_sensors: set[tuple[str, str]] = set()

    def _add_new_entities() -> None:
        new_entities: list[EMHCASAMeterValueSensor] = []
        descriptions = _discover_meter_descriptions(coordinator)
        for sensor_key, description in descriptions.items():
            if sensor_key in known_sensors:
                continue

            meter_id, _ = sensor_key
            known_sensors.add(sensor_key)
            new_entities.append(
                EMHCASAMeterValueSensor(
                    coordinator=coordinator,
                    meter_id=meter_id,
                    value_description=description,
                ),
            )

        if new_entities:
            async_add_entities(new_entities)

    _add_new_entities()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_entities))


class EMHCASAMeterValueSensor(EMHCASAEntity, SensorEntity):
    """Sensor entity for a single value reported by a meter."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EMHCASADataUpdateCoordinator,
        meter_id: str,
        value_description: MeterValueDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, meter_id)
        self._value_description = value_description
        self.entity_description = SensorEntityDescription(
            key=value_description.logical_name,
            name=value_description.name,
            device_class=value_description.device_class,
            native_unit_of_measurement=value_description.native_unit_of_measurement,
            state_class=value_description.state_class,
            suggested_display_precision=value_description.suggested_display_precision,
        )
        self._attr_unique_id = (
            f"{coordinator.config_entry.entry_id}_"
            f"{meter_id}_{value_description.logical_name}"
        )

    @property
    def _meter_data(self) -> dict[str, Any]:
        """Return the current payload for this meter."""
        return (self.coordinator.data or {}).get(self.meter_id, {})

    @property
    def _value_payload(self) -> dict[str, Any] | None:
        """Return the current payload for this sensor."""
        values = self._meter_data.get("values", [])
        if not isinstance(values, list):
            return None

        for value in values:
            if (
                isinstance(value, dict)
                and value.get("logical_name") == self._value_description.logical_name
            ):
                return value

        return None

    @property
    def native_value(self) -> Decimal | str | None:
        """Return the normalized sensor value."""
        value_payload = self._value_payload
        if value_payload is None:
            return None

        raw_value = value_payload.get("value")
        if raw_value is None:
            return None

        scaler = value_payload.get("scaler", 0)
        unit_code = value_payload.get("unit")

        try:
            normalized_value = Decimal(str(raw_value)) * (Decimal(10) ** int(scaler))
        except InvalidOperation, TypeError, ValueError:
            return str(raw_value)

        if isinstance(unit_code, int) and unit_code in UNIT_CODE_NORMALIZERS:
            normalized_value *= UNIT_CODE_NORMALIZERS[unit_code][1]

        return normalized_value

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose meter metadata alongside the reading."""
        meter_data = self._meter_data
        value_payload = self._value_payload or {}
        return {
            "meter_id": self.meter_id,
            "logical_name": self._value_description.logical_name,
            "obis_code": self._value_description.obis_code,
            "capture_time": meter_data.get("capture_time"),
            "timestamp": meter_data.get("timestamp"),
            "status": meter_data.get("status"),
            "signature": value_payload.get("signature"),
            "raw_value": value_payload.get("value"),
            "scaler": value_payload.get("scaler"),
            "unit_code": value_payload.get("unit"),
        }
