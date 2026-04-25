"""Constants for ha_smg_emh_casa."""

from decimal import Decimal
from logging import Logger, getLogger

from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
from homeassistant.const import (
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfFrequency,
    UnitOfPower,
)

LOGGER: Logger = getLogger(__package__)

DOMAIN = "ha_smg_emh_casa"
ATTRIBUTION = "Data provided by the EMH CASA gateway."
DEFAULT_SCAN_INTERVAL = 60
CONF_GATEWAY_ID = "gateway_id"

OBIS_CODE_IMPORT_TOTAL = "0100010800ff"
OBIS_CODE_EXPORT_TOTAL = "0100020800ff"

OBIS_SENSOR_METADATA: dict[
    str,
    dict[str, str | SensorDeviceClass | SensorStateClass],
] = {
    OBIS_CODE_IMPORT_TOTAL: {
        "name": "Total import",
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL_INCREASING,
    },
    OBIS_CODE_EXPORT_TOTAL: {
        "name": "Total export",
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL_INCREASING,
    },
}

UNIT_CODE_NORMALIZERS: dict[int, tuple[str, Decimal]] = {
    27: (UnitOfPower.WATT, Decimal(1)),
    30: (UnitOfEnergy.KILO_WATT_HOUR, Decimal("0.001")),
    33: (UnitOfElectricCurrent.AMPERE, Decimal(1)),
    35: (UnitOfElectricPotential.VOLT, Decimal(1)),
    44: (UnitOfFrequency.HERTZ, Decimal(1)),
}
