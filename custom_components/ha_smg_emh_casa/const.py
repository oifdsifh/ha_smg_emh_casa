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
CONFIG_ENTRY_MINOR_VERSION = 2
CONF_GATEWAY_ID = "gateway_id"
CONF_TLS_MODE = "tls_mode"
CONF_TLS_CERTIFICATE = "tls_certificate"
CONF_TLS_FINGERPRINT = "tls_fingerprint"

TLS_MODE_PINNED_CERTIFICATE = "pinned_certificate"
TLS_MODE_TRUSTED_CERTIFICATE = "trusted_certificate"
TLS_MODE_INSECURE = "insecure"
TLS_MODES = (
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODE_TRUSTED_CERTIFICATE,
    TLS_MODE_INSECURE,
)
DEFAULT_TLS_MODE = TLS_MODE_PINNED_CERTIFICATE

ISSUE_CERTIFICATE_CHANGED = "certificate_changed"
ISSUE_CERTIFICATE_INVALID = "certificate_invalid"
ISSUE_HTTPS_MIGRATION_FAILED = "https_migration_failed"

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
