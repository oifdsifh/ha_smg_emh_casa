"""Shared constants for the ha_smg_emh_casa tests."""

from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)

MOCK_METER_ID = "1emh1234567890"

MOCK_API_DATA = {
    MOCK_METER_ID: {
        "capture_time": "2026-04-03T18:14:43+02:00",
        "status": "a000000010229100",
        "timestamp": "2026-04-03T18:14:43+02:00",
        "values": [
            {
                "logical_name": f"0100010800ff.{MOCK_METER_ID}.sm",
                "scaler": -1,
                "signature": "-",
                "unit": 30,
                "value": "16826471",
            },
            {
                "logical_name": f"0100020800ff.{MOCK_METER_ID}.sm",
                "scaler": -1,
                "signature": "-",
                "unit": 30,
                "value": "1271",
            },
        ],
    },
}

MOCK_GATEWAY_HOST = "192.0.2.25"
MOCK_GATEWAY_ID = "eemh0123456789"

MOCK_CONFIG = {
    CONF_HOST: MOCK_GATEWAY_HOST,
    CONF_USERNAME: "test-user@example.com",
    CONF_PASSWORD: "super-secret",
    CONF_SCAN_INTERVAL: 60,
}
