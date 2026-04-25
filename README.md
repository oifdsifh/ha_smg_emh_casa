# ha_smg_emh_casa

Home Assistant custom integration for the EMH CASA gateway.

This integration connects to your local EMH CASA device, authenticates with the
gateway, fetches available meter data, and creates Home Assistant sensors for
the readings it exposes. It supports UI setup and local network discovery.

> [!IMPORTANT]
> This project is independent and is not affiliated with, endorsed by, or
> supported by EMH.

## Features

- Connects directly to the EMH CASA gateway on your local network
- Discovers connected meters and reads their latest values
- Creates Home Assistant sensor entities for supported OBIS readings
- Supports configuration through the Home Assistant UI
- Supports zeroconf discovery

## Installation via HACS

1. Open HACS in Home Assistant.
2. Go to `Integrations`.
3. Open the menu in the top right and select `Custom repositories`.
4. Add `https://github.com/oifdsifh/ha_smg_emh_casa` as an `Integration`
   repository.
5. Search for `EMH CASA` in HACS and install it.
6. Restart Home Assistant.

## Setup

1. In Home Assistant, go to `Settings` > `Devices & Services`.
2. Click `Add Integration`.
3. Search for `EMH CASA`.
4. Enter the gateway host, username, and password.
5. Finish the setup flow. After a successful connection, sensors will be
   created automatically.

If your gateway is discovered automatically, Home Assistant may already offer
the integration for setup.
