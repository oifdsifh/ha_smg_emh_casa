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
- Offers certificate pinning, normal certificate validation, and an explicit
  insecure compatibility mode

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
4. Enter the gateway host and choose how Home Assistant should check its TLS
   certificate.
5. If you choose certificate pinning, review and accept the SHA-256 fingerprint
   shown by the gateway before entering your username and password.
6. Finish the setup flow. After a successful connection, sensors will be
   created automatically.

If your gateway is discovered automatically, Home Assistant may already offer
the integration for setup.

## TLS certificate checking

The integration always connects over HTTPS and offers three choices:

- **Trust and remember this gateway certificate** is the default and is
  intended for a direct connection to a factory gateway or a reverse proxy with
  a self-signed certificate. Home Assistant saves the certificate accepted
  during setup. If it changes, requests stop before credentials are sent and a
  Repair shows the old and new fingerprints for explicit approval.
- **Use a certificate trusted by Home Assistant** performs normal certificate
  authority and hostname validation. Choose this for a reverse proxy using a
  publicly trusted certificate, such as a Let's Encrypt certificate. Normal
  certificate renewals continue without approval as long as the certificate
  remains valid for the configured hostname.
- **Do not check the certificate (insecure)** preserves encrypted HTTPS but does
  not authenticate the gateway. An attacker able to intercept local traffic
  could impersonate the gateway and observe the authentication exchange and
  returned meter data. This mode should only be used when neither verified mode
  is possible.
