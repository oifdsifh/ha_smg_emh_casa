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
2. Start the setup in one of these ways:
   - Select the discovered EMH CASA gateway if Home Assistant already offers
     it. The gateway host will be prefilled.
   - Otherwise, click `Add Integration` and search for `EMH CASA`.
3. Enter or confirm the gateway host, then choose how Home Assistant should
   check its TLS certificate.
4. If you choose **Trust and remember this gateway certificate**, review the
   SHA-256 fingerprint and certificate validity dates. Compare the fingerprint
   with one obtained directly from the gateway if possible, then accept it.
   The trusted-certificate and insecure modes skip this confirmation step.
5. Enter the username and password for the EMH CASA user portal and choose the
   scan interval in seconds.
6. Submit the form. The integration checks the connection according to the
   selected TLS mode, authenticates, and verifies that it can fetch meter data.
7. If validation fails, review the error shown in the flow, correct the relevant
   setting, and submit it again.
8. After successful validation, the flow reports if the gateway is already
   configured. Otherwise, it creates the config entry and the sensors appear
   automatically.

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
