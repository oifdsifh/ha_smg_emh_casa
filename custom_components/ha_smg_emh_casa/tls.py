"""TLS helpers for the EMH CASA integration."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import ssl
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from homeassistant.util.ssl import (
    SSL_ALPN_HTTP11,
    client_context,
    create_no_verify_ssl_context,
)

from .const import (
    TLS_MODE_INSECURE,
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODE_TRUSTED_CERTIFICATE,
)

TLS_TIMEOUT = 20
HTTPS_PORT = 443
IPV6_MINIMUM_COLONS = 2


class EMHCASATlsError(Exception):
    """Base exception for TLS configuration errors."""


class EMHCASAInvalidHostError(EMHCASATlsError):
    """The configured host is not a valid gateway authority."""


class EMHCASAHttpNotAllowedError(EMHCASATlsError):
    """The configured host explicitly uses HTTP."""


class EMHCASATlsConnectionError(EMHCASATlsError):
    """The TLS endpoint could not be reached."""


class EMHCASATlsVerificationError(EMHCASATlsError):
    """The TLS certificate could not be verified."""


class EMHCASACertificateValidityError(EMHCASATlsError):
    """The presented TLS certificate is not currently valid."""

    def __init__(self, reason: str) -> None:
        """Initialize the validity error."""
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class GatewayCertificate:
    """Certificate details collected without an HTTP request."""

    pem: str
    fingerprint: str
    not_valid_before: datetime
    not_valid_after: datetime

    @property
    def formatted_fingerprint(self) -> str:
        """Return the fingerprint in a human-readable form."""
        return ":".join(
            self.fingerprint[index : index + 2].upper()
            for index in range(0, len(self.fingerprint), 2)
        )

    @property
    def validity_error(self) -> str | None:
        """Return a translation key when the certificate is not currently valid."""
        now = datetime.now(UTC)
        if now < self.not_valid_before:
            return "certificate_not_yet_valid"
        if now > self.not_valid_after:
            return "certificate_expired"
        return None


def normalize_host(host: str) -> str:
    """Validate a gateway host and normalize it to an HTTPS authority."""
    value = host.strip()
    if not value:
        raise EMHCASAInvalidHostError

    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() == "http":
            raise EMHCASAHttpNotAllowedError
        if parsed.scheme.lower() != "https":
            raise EMHCASAInvalidHostError
    elif value.count(":") >= IPV6_MINIMUM_COLONS and not value.startswith("["):
        try:
            ipaddress.ip_address(value)
        except ValueError as exception:
            raise EMHCASAInvalidHostError from exception
        return f"[{value}]"
    else:
        parsed = urlsplit(f"//{value}")

    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise EMHCASAInvalidHostError

    try:
        port = parsed.port
    except ValueError as exception:
        raise EMHCASAInvalidHostError from exception

    hostname = parsed.hostname.rstrip(".")
    if not hostname or any(character.isspace() for character in hostname):
        raise EMHCASAInvalidHostError

    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != HTTPS_PORT:
        authority = f"{authority}:{port}"
    return authority


def normalize_legacy_host(host: str) -> tuple[str, bool]:
    """Normalize an existing host, upgrading an explicit HTTP URL to HTTPS."""
    value = host.strip()
    if value.lower().startswith("http://"):
        value = f"https://{value[7:]}"
        return normalize_host(value), True
    return normalize_host(value), False


def _split_authority(authority: str) -> tuple[str, int]:
    """Split a normalized authority into hostname and port."""
    parsed = urlsplit(f"//{authority}")
    if parsed.hostname is None:
        raise EMHCASAInvalidHostError
    return parsed.hostname, parsed.port or HTTPS_PORT


def _certificate_from_der(certificate_der: bytes) -> GatewayCertificate:
    """Build certificate metadata from a DER encoded certificate."""
    certificate = x509.load_der_x509_certificate(certificate_der)
    return GatewayCertificate(
        pem=ssl.DER_cert_to_PEM_cert(certificate_der),
        fingerprint=hashlib.sha256(certificate_der).hexdigest(),
        not_valid_before=certificate.not_valid_before_utc,
        not_valid_after=certificate.not_valid_after_utc,
    )


async def _async_open_tls(
    host: str,
    context: ssl.SSLContext,
) -> bytes:
    """Open TLS without sending HTTP data and return the peer certificate."""
    hostname, port = _split_authority(host)
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(TLS_TIMEOUT):
            _, writer = await asyncio.open_connection(
                host=hostname,
                port=port,
                ssl=context,
                server_hostname=hostname,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None or not (
                certificate_der := ssl_object.getpeercert(binary_form=True)
            ):
                msg = "The gateway did not present a TLS certificate"
                raise EMHCASATlsConnectionError(msg)
            return certificate_der
    except ssl.SSLCertVerificationError as exception:
        raise EMHCASATlsVerificationError(str(exception)) from exception
    except (TimeoutError, OSError, ssl.SSLError) as exception:
        raise EMHCASATlsConnectionError(str(exception)) from exception
    finally:
        if writer is not None:
            writer.close()
            with suppress(OSError, ssl.SSLError):
                await writer.wait_closed()


async def async_probe_certificate(host: str) -> GatewayCertificate:
    """Read the presented certificate without sending an HTTP request."""
    context = create_no_verify_ssl_context(alpn_protocols=SSL_ALPN_HTTP11)
    certificate_der = await _async_open_tls(host, context)
    return _certificate_from_der(certificate_der)


async def async_test_trusted_certificate(host: str) -> None:
    """Validate the TLS endpoint with Home Assistant's trusted CA context."""
    await _async_open_tls(
        host,
        client_context(alpn_protocols=SSL_ALPN_HTTP11),
    )


def create_pinned_ssl_context(certificate_pem: str) -> ssl.SSLContext:
    """Create a TLS context that trusts the pinned gateway certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=certificate_pem)
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    if SSL_ALPN_HTTP11 is not None:
        context.set_alpn_protocols(SSL_ALPN_HTTP11)
    return context


def create_httpx_client(
    tls_mode: str,
    certificate_pem: str | None = None,
) -> httpx.AsyncClient:
    """Create an integration-owned HTTPX client for the selected TLS mode."""
    if tls_mode == TLS_MODE_PINNED_CERTIFICATE:
        if certificate_pem is None:
            msg = "Pinned TLS mode requires a stored certificate"
            raise EMHCASATlsError(msg)
        context = create_pinned_ssl_context(certificate_pem)
    elif tls_mode == TLS_MODE_TRUSTED_CERTIFICATE:
        context = client_context(alpn_protocols=SSL_ALPN_HTTP11)
    elif tls_mode == TLS_MODE_INSECURE:
        context = create_no_verify_ssl_context(alpn_protocols=SSL_ALPN_HTTP11)
    else:
        msg = f"Unsupported TLS mode: {tls_mode}"
        raise EMHCASATlsError(msg)

    return httpx.AsyncClient(
        verify=context,
        timeout=TLS_TIMEOUT,
        headers={"Connection": "close"},
        follow_redirects=False,
    )


def is_certificate_verification_error(exception: BaseException) -> bool:
    """Return whether an exception chain contains a TLS verification failure."""
    current: BaseException | None = exception
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError) or (
            "CERTIFICATE_VERIFY_FAILED" in str(current)
        ):
            return True
        current = current.__cause__ or current.__context__
    return False
