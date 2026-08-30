"""Tests for EMH CASA TLS helpers."""

from __future__ import annotations

import hashlib
import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from custom_components.ha_smg_emh_casa.const import (
    TLS_MODE_INSECURE,
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODE_TRUSTED_CERTIFICATE,
)
from custom_components.ha_smg_emh_casa.tls import (
    EMHCASAHttpNotAllowedError,
    EMHCASAInvalidHostError,
    GatewayCertificate,
    async_probe_certificate,
    async_test_trusted_certificate,
    create_httpx_client,
    create_pinned_ssl_context,
    is_certificate_verification_error,
    normalize_host,
    normalize_legacy_host,
)

TEST_HTTPS_PORT = 8443


def _self_signed_certificate() -> tuple[bytes, str]:
    """Create a short-lived self-signed gateway certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "gateway.example.test")]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("gateway.example.test")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    return der, certificate.public_bytes(serialization.Encoding.PEM).decode()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.0.2.25", "192.0.2.25"),
        ("gateway.example.test", "gateway.example.test"),
        ("gateway.example.test:8443", "gateway.example.test:8443"),
        ("https://gateway.example.test", "gateway.example.test"),
        ("https://gateway.example.test:8443", "gateway.example.test:8443"),
        ("2001:db8::25", "[2001:db8::25]"),
        ("[2001:db8::25]:8443", "[2001:db8::25]:8443"),
    ],
)
def test_normalize_host(value: str, expected: str) -> None:
    """Valid host forms should normalize to an HTTPS authority."""
    assert normalize_host(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://gateway.example.test",
        "https://gateway.example.test/",
        "https://user:secret@gateway.example.test",
        "https://gateway.example.test/path",
        "https://gateway.example.test?query=yes",
        "https://gateway.example.test#fragment",
    ],
)
def test_normalize_host_rejects_invalid_values(value: str) -> None:
    """Hosts must not contain URL features outside an HTTPS authority."""
    with pytest.raises(EMHCASAInvalidHostError):
        normalize_host(value)


def test_normalize_host_rejects_http() -> None:
    """New configuration must not allow explicit HTTP."""
    with pytest.raises(EMHCASAHttpNotAllowedError):
        normalize_host("http://gateway.example.test")


def test_normalize_legacy_host_upgrades_http() -> None:
    """Migration should try the corresponding HTTPS authority."""
    assert normalize_legacy_host("http://gateway.example.test:8443") == (
        "gateway.example.test:8443",
        True,
    )


async def test_probe_certificate_only_performs_tls_handshake() -> None:
    """Certificate discovery should read the peer certificate without HTTP."""
    certificate_der, certificate_pem = _self_signed_certificate()
    ssl_object = MagicMock()
    ssl_object.getpeercert.return_value = certificate_der
    writer = MagicMock()
    writer.get_extra_info.return_value = ssl_object
    writer.wait_closed = AsyncMock()

    with patch(
        "custom_components.ha_smg_emh_casa.tls.asyncio.open_connection",
        new=AsyncMock(return_value=(AsyncMock(), writer)),
    ) as open_connection:
        certificate = await async_probe_certificate("gateway.example.test:8443")

    assert certificate.pem == certificate_pem
    assert certificate.fingerprint == hashlib.sha256(certificate_der).hexdigest()
    open_connection.assert_awaited_once()
    connection_call = open_connection.await_args
    assert connection_call is not None
    assert connection_call.kwargs["host"] == "gateway.example.test"
    assert connection_call.kwargs["port"] == TEST_HTTPS_PORT
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


async def test_trusted_probe_uses_verifying_context() -> None:
    """Trusted mode should perform a verified TLS handshake."""
    with patch(
        "custom_components.ha_smg_emh_casa.tls._async_open_tls",
        new=AsyncMock(return_value=b"certificate"),
    ) as open_tls:
        await async_test_trusted_certificate("gateway.example.test")

    open_tls_call = open_tls.await_args
    assert open_tls_call is not None
    context = open_tls_call.args[1]
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname


def test_pinned_context_verifies_without_hostname() -> None:
    """Pinned mode should trust the saved certificate and its validity."""
    _, certificate_pem = _self_signed_certificate()
    context = create_pinned_ssl_context(certificate_pem)

    assert context.verify_mode is ssl.CERT_REQUIRED
    assert not context.check_hostname
    assert context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


@pytest.mark.parametrize(
    ("tls_mode", "expected"),
    [
        (TLS_MODE_TRUSTED_CERTIFICATE, (ssl.CERT_REQUIRED, True)),
        (TLS_MODE_INSECURE, (ssl.CERT_NONE, False)),
    ],
)
async def test_httpx_client_tls_modes(
    tls_mode: str,
    expected: tuple[ssl.VerifyMode, bool],
) -> None:
    """Runtime HTTPX clients should use the selected TLS behavior."""
    verify_mode, check_hostname = expected
    with patch(
        "custom_components.ha_smg_emh_casa.tls.httpx.AsyncClient",
        wraps=httpx.AsyncClient,
    ) as client_class:
        client = create_httpx_client(tls_mode)
    try:
        client_call = client_class.call_args
        assert client_call is not None
        context = client_call.kwargs["verify"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode is verify_mode
        assert context.check_hostname is check_hostname
        assert client_call.kwargs["follow_redirects"] is False
    finally:
        await client.aclose()


async def test_httpx_pinned_client_uses_saved_certificate() -> None:
    """Pinned HTTPX clients should use the dedicated pinning context."""
    _, certificate_pem = _self_signed_certificate()
    with patch(
        "custom_components.ha_smg_emh_casa.tls.httpx.AsyncClient",
        wraps=httpx.AsyncClient,
    ) as client_class:
        client = create_httpx_client(
            TLS_MODE_PINNED_CERTIFICATE,
            certificate_pem,
        )
    try:
        client_call = client_class.call_args
        assert client_call is not None
        context = client_call.kwargs["verify"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert not context.check_hostname
    finally:
        await client.aclose()


def test_gateway_certificate_validity() -> None:
    """Certificate metadata should distinguish validity failures."""
    now = datetime.now(UTC)
    expired = GatewayCertificate(
        "pem", "00" * 32, now - timedelta(2), now - timedelta(1)
    )
    future = GatewayCertificate(
        "pem", "00" * 32, now + timedelta(1), now + timedelta(2)
    )
    valid = GatewayCertificate("pem", "00" * 32, now - timedelta(1), now + timedelta(1))

    assert expired.validity_error == "certificate_expired"
    assert future.validity_error == "certificate_not_yet_valid"
    assert valid.validity_error is None


def test_detects_nested_certificate_verification_error() -> None:
    """HTTPX wrappers should not hide TLS verification failures."""
    with pytest.raises(httpx.ConnectError) as error:
        _raise_nested_certificate_error()

    assert is_certificate_verification_error(error.value)


def _raise_nested_certificate_error() -> None:
    """Raise an HTTPX error caused by certificate verification."""
    cause = ssl.SSLCertVerificationError("certificate verify failed")
    msg = "[SSL: CERTIFICATE_VERIFY_FAILED]"
    raise httpx.ConnectError(msg) from cause
