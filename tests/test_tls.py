"""Tests for EMH CASA TLS helpers."""

from __future__ import annotations

import hashlib
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
    EMHCASATlsVerificationError,
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
CERTIFICATE_NOT_BEFORE = datetime(2025, 1, 1, tzinfo=UTC)
CERTIFICATE_NOT_AFTER = datetime(2045, 1, 1, tzinfo=UTC)
FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_certificate(name: str) -> tuple[bytes, str]:
    """Read synthetic certificate bytes without re-encoding their contents."""
    pem = (FIXTURES / name).read_text()
    return ssl.PEM_cert_to_DER_cert(pem), pem


def _self_signed_certificate(*, legacy_parameters: bool = False) -> tuple[bytes, str]:
    """Return a synthetic legacy certificate or generate a standard one."""
    if legacy_parameters:
        return _fixture_certificate("legacy_certificate.pem")
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "gateway.example.test")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(CERTIFICATE_NOT_BEFORE)
        .not_valid_after(CERTIFICATE_NOT_AFTER)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("gateway.example.test")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    return der, ssl.DER_cert_to_PEM_cert(der)


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


@pytest.mark.parametrize("legacy_parameters", [False, True])
async def test_probe_certificate_only_performs_tls_handshake(
    *,
    legacy_parameters: bool,
) -> None:
    """Certificate discovery should read the peer certificate without HTTP."""
    certificate_der, certificate_pem = _self_signed_certificate(
        legacy_parameters=legacy_parameters
    )
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
    assert certificate.not_valid_before == CERTIFICATE_NOT_BEFORE
    assert certificate.not_valid_after == CERTIFICATE_NOT_AFTER
    assert certificate.validity_error is None
    open_connection.assert_awaited_once()
    connection_call = open_connection.await_args
    assert connection_call is not None
    assert connection_call.kwargs["host"] == "gateway.example.test"
    assert connection_call.kwargs["port"] == TEST_HTTPS_PORT
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


@pytest.mark.parametrize("certificate_der", [b"", b"invalid", b"\x30\x00"])
async def test_probe_rejects_unreadable_certificate(certificate_der: bytes) -> None:
    """Invalid certificate metadata should raise a handled TLS error."""
    with (
        patch(
            "custom_components.ha_smg_emh_casa.tls._async_open_tls",
            new=AsyncMock(return_value=certificate_der),
        ),
        pytest.raises(EMHCASATlsVerificationError, match="validity dates"),
    ):
        await async_probe_certificate("gateway.example.test")


async def test_probe_rejects_trailing_certificate_data() -> None:
    """Certificate decoding must not ignore bytes after the DER certificate."""
    certificate_der, _ = _self_signed_certificate()
    with (
        patch(
            "custom_components.ha_smg_emh_casa.tls._async_open_tls",
            new=AsyncMock(return_value=certificate_der + b"trailing data"),
        ),
        pytest.raises(EMHCASATlsVerificationError),
    ):
        await async_probe_certificate("gateway.example.test")


async def test_probe_supports_certificate_without_version_or_extensions() -> None:
    """X.509 v1 certificates should use the default version and omit extensions."""
    certificate_der, _ = _fixture_certificate("v1_certificate.pem")
    with patch(
        "custom_components.ha_smg_emh_casa.tls._async_open_tls",
        new=AsyncMock(return_value=certificate_der),
    ):
        metadata = await async_probe_certificate("gateway.example.test")

    assert metadata.pem == ssl.DER_cert_to_PEM_cert(certificate_der)
    assert metadata.not_valid_before == CERTIFICATE_NOT_BEFORE
    assert metadata.not_valid_after == CERTIFICATE_NOT_AFTER


async def test_probe_rejects_reversed_validity_dates() -> None:
    """A certificate validity interval must not end before it starts."""
    certificate_der, _ = _fixture_certificate("reversed_validity_certificate.pem")
    with (
        patch(
            "custom_components.ha_smg_emh_casa.tls._async_open_tls",
            new=AsyncMock(return_value=certificate_der),
        ),
        pytest.raises(EMHCASATlsVerificationError, match="Invalid gateway"),
    ):
        await async_probe_certificate("gateway.example.test")


@pytest.mark.parametrize(
    ("fixture", "not_before", "not_after", "error"),
    [
        (
            "legacy_expired_certificate.pem",
            datetime(2020, 1, 1, tzinfo=UTC),
            datetime(2021, 1, 1, tzinfo=UTC),
            "certificate_expired",
        ),
        (
            "legacy_future_certificate.pem",
            datetime(2090, 1, 1, tzinfo=UTC),
            datetime(2091, 1, 1, tzinfo=UTC),
            "certificate_not_yet_valid",
        ),
    ],
)
async def test_legacy_certificate_validity_is_checked(
    fixture: str,
    not_before: datetime,
    not_after: datetime,
    error: str,
) -> None:
    """Legacy algorithm parameters must not bypass validity checks."""
    certificate_der, _ = _fixture_certificate(fixture)
    with patch(
        "custom_components.ha_smg_emh_casa.tls._async_open_tls",
        new=AsyncMock(return_value=certificate_der),
    ):
        metadata = await async_probe_certificate("gateway.example.test")

    assert metadata.not_valid_before == not_before
    assert metadata.not_valid_after == not_after
    assert metadata.validity_error == error


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
