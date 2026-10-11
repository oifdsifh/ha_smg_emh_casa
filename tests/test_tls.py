"""Tests for EMH CASA TLS helpers."""

from __future__ import annotations

import hashlib
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from custom_components.ha_smg_emh_casa.const import (
    TLS_MODE_INSECURE,
    TLS_MODE_PINNED_CERTIFICATE,
    TLS_MODE_TRUSTED_CERTIFICATE,
)
from custom_components.ha_smg_emh_casa.tls import (
    EMHCASAHttpNotAllowedError,
    EMHCASAInvalidHostError,
    EMHCASATlsConnectionError,
    EMHCASATlsVerificationError,
    async_probe_certificate,
    async_test_trusted_certificate,
    create_httpx_client,
    create_pinned_ssl_context,
    is_certificate_verification_error,
    normalize_host,
    normalize_legacy_host,
)

TEST_HTTPS_PORT = 8443
CERTIFICATE_DER = b"gateway certificate"
CERTIFICATE_PEM = ssl.DER_cert_to_PEM_cert(CERTIFICATE_DER)


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
    ssl_object = MagicMock()
    ssl_object.getpeercert.return_value = CERTIFICATE_DER
    writer = MagicMock()
    writer.get_extra_info.return_value = ssl_object
    writer.wait_closed = AsyncMock()

    with patch(
        "custom_components.ha_smg_emh_casa.tls.asyncio.open_connection",
        new=AsyncMock(return_value=(AsyncMock(), writer)),
    ) as open_connection:
        certificate = await async_probe_certificate("gateway.example.test:8443")

    assert certificate.pem == CERTIFICATE_PEM
    assert certificate.fingerprint == hashlib.sha256(CERTIFICATE_DER).hexdigest()
    open_connection.assert_awaited_once()
    connection_call = open_connection.await_args
    assert connection_call is not None
    assert connection_call.kwargs["host"] == "gateway.example.test"
    assert connection_call.kwargs["port"] == TEST_HTTPS_PORT
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


async def test_pinned_probe_verifies_in_one_handshake() -> None:
    """The normal polling probe must validate the saved pin without extra IO."""
    with (
        patch(
            "custom_components.ha_smg_emh_casa.tls.ssl.SSLContext.load_verify_locations"
        ) as load_certificate,
        patch(
            "custom_components.ha_smg_emh_casa.tls._async_open_tls",
            new=AsyncMock(return_value=CERTIFICATE_DER),
        ) as open_tls,
        patch(
            "custom_components.ha_smg_emh_casa.tls.create_pinned_ssl_context",
            wraps=create_pinned_ssl_context,
        ) as pinned_context,
    ):
        certificate = await async_probe_certificate(
            "gateway.example.test", CERTIFICATE_PEM
        )

    assert certificate.pem == CERTIFICATE_PEM
    pinned_context.assert_called_once_with(CERTIFICATE_PEM)
    load_certificate.assert_called_once_with(cadata=CERTIFICATE_PEM)
    open_tls.assert_awaited_once()
    context = open_tls.await_args.args[1]
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert not context.check_hostname
    assert context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


async def test_probe_translates_verification_failure() -> None:
    """TLS verification failures should become integration-specific errors."""
    with (
        patch(
            "custom_components.ha_smg_emh_casa.tls.ssl.SSLContext.load_verify_locations"
        ),
        patch(
            "custom_components.ha_smg_emh_casa.tls.asyncio.open_connection",
            new=AsyncMock(
                side_effect=ssl.SSLCertVerificationError("certificate verify failed")
            ),
        ),
        pytest.raises(EMHCASATlsVerificationError, match="certificate verify failed"),
    ):
        await async_probe_certificate("gateway.example.test", CERTIFICATE_PEM)


async def test_probe_rejects_missing_peer_certificate() -> None:
    """Discovery cannot produce a fingerprint when the TLS peer has no certificate."""
    writer = MagicMock()
    writer.get_extra_info.return_value = None
    writer.wait_closed = AsyncMock()
    with (
        patch(
            "custom_components.ha_smg_emh_casa.tls.asyncio.open_connection",
            new=AsyncMock(return_value=(AsyncMock(), writer)),
        ),
        pytest.raises(EMHCASATlsConnectionError, match="did not present"),
    ):
        await async_probe_certificate("gateway.example.test")
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


@pytest.mark.parametrize(
    ("tls_mode", "verify_mode", "check_hostname"),
    [
        (TLS_MODE_TRUSTED_CERTIFICATE, ssl.CERT_REQUIRED, True),
        (TLS_MODE_PINNED_CERTIFICATE, ssl.CERT_REQUIRED, False),
        (TLS_MODE_INSECURE, ssl.CERT_NONE, False),
    ],
)
async def test_httpx_client_tls_modes(
    tls_mode: str,
    verify_mode: ssl.VerifyMode,
    *,
    check_hostname: bool,
) -> None:
    """Each HTTPX mode should configure certificate checks and disable redirects."""
    with (
        patch(
            "custom_components.ha_smg_emh_casa.tls.ssl.SSLContext.load_verify_locations"
        ),
        patch(
            "custom_components.ha_smg_emh_casa.tls.httpx.AsyncClient",
            wraps=httpx.AsyncClient,
        ) as client_class,
    ):
        client = create_httpx_client(tls_mode, CERTIFICATE_PEM)
    try:
        kwargs = client_class.call_args.kwargs
        context = kwargs["verify"]
        assert context.verify_mode is verify_mode
        assert context.check_hostname is check_hostname
        assert kwargs["follow_redirects"] is False
        if tls_mode == TLS_MODE_PINNED_CERTIFICATE:
            assert context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    finally:
        await client.aclose()


def test_detects_nested_certificate_verification_error() -> None:
    """HTTPX wrappers should not hide TLS verification failures."""
    error = httpx.ConnectError("TLS connection failed")
    error.__cause__ = ssl.SSLCertVerificationError("certificate verify failed")
    assert is_certificate_verification_error(error)
