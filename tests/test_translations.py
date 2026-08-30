"""Tests for EMH CASA TLS user-facing translations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.helpers.translation import async_get_translations

from custom_components.ha_smg_emh_casa.const import DOMAIN

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant


async def test_tls_choices_have_plain_language_explanations(
    hass: HomeAssistant,
) -> None:
    """The setup flow should explain all certificate-checking choices."""
    config = await async_get_translations(hass, "en", "config", {DOMAIN})
    selector = await async_get_translations(hass, "en", "selector", {DOMAIN})

    description = config[f"component.{DOMAIN}.config.step.user.description"]
    assert "before sending login details" in description
    assert "public certificate" in description
    assert "cannot detect an impersonated gateway" in description
    assert selector == {
        f"component.{DOMAIN}.selector.tls_mode.options.pinned_certificate": (
            "Trust and remember this gateway certificate"
        ),
        f"component.{DOMAIN}.selector.tls_mode.options.trusted_certificate": (
            "Use a certificate trusted by Home Assistant"
        ),
        f"component.{DOMAIN}.selector.tls_mode.options.insecure": (
            "Do not check the certificate (insecure)"
        ),
    }


async def test_certificate_issue_includes_fix_flow_translations(
    hass: HomeAssistant,
) -> None:
    """The certificate-change issue should render its repair form and errors."""
    issues = await async_get_translations(hass, "en", "issues", {DOMAIN})
    prefix = f"component.{DOMAIN}.issues.certificate_changed"

    assert issues[f"{prefix}.title"] == "The EMH CASA gateway certificate changed"
    assert issues[f"{prefix}.fix_flow.step.confirm.title"] == (
        "Accept the replacement gateway certificate?"
    )
    assert (
        "changed again" in issues[f"{prefix}.fix_flow.error.certificate_changed_again"]
    )
