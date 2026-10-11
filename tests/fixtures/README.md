# Certificate fixtures

These synthetic certificates use `gateway.example.test`; none comes from a real
gateway. `legacy_certificate.pem` has ECDSA-with-SHA256 NULL parameters and was
re-signed after adding them. The other fixtures modify its validity or version
without re-signing, to test metadata decoding behind a mocked TLS handshake.
Private keys are discarded. Static fixtures also work with the older cryptography
version at the supported Home Assistant floor, whose ASN.1 encoder cannot emit
raw TLV fields.
