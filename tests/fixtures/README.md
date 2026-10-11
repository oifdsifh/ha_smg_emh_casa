# Certificate fixtures

`legacy_certificate.pem` is a synthetic certificate for `gateway.example.test`;
it does not come from a real gateway. It has ECDSA-with-SHA256 NULL parameters
and was re-signed after adding them. The private key was discarded.

The fixture tests that discovery preserves the original bytes and fingerprint
without parsing certificate fields. Other tests cover the integration's SSL
verification settings and handling of verification failures during setup,
polling, and repairs.
