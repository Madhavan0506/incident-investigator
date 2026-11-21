# Identity incident runbook

Service: identity

## Token verification and signing-key refresh

New signing-key identifiers can produce HTTP 401 responses when the cached key set fails to refresh.
Diagnosis: Identity signing-key cache refresh failure
Signals: JWKS_KID_UNKNOWN, JWKS_REFRESH_FAILED
Next step: Verify the upstream signing-key publication and cached key age with the identity on-call.

## Identity service telemetry

Compare the token-verification error rate with the upstream key set requests for the incident window.
