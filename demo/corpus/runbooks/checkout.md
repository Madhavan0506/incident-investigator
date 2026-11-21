# Checkout incident runbook

Service: checkout

## Database connections and slow checkout

Checkout may return HTTP 503 or time out when it cannot acquire database connections.
Diagnosis: Checkout database connection pool saturation
Signals: DB_POOL_EXHAUSTED, DB_ACQUIRE_TIMEOUT
Next step: Review connection checkout durations and active database sessions with the database on-call.

## DNS resolution for the payment dependency

Checkout may return HTTP 503 when its payment dependency cannot be resolved or contacted.
Diagnosis: Checkout payment dependency DNS resolution failure
Signals: PAYMENT_DNS_NO_ADDRESS, PAYMENT_GATEWAY_UNREACHABLE
Next step: Ask the networking on-call to compare resolver results from affected checkout instances.

## Checkout HTTP errors and slow requests

Compare the HTTP status and latency curves with the affected request paths.
Use the matching diagnostic signals above to narrow the investigation.
