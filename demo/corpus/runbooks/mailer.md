# Mailer incident runbook

Service: mailer

## Delivery delays and relay sending limits

The relay may defer deliveries while the retry queue grows and message age increases.
Diagnosis: Mail relay throttling with a delivery retry backlog
Signals: SMTP_RATE_LIMITED, DELIVERY_RETRY_BACKLOG
Next step: Confirm the relay's sending limits and compare queued retry age with the mailer on-call.

## Delivery queue telemetry

Compare new messages, retry depth, and queue age across delivery workers.
