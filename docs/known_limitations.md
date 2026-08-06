# Submission limitations and data-validity statement

## SILRAD integration

The included `fasttext-all-nofamily.csv` file is a FastText numerical feature
export. Its columns resemble Sysmon fields, but their values are embeddings and
do not preserve the original path, process, or timestamp semantics. The project
therefore treats it as an exploratory SILRAD-native dataset and does not mix it
with raw Sysmon windows for baseline training by default.

## Current evaluation scope

The raw-Sysmon pipeline is validated on selected Splunk ATT&CK logs. A valid
production-performance claim requires captured benign Sysmon telemetry, complete
execution-level train/test separation, family-held-out evaluation, and recorded
encryption start times. Dashboard/demo scores are not enterprise accuracy claims.

## Containment safety

Containment PowerShell scripts are locked to dry-run mode in this project build.
They log intended actions but do not disable adapters or terminate processes.
Live containment requires a separately reviewed service with independent
authorization, incident-response approval, and isolated VM validation.

## Secrets

`BRDS_ALERT_HMAC_KEY` is mandatory for application alert signing. The automated
tests use a dedicated test-only environment override; it must never be enabled
outside tests.
