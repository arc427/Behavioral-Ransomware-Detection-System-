# Submission limitations and data-validity statement

## SILRAD integration

The SILRAD-1.0 dataset (`fasttext-all-nofamily.csv`) contains raw Sysmon field
data (event.code, ProcessGuid, Image, TargetObject, CommandLine, class) captured
from Windows 11 endpoints running 50 ransomware samples across 6 families plus
176,130 benign application events. The `SILRADAdapter` aggregates these records
into 5-second behavioral windows using the same feature engineering pipeline as
the rest of BRDS. 17,617 genuine benign windows are used as the operational
baseline alongside 2,785 attack windows from Splunk ATT&CK data.

## Current evaluation scope

The baseline model achieves 99.51% F1 Score, 99.53% Precision, 99.48% Recall,
and 0.22% False Positive Rate on strict source-level splits. However, a
production-performance claim would additionally require family-held-out
evaluation, recorded encryption start times for detection lead-time measurement,
and deployment validation on diverse enterprise environments.
Dashboard/demo scores are not enterprise accuracy claims.

## Containment safety

Containment PowerShell scripts are locked to dry-run mode in this project build.
They log intended actions but do not disable adapters or terminate processes.
Live containment requires a separately reviewed service with independent
authorization, incident-response approval, and isolated VM validation.

## Secrets

`BRDS_ALERT_HMAC_KEY` is mandatory for application alert signing. The automated
tests use a dedicated test-only environment override; it must never be enabled
outside tests.
