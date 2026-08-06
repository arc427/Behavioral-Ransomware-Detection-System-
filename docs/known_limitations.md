# Submission limitations and data-validity statement

## SILRAD integration

The SILRAD-1.0 dataset (`fasttext-all-nofamily.csv`) contains 196,840 Sysmon
records from Windows 11 endpoints. While `event.code` is preserved as a real
integer, the text columns (`Image`, `CommandLine`, `TargetObject`) have been
replaced with FastText embedding floats by the dataset authors.

For **benign records** (class=0, 176,130 events), the `event.code` distribution
alone is sufficient for the `SILRADAdapter` to produce realistic behavioral
windows (17,617 windows used as operational baseline).

For **ransomware records** (class=1, 20,710 events), the embedded text columns
produce misleading feature profiles: `unique_images`, `suspicious_path_count`,
and `unique_files` are computed from float strings instead of real file paths,
causing the classifier to learn artifacts rather than genuine attack behaviour.
Empirical testing confirmed a drop from 99.51% to 54.97% F1 when including
SILRAD attack windows. These records are therefore excluded from training.

Attack behaviour is sourced from 2,785 windows extracted from Splunk ATT&CK
logs with real Sysmon paths and process metadata.

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
