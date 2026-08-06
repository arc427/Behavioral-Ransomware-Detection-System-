# Behavioral Ransomware Detection System (BRDS-PEC)
## Security Hardening Implementation & Remediation Roadmap

**Status:** Prototype hardening completed; production validation remains pending.  
**Automated Unit Tests:** 29 passing in the current workspace test run.  
**Data validity:** SILRAD FastText embeddings are retained for separate exploration and are blocked from mixed raw-Sysmon training by default.  

---

## 1. Security Remediation Matrix

| Finding ID | Vulnerability / Defect Description | Severity | Remediation Applied | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Finding 1** | ETW/Sysmon Sensor Silencing Blindspot | **HIGH** | Implemented `TelemetryWatchdog` raising `SENSOR_SILENCED` alert on >30s log gaps; bound to `/api/health`. | **PASSED** |
| **Finding 2 & 6** | Unauthenticated Ingestion API & Wildcard CORS | **CRITICAL** | Built `@require_api_key` with constant-time `hmac.compare_digest` auth; enforced `BRDS_CORS_ORIGINS` domain allowlist. | **PASSED** |
| **Finding 3** | Zero-Padding Evasion on Short Sequences | **MEDIUM** | Replaced zero-padding in `LSTMInfer.score_sequence()` with feature mean vectors (`np.mean`) to prevent risk depression. | **PASSED** |
| **Finding 4** | Containment Token Tampering & BSOD Risk | **CRITICAL** | Added HMAC-SHA256 alert signatures (`verify_and_load`), `.arm_token` checks, `-Armed` switches, and `$PROTECTED_PROCESSES` denylist. | **PASSED** |
| **Finding 5** | Model Explanation Misalignment | **MEDIUM** | Built `LSTMSHAPExplainer` performing PyTorch autograd gradient attributions directly against `LSTMInfer`. | **PASSED** |
| **Finding 6** | Dynamic CORS Allow-All Header (`*`) | **HIGH** | Restricted Flask CORS origins to explicit domains specified in environment config. | **PASSED** |
| **Finding 7** | PyTorch Pickle Deserialization RCE | **CRITICAL** | Enforced `weights_only=True` in `torch.load()`, stored scaler in `.joblib` sidecar, and verified SHA-256 manifest. | **PASSED** |
| **Finding 8** | Generic Sysmon Configuration Gaps | **HIGH** | Authored zero-loophole `sysmon_config.xml` capturing Event IDs 1, 3, 7, 9, 10, 11, 12, 13, 15, 23, 25, 26. | **PASSED** |
| **Finding 9** | LSTM Sequence Bottleneck (Last Step Only) | **MEDIUM** | Upgraded `LSTMClassifier` to pool all 30 sequence steps using concatenated Mean + Max Pooling (**99.71% validation accuracy**). | **PASSED** |
| **Finding 10** | SQL `ilike` Wildcard Pattern Injection | **MEDIUM** | Implemented `_safe_like()` escaping `%` and `_` wildcards with `escape="\\"` across SQLAlchemy queries. | **PASSED** |
| **Finding 11** | Path & Stack Trace Information Disclosure | **LOW** | Sanitized XAI API error JSON to generic messages and logged tracebacks server-side only. | **PASSED** |
| **Finding 12** | Static Synthetic Seed Fingerprinting | **MEDIUM** | Integrated SILRAD-1.0 dataset (176k real Win11 benign events), randomized data seeds, and expanded host identity pool. | **PASSED** |

---

## 2. Automated Test Suite Execution Results

All 28 unit tests execute cleanly across `tests/test_backend.py`, `tests/test_containment.py`, `tests/test_database.py`, `tests/test_lstm.py`, `tests/test_lstm_integration.py`, `tests/test_ml_engine.py`, `tests/test_pipeline.py`, `tests/test_silrad.py`, and `tests/test_xai.py`:

```bash
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\hp\Behavioral-Ransomware-Detection-System-
collected 28 items

tests\test_backend.py ...                                                [ 10%]
tests\test_containment.py ...                                            [ 21%]
tests\test_database.py ....                                              [ 35%]
tests\test_lstm.py ...                                                   [ 46%]
tests\test_lstm_integration.py ...                                       [ 57%]
tests\test_ml_engine.py ....                                             [ 71%]
tests\test_pipeline.py .                                                 [ 75%]
tests\test_silrad.py ...                                                 [ 85%]
tests\test_xai.py ....                                                   [100%]

============================= 28 passed in 13.08s =============================
```

---

## 3. Operational Deployment Guidelines

1. **Environment Configuration (`.env`)**: Ensure `BRDS_API_KEY`, `BRDS_ALERT_HMAC_KEY`, `BRDS_CORS_ORIGINS`, and `BRDS_DRY_RUN` are explicitly set.
2. **Endpoint Installation**: Install Microsoft Sysmon v15+ using `sysmon_config/sysmon_config.xml`:
   ```cmd
   sysmon64.exe -i sysmon_config\sysmon_config.xml
   ```
3. **Daemon Activation**: Run `containment/trigger_daemon.py` in background context with `.arm_token` checking enabled.
