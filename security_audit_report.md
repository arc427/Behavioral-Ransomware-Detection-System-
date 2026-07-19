# BRDS-PEC Final Security Audit Report

**Prepared by:** Malware Research Engineer (Security Review)
**System Under Review:** Behavioral Ransomware Detection System — Production Engineering Candidate (BRDS-PEC)
**Architecture:** Sysmon ETW → Python Vectorizer → Isolation Forest (Tier 1) → LSTM Classifier (Tier 2) → Flask API → PowerShell Containment

---

> [!CAUTION]
> This report identifies **exploitable design weaknesses** in the detection and containment pipeline. Each finding is grounded in the **actual source code** of the repository. These are not theoretical — they represent concrete attack surfaces a post-exploitation adversary could use to survive, evade, or disable the system entirely.

---

## Finding 1 — Telemetry Manipulation (Sysmon Blind Spots)

### Severity: CRITICAL

### Attack Surface

The entire detection pipeline is **100% dependent** on Sysmon as its sole telemetry source. There is no secondary or corroborating sensor. If the Sysmon event stream is suppressed, poisoned, or silenced, the Isolation Forest and LSTM receive no data to classify, and the containment daemon never fires.

### Exploitation Path

**Step 1 — Identify the monitoring stack**
After gaining initial persistence (e.g., via a phishing macro or supply chain implant), the attacker runs a lightweight reconnaissance script:

```powershell
Get-Service Sysmon64             # Confirm Sysmon is running
fltMC.exe                        # List kernel filter drivers — reveals SysmonDrv
Get-Process python               # Detect the Python pipeline process
Get-Process | Where-Object { $_.MainModule.FileName -like "*trigger_daemon*" }
```

**Step 2 — Silence ETW/Sysmon without stopping the service**
The most surgically precise attack is **ETW provider manipulation**. The attacker does _not_ stop Sysmon (which would itself generate an event), but instead patches the ETW session:

```powershell
# Remove Sysmon's ETW session provider — no events written to the Event Log
logman stop EventLog-Microsoft-Windows-Sysmon -ets
```

**Step 3 — Wipe existing evidence**

```powershell
# Clears the Microsoft-Windows-Sysmon/Operational channel silently
wevtutil cl Microsoft-Windows-Sysmon/Operational
```

**Step 4 — Exploit the Python vectorizer's lack of gap detection**
The pipeline script `run_pipeline.py` reads Sysmon XML output on a polling basis. It has **no mechanism to detect periods of silence** in the event stream (i.e., 30 seconds of zero events is statistically indistinguishable from a quiet system).

```python
# Current behavior in run_pipeline.py — no dead-zone watchdog
# A 10-minute gap in Sysmon data → no anomaly score computed → no alert
```

### Code-Level Impact

In `telemetry_routes.py` lines 101–117, `lstm_score` defaults to `0.0` if no data exists:

```python
lstm_score = 0.0
lstm_infer = current_app.config.get("LSTM_INFER")
if lstm_infer:
    history = FeatureVector.query...limit(30).all()
    if history:  # ← If Sysmon is silenced, history is empty, score stays 0.0
        ...
```

**An empty Sysmon stream silently produces a 0.0 risk score — no alert, no containment.**

### Recommended Mitigations

1. **Implement a Telemetry Heartbeat Watchdog**: Alert SOC if zero events are received for any rolling 30-second window during expected operating hours.
2. **Deploy Secondary Telemetry Sources**: Add ETW consumers from `Microsoft-Windows-Kernel-File` and `Microsoft-Windows-Security-Auditing` as independent cross-checks.
3. **Protect the ETW Session via a PPL Process**: Run Sysmon as a Protected Process Light (PPL) to prevent standard Administrator accounts from terminating it via `TerminateProcess`.
4. **Hash and Timestamp Event Log Integrity**: Use a signed HMAC chain on the rolling event log to detect log-clearing events even after the fact.

---

## Finding 2 — Adversarial Poisoning of the Isolation Forest (Tier 1)

### Severity: HIGH

### Attack Surface

The Isolation Forest model is trained **once offline** using `scripts/train_baseline.py` and saved as a static joblib artifact (`baseline_models.joblib`). It does not perform continuous retraining. However, if an attacker can influence the training data **before** the model is serialized, or gradually bias the feature distribution the model observes during live operation, they can shift the anomaly decision boundary.

### Two Poisoning Vectors

#### Vector A — Training Data Poisoning (Pre-Deployment)

If an attacker can write files into `data/processed/` before `train_baseline.py` is run, they can inject "malicious-adjacent" samples labeled as `label=0` (benign):

```python
# In prepare_live_data.py — no integrity check on source files
frame = pd.read_csv(path)  # ← No hash verification of source CSV
```

By seeding `sysmon_windows.csv` with 200–500 rows of high-`file_activity_count` benign-labeled windows, the Isolation Forest learns that high file activity is normal, widening its anomaly threshold and causing the early ransomware encryption phase to be classified as benign.

#### Vector B — Slow Contamination via the Live API (Post-Deployment)

The `/api/score/live` endpoint (`telemetry_routes.py` line 68) accepts arbitrary feature vectors **without authentication**:

```python
@telemetry_bp.post("/api/score/live")
def score_live():
    data = request.get_json() or {}
    computer = data.get("computer", "BRDS-WIN11-SEC")  # ← No authentication
    ...
    vec = FeatureVector(...)
    db.session.add(vec)   # ← Written directly to the database
```

An attacker who can reach the API endpoint can inject thousands of benign-labeled vectors with elevated `file_activity_count` values. If the model is ever **retrained** on this database, the Isolation Forest's contamination parameter recalibrates to absorb these attack-mimicking features as normal.

### Recommended Mitigations

1. **Authenticate the Live Scoring API**: Require an HMAC-signed bearer token (or mutual TLS) on `POST /api/score/live` to prevent unauthenticated feature injection.
2. **Validate and Clamp Feature Vectors**: Reject payloads where any feature value exceeds 3× the training set's per-feature standard deviation.
3. **Lock the Training Set with a Cryptographic Hash**: Compute and store a SHA-256 hash of `sysmon_windows.csv` before training. Verify it before any retraining run.
4. **Separate the Live Ingestion Database from the Training Pipeline**: Live `FeatureVector` records written by the API should never be automatically included in a retrain batch without explicit human review.

---

## Finding 3 — Time-Based Evasion (LSTM Context Window Chaff Injection)

### Severity: HIGH

### Attack Surface

The `LSTMInfer.score_sequence()` method in `infer.py` processes the **most recent 30 steps** for a given host. An attacker who injects high-frequency "chaff" — meaningless but legitimate-looking system events — between malicious encryption steps can dilute the signal across the 30-step context window.

### Exploitation Path

The LSTM looks at a fixed 30-step window (150 seconds). The attacker's strategy is to push incriminating steps outside the 30-step boundary by flooding the database with intermediate benign windows:

```
T=0s:    Encrypt 5 files    → 1 suspicious window
T=5-180s: Generate 36 benign chaff bursts  → 36 benign windows
T=185s:  Encrypt 5 more files
         ← The T=0 window is now OUTSIDE the 30-step context!
         ← Each individual burst looks benign in isolation
```

### Code-Level Impact

From `infer.py` lines 51–59:

```python
seq_len = 30
if len(features_scaled) > seq_len:
    features_scaled = features_scaled[-seq_len:]  # ← Always takes latest 30
elif len(features_scaled) < seq_len:
    padding = np.zeros(...)  # ← Zero-padding adds benign bias at front
```

**Zero-padding** (line 58–59) systematically biases sequences shorter than 30 steps toward a lower risk score. An attacker who keeps their activity sparse (< 30 total windows per host session) will always benefit from this padding bias.

### Recommended Mitigations

1. **Implement Sparse Sequence Attention**: Use an attention mechanism that weights windows by their anomaly score contribution rather than treating all 30 steps equally.
2. **Replace Zero-Padding with Learned Padding**: Initialize short-sequence padding vectors to the training set's per-feature mean rather than zero.
3. **Add Inter-Event Gap Detection**: Flag sequences where the time gap between high-activity windows is abnormally long (> 30s between `file_activity_count` spikes) as a "chaff-spacing" indicator.
4. **Track Per-Host Cumulative Risk**: Maintain a rolling cumulative risk score across all windows for a host session, not just the latest 30.

---

## Finding 4 — Containment System Vulnerability

### Severity: CRITICAL

### Attack Surface

The containment engine has **two critical design vulnerabilities** rooted in its reliance on environment variables and a plaintext JSON alert file as the containment trigger.

### Vulnerability A — Single Environment Variable Kill Switch

The entire containment system's active mode is controlled by a single environment variable (`BRDS_DRY_RUN`). From `trigger_daemon.py` lines 104–109:

```python
if os.environ.get("BRDS_DRY_RUN") != "0":
    os.environ["BRDS_DRY_RUN"] = "1"      # ← Forced dry-run if not explicitly armed
```

An attacker with code execution in the same user session as the Python daemon can disable all active containment with a single command:

```powershell
$env:BRDS_DRY_RUN = "1"
# The daemon continues running and logging — but isolation NEVER fires
```

### Vulnerability B — Plaintext JSON Alert File as Control Channel

The daemon polls `dry_run_alerts.json` as its trigger signal. This file has **no integrity protection**. An attacker who can write to the file system can:

1. **Truncate the alert file** to silently prevent all future containment:

   ```python
   open("data/processed/dry_run_alerts.json", "w").write("[]")
   ```

2. **Inject a fake alert targeting a critical Windows system process** to cause a self-inflicted Denial of Service. From `trigger_daemon.py` line 65:
   ```python
   proc_output = run_powershell(KILL_PROCESS_SCRIPT, ["-ParentPid", str(pid)])
   ```
   The `pid` value comes **directly from the JSON file with no allowlist validation**. Injecting `"process_key": "lsass.exe:600"` causes the daemon to execute `kill_process_tree.ps1 -ParentPid 600`, terminating `lsass.exe` and crashing the system.

### Recommended Mitigations

1. **Replace Environment Variable with a Cryptographically Signed Arm/Disarm Token**: The daemon should only activate if it can verify an HMAC-signed activation token, not a plain environment variable.
2. **Sign the Alert File**: Compute and verify an HMAC-SHA256 signature of `dry_run_alerts.json` before processing. Reject unsigned or tampered files.
3. **Implement a PID Allowlist/Denylist**: Before executing `kill_process_tree.ps1`, validate that the target PID does not belong to a critical system process (e.g., `lsass.exe`, `csrss.exe`, `System`).
4. **Run the Containment Daemon as a Dedicated Low-Privilege Service Account**: It should have exactly the permissions needed for `Disable-NetAdapter` and `Stop-Process` on non-system PIDs, and **no write access** to its own alert file or configuration.

---

## Finding 5 — Explainability Abuse (SHAP False Flag Generation)

### Severity: MEDIUM

### Attack Surface

The `SHAPExplainer.explain()` method in `shap_explainer.py` computes feature importances for the **Logistic Regression baseline model**, not the LSTM model that actually triggered the alert. This creates a **model-explanation mismatch** that can be systematically exploited to generate misleading analyst explanations.

### Exploitation Path

From `shap_explainer.py` lines 30–33:

```python
self.supervised_model = self.artifacts["supervised_model"]  # ← Logistic Regression
self.scaler = self.supervised_model.named_steps["scale"]
self.model = self.supervised_model.named_steps["model"]
```

The LSTM produced a `0.97` risk score. The SHAP explanation is computed from the **Logistic Regression** model's coefficients. These two models may have **entirely different feature importance rankings**.

An attacker can craft their activity to maximize `registry_activity_count` and `network_activity_count` (high Logistic Regression coefficients) while keeping the actual encryption signal in `file_activity_count` (which the LSTM flagged). The SOC analyst then sees:

```
Top SHAP Attributions:
1. registry_activity_count:  +0.84  ← "Looks like a Windows Update scan"
2. network_activity_count:   +0.71  ← "Looks like a backup client"
3. file_activity_count:      +0.12  ← "Not the primary driver?"
```

The analyst is **more likely to dismiss the alert as a false positive** — even though the LSTM detected a genuine encryption sequence.

Additionally, the `except Exception` block on line 65 silently falls back to a simplified linear approximation. An attacker who triggers a controlled SHAP import failure receives an even lower-fidelity explanation that further obscures the true detection signal.

### Recommended Mitigations

1. **Compute SHAP Values Against the Actual LSTM Model**: Implement a `GradientExplainer` or `DeepExplainer` targeting the `LSTMClassifier` PyTorch model, not the Logistic Regression.
2. **Display Model Attribution Source to the Analyst**: Add a visible disclaimer in the SOC dashboard specifying which model produced the explanation.
3. **Add a Feature-Importance Consistency Check**: If the SHAP top feature and the LSTM's most sensitive gradient feature diverge beyond a threshold, display a `⚠ EXPLANATION MISMATCH` warning in the SOC UI.
4. **Replace the Silent `except Exception` Fallback**: Catch only `ImportError` for a missing `shap` library. All other exceptions should propagate with full tracebacks so analyst tooling is never silently degraded.

---

## Summary Risk Matrix

| #   | Finding                                        | Severity    | Exploitability                        | Impact                                            |
| --- | ---------------------------------------------- | ----------- | ------------------------------------- | ------------------------------------------------- |
| 1   | Sysmon ETW Suppression / Log Clearing          | 🔴 CRITICAL | Low privilege + `wevtutil`            | Complete sensor blindness                         |
| 2   | Isolation Forest Training Data Poisoning       | 🟠 HIGH     | Unauthenticated API access            | Widens detection threshold permanently            |
| 3   | LSTM Chaff Injection (Context Dilution)        | 🟠 HIGH     | Code execution on host                | Breaks sequential detection continuity            |
| 4   | Containment Kill Switch & Alert File Injection | 🔴 CRITICAL | Same user session or filesystem write | Disables response OR causes self-inflicted DoS    |
| 5   | SHAP False Flag / Model-Explanation Mismatch   | 🟡 MEDIUM   | Craft a specific feature vector       | Analyst dismisses a genuine high-confidence alert |

---

## Priority Hardening Roadmap

```
IMMEDIATE (before any production deployment):
  ├── Authenticate /api/score/live with HMAC bearer tokens
  ├── Add HMAC signature verification on dry_run_alerts.json
  ├── Add PID allowlist/denylist before kill_process_tree.ps1 invocation
  └── Implement a Telemetry Heartbeat Watchdog

SHORT TERM (within 2 sprints):
  ├── Replace zero-padding with training-mean padding in LSTMInfer
  ├── Implement per-host cumulative risk tracking across sessions
  ├── Lock training set integrity with SHA-256 manifest
  └── Migrate SHAP explanations to LSTM GradientExplainer

LONG TERM (production hardening):
  ├── Run Sysmon as a PPL (Protected Process Light)
  ├── Deploy secondary ETW telemetry sources (Kernel-File, Security-Auditing)
  ├── Implement backpressure rate-limiting on the ingestion pipeline
  └── Run trigger_daemon.py as a dedicated low-privilege service account
```
