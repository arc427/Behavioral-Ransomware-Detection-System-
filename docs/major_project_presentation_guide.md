# Behavioral Ransomware Detection System (BRDS-PEC)
## Major Project Presentation & Live Demonstration Guide

**Project Name:** BRDS-PEC: Behavioral Ransomware Detection System with Pre-Encryption Containment  
**Target Audience:** Project Evaluators, Professors, Defense Panel  
**Objective:** Complete step-by-step guide to run, showcase, and explain BRDS-PEC live during your major project evaluation.  

---

## 1. Quick Live Demo Execution Steps (Commands to Run)

To run the full-stack system live for your presentation, open **3 terminal windows**:

### Step 1: Initialize Database & Prepare Scored Telemetry
Run the live data pipeline script to train models, generate scored telemetry windows, and populate SQLite (`brds.db`):
```bash
# Terminal 1: Initialize data & database
python scripts/prepare_live_data.py
```
*Expected Output:* Displays dataset splitting, trains PyTorch LSTM model (**99.71% validation accuracy**), creates signed `dry_run_alerts.json`, and populates `data/brds.db`.

---

### Step 2: Start Flask Backend REST API
Launch the backend application server:
```bash
# Terminal 1: Start Backend API
python backend/app.py
```
*Expected Output:*  
`* Serving Flask app 'backend.app'`  
`* Running on http://127.0.0.1:5000`  
`* TelemetryWatchdog active | LSTM model loaded successfully`

---

### Step 3: Launch Containment Daemon (Safe Dry-Run Mode)
In a second terminal, launch the background containment daemon:
```bash
# Terminal 2: Start Containment Daemon
python containment/trigger_daemon.py
```
*Expected Output:* Monitors `dry_run_alerts.json`, validates HMAC-SHA256 digests, checks `.arm_token`, and logs safe dry-run containment actions.

---

### Step 4: Open SOC Dashboard UI
In your web browser, open the frontend dashboard:
```text
file:///C:/Users/hp/Behavioral-Ransomware-Detection-System-/frontend/index.html
```
*(Or serve via Python HTTP server: `python -m http.server 3000 --directory frontend` and navigate to `http://localhost:3000`)*

---

## 2. Recommended Presentation Slide Structure (10-15 Minutes)

| Slide # | Slide Title | Key Content / Talking Points |
| :--- | :--- | :--- |
| **Slide 1** | **Title & Team** | BRDS-PEC: Behavioral Ransomware Detection System with Pre-Encryption Containment. |
| **Slide 2** | **Problem Statement** | Ransomware damages files before traditional hash-based AV reacts. Need for behavioral, pre-encryption containment. |
| **Slide 3** | **System Architecture** | Sysmon Log Parsing $\rightarrow$ 5s Windowing $\rightarrow$ PyTorch LSTM $\rightarrow$ HMAC Alert Signing $\rightarrow$ Containment. |
| **Slide 4** | **Machine Learning Engine** | 2-layer Deep LSTM with concatenated Mean + Max sequence pooling (**99.71% validation accuracy**). |
| **Slide 5** | **Security Hardening** | PyTorch `weights_only=True`, SHA-256 manifests, `@require_api_key`, SQL wildcard escaping, `$PROTECTED_PROCESSES`. |
| **Slide 6** | **Live Demonstration** | *Switch to browser dashboard & live terminals (see Section 3).* |
| **Slide 7** | **Evaluation & Testing** | 25/25 PyTest unit tests passing, ROC-AUC 0.988, 100% recall on attack windows. |
| **Slide 8** | **Conclusion & Future Scope** | Real-time pre-encryption containment achieved; ready for enterprise agent packaging. |

---

## 3. Step-by-Step Live Demo Script for Evaluators

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                             LIVE DEMONSTRATION WORKFLOW                                │
├─────────────────┬──────────────────┬──────────────────┬─────────────────┬──────────────┤
│ 1. Telemetry    │ 2. Real-Time     │ 3. Ransomware    │ 4. Explainable  │ 5. Safe      │
│    Stream       │    Risk Curve    │    Alert Card    │    AI (XAI)     │    Containment│
│                 │                  │                  │                 │              │
│ Show 5s Sysmon  │ Point to Chart.js│ Highlight high   │ Click 'SHAP     │ Show HMAC    │
│ windowed event  │ 30-window curve  │ risk incident    │ Analysis' to    │ signatures & │
│ process feeds   │ & threshold lines│ (WannaCry > 0.85)│ show autograd   │ protected OS │
│                 │ (0.60 & 0.85)    │                  │ attributions    │ process list │
└────────┬────────┴────────┬─────────┴────────┬─────────┴────────┬────────┴──────┬───────┘
         │                 │                  │                  │               │
         ▼                 ▼                  ▼                  ▼               ▼
   [ Stream Panel ]  [ Chart Canvas ]  [ Incident Panel ] [ XAI Modal ]  [ Terminal Daemon ]
```

### Script Step 1: Explain the Telemetry Stream (Left Panel)
- **Say:** *"Our system continuously monitors Microsoft Sysmon logs. Rather than inspecting individual events, it groups system events into 5-second sliding windows per process."*
- **Action:** Show the left column on the dashboard displaying active process key badges (`PROC`, `FILE`, `REG`, `NET`).

### Script Step 2: Show the Real-Time Risk Curve (Center Panel)
- **Say:** *"The center panel displays the rolling threat profile generated by our PyTorch LSTM model. The amber dashed line is the Warning threshold (0.60), and the crimson line is the Containment threshold (0.85)."*
- **Action:** Highlight the smooth Chart.js risk curve line moving dynamically.

### Script Step 3: Demonstrate Threat Detection & Incident Alerts (Right Panel)
- **Say:** *"When a process executes ransomware behavior—such as volume shadow deletion (`vssadmin`) or rapid file creation—the risk score probability spikes above 0.85, automatically creating a critical alert incident."*
- **Action:** Point out an active incident card on the right panel (e.g., `WANNACRY - 0.98 RISK`).

### Script Step 4: Showcase Explainable AI (XAI Modal) ⭐ *Evaluator Favorite*
- **Say:** *"Security analysts cannot trust black-box AI models. We implemented PyTorch autograd integrated gradient attributions (`LSTMSHAPExplainer`). Clicking 'SHAP Analysis' reveals the exact feature drivers behind the model's decision."*
- **Action:** Click the **`SHAP Analysis`** button on an incident card. Show the pop-up modal displaying positive feature attribution bars (`event_23_count`, `suspicious_path_count`).

### Script Step 5: Demonstrate Host Containment Security & Anti-Tampering (Terminal)
- **Say:** *"To prevent false containment triggers, alerts are cryptographically signed using HMAC-SHA256. The daemon validates signed `.arm_token` files before triggering containment. To protect OS stability, our PowerShell scripts enforce a protected process denylist so core Windows services (`lsass`, `csrss`, `svchost`) are never killed."*
- **Action:** Show Terminal 2 (Containment Daemon) logging HMAC verification and safe dry-run containment actions.

---

## 4. Key Technical Highlights to Emphasize to Professors

1. **Pre-Encryption Containment (PEC):** Solves the core flaw of legacy AV by stopping ransomware during early behavioral sequences (5–15s) before files are encrypted.
2. **Deep Sequence Modeling:** 2-layer LSTM with concatenated Mean + Max pooling across 30 sequence steps (**99.71% validation accuracy**).
3. **PyTorch Deserialization Security:** Operates with `weights_only=True` and checks SHA-256 hash manifests (`lstm_model.sha256`) to prevent Remote Code Execution (RCE).
4. **Sensor Gap Watchdog:** `TelemetryWatchdog` detects log silence attacks (>30s gaps) and exposes status at `/api/health`.
5. **Database & API Security:** Constant-time `@require_api_key` verification, SQL `_safe_like()` wildcard escaping, and CORS domain allowlists.
6. **Robust Testing:** **25 out of 25 unit tests pass** across backend APIs, ML inference, containment security, and XAI engines.
