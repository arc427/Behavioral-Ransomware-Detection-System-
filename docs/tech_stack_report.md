# Behavioral Ransomware Detection System (BRDS)
## Comprehensive Technology Stack Report

**System:** Behavioral Ransomware Detection System (`BRDS-PEC`)  
**Scope:** Exhaustive breakdown of all programming languages, machine learning frameworks, backend web technologies, databases, system security tools, frontend visualization libraries, and testing frameworks used in the project.  

---

## Executive Summary

The **Behavioral Ransomware Detection System (BRDS)** is built on a modern, multi-tiered security architecture designed for **Pre-Encryption Containment (PEC)** of zero-day ransomware. Its technology stack combines deep neural sequence classification, real-time Windows ETW/Sysmon telemetry parsing, cryptographic anti-tampering defenses, RESTful microservice APIs, and a modern dark-mode SOC dashboard.

---

## 1. Technology Stack Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SOC DASHBOARD (Frontend)                       │
│           HTML5 • CSS3 (Vanilla Dark Mode) • JavaScript (ES6)           │
│                    Chart.js • Lucide Icons CDN                          │
└────────────────────┬────────────────────────────────────┘
                                     │ REST HTTP / JSON
┌────────────────────▼────────────────────────────────────┐
│                        BACKEND API & SECURITY LAYER                     │
│               Flask 2.3+ • Flask-SQLAlchemy • Flask-CORS                │
│       HMAC-SHA256 Auth (@require_api_key) • TelemetryWatchdog           │
└──────────────────┬─────────────────┬──────────────────┬─────────────────┘
                   │                 │                  │
┌──────────────────▼──────┐ ┌────────▼────────┐ ┌───────▼─────────────────┐
│   DEEP LEARNING ENGINE  │ │ DATABASE LAYER  │ │  HOST CONTAINMENT DAEMON│
│  PyTorch 2.0+ (LSTM)    │ │ SQLite (brds.db)│ │ Python 3.14 Daemon      │
│  Scikit-Learn • SHAP    │ │ SQLAlchemy ORM  │ │ PowerShell 5.1/7.0      │
│  Joblib • SHA-256 Check │ │                 │ │ Win Firewall • Taskkill │
└─────────────────────────┘ └─────────────────┘ └─────────────────────────┘
```

---

## 2. Core Programming Languages & Runtimes

### 1. Python (v3.14)
- **Role:** Primary programming language used across the entire core system architecture.
- **Usage:**
  - **Machine Learning Engine:** Model architecture (`ml_engine/lstm/model.py`), training pipelines (`train.py`), real-time sequence inference (`infer.py`), and SHAP gradient explanations (`ml_engine/xai/shap_explainer.py`).
  - **Telemetry Processing:** EVTX log parsing (`pipeline/evtx_reader.py`), 5-second sliding temporal aggregation (`temporal_aggregator.py`), feature vector encoding (`vectorizer.py`), and sensor gap monitoring (`watchdog.py`).
  - **Backend Services:** Flask REST API web server (`backend/app.py`), authentication middleware (`backend/auth.py`), and SQLite ORM models.
  - **Containment Daemon:** Cryptographic alert verification, HMAC signature validation, and arm token issuance (`containment/trigger_daemon.py`, `alert_integrity.py`).

### 2. PowerShell (v5.1 / v7.0+)
- **Role:** Native Windows automation scripting language for OS-level containment actions.
- **Usage:**
  - **`ContainHost.ps1`:** Flushes ARP/DNS caches, disables network interfaces, and configures Windows Defender Firewall block rules to isolate infected endpoints.
  - **`kill_process_tree.ps1`:** Traverses CIM/WMI process trees to terminate ransomware processes and their sub-processes while enforcing a `$PROTECTED_PROCESSES` denylist (`lsass`, `csrss`, `svchost`, etc.).

### 3. JavaScript (ES6+ Vanilla)
- **Role:** Client-side scripting language for the SOC Dashboard UI.
- **Usage:**
  - **`telemetry_stream.js`:** Real-time polling and DOM rendering of incoming Sysmon process event feeds.
  - **`risk_timeline.js`:** Canvas rendering of the 30-window rolling risk score curve with warning (0.60) and containment (0.85) threshold lines.
  - **`incident_log.js`:** Dynamic management of active threat incident cards and manual host isolation triggers.
  - **`xai_modal.js`:** Modal rendering of feature importance bars powered by backend PyTorch gradient attributions.

### 4. HTML5 & Vanilla CSS3
- **Role:** Structure and styling for the SOC Dashboard web interface (`frontend/index.html`, `frontend/css/dashboard.css`).
- **Usage:** Uses modern CSS Grid, Flexbox, custom CSS design tokens (cyberpunk dark-mode palette), glassmorphism effects, and CSS micro-animations.

### 5. XML (Sysmon Rule Schema)
- **Role:** Configuration language for Microsoft System Monitor (`sysmon_config/sysmon_config.xml`).
- **Usage:** Defines zero-loophole rule filtering for Sysmon Event IDs 1, 3, 7, 9, 10, 11, 12, 13, 15, 23, 25, and 26.

---

## 3. Machine Learning, Deep Learning & XAI Frameworks

### 1. PyTorch (`torch >= 2.0.0`)
- **Role:** Deep Learning framework powering the primary sequence classification model.
- **Usage:** Implements `LSTMClassifier` with 2 LSTM layers (hidden dim 64), concatenated Mean + Max pooling across 30 sequence steps, and a dense linear output layer (`fc = Linear(256, 1)`). Operates with `weights_only=True` for security.

### 2. Scikit-Learn (`scikit-learn >= 1.2.0`)
- **Role:** Machine Learning library for feature scaling, baseline classification, and anomaly detection.
- **Usage:**
  - `StandardScaler`: Normalizes feature distributions, saved to a `.joblib` sidecar file for RCE protection.
  - `LogisticRegression`: Baseline linear classifier fallback.
  - `IsolationForest`: Unsupervised anomaly detection scoring.

### 3. SHAP (`shap >= 0.42.0`) & PyTorch Autograd
- **Role:** Explainable AI (XAI) engine explaining model predictions to SOC analysts.
- **Usage:**
  - `LSTMSHAPExplainer`: Computes PyTorch autograd gradient-to-input attributions (`|∇x y * x|`) directly against the active PyTorch LSTM model.
  - `shap.GradientExplainer`: Reference sequence attribution explainer.

### 4. Joblib (`joblib >= 1.2.0`)
- **Role:** Object serialization library.
- **Usage:** Used to save and load scikit-learn models (`baseline_models.joblib`) and sidecar scaler files (`lstm_model.scaler.joblib`).

---

## 4. Telemetry Pipeline & Data Engineering Stack

### 1. Pandas (`pandas >= 2.0.0`)
- **Role:** Tabular data processing and feature engineering library.
- **Usage:** Handles DataFrame operations, feature matrix construction, sliding temporal window generation, missing value imputation, and dataset CSV exports under `data/processed/`.

### 2. NumPy (`numpy >= 1.24.0`)
- **Role:** Numerical computing library.
- **Usage:** Array transformations, concatenated sequence pooling calculations, feature mean-padding for short-sequence inference, and mathematical operations.

### 3. Python-EVTX (`python-evtx >= 0.8.0`)
- **Role:** Low-level parser for native Windows Event Log (`.evtx`) binary files.
- **Usage:** Reads Sysmon EVTX logs and parses raw XML record payloads into structured Python event objects (`pipeline/evtx_reader.py`).

---

## 5. Backend Web Framework & Security Stack

### 1. Flask (`Flask >= 2.3.0`)
- **Role:** Micro web framework hosting the backend REST APIs.
- **Usage:** Implements application factory (`app.py`) and modular Blueprints (`telemetry_routes.py`, `incident_routes.py`, `xai_routes.py`).

### 2. Flask-SQLAlchemy (`Flask-SQLAlchemy >= 3.0.0`)
- **Role:** Object-Relational Mapper (ORM) for SQLite database interactions.
- **Usage:** Manages `Incident`, `FeatureVector`, and `ExplainabilityLog` database models, executing safe parameterized queries with `_safe_like()` SQL wildcard escaping.

### 3. Flask-CORS (`Flask-Cors >= 4.0.0`)
- **Role:** Cross-Origin Resource Sharing security middleware.
- **Usage:** Restricts API access from unauthorized domains to an explicit domain allowlist defined in `BRDS_CORS_ORIGINS`.

### 4. Python-Dotenv (`python-dotenv >= 1.0.0`)
- **Role:** Environment variable configuration loader.
- **Usage:** Loads keys (`BRDS_API_KEY`, `BRDS_ALERT_HMAC_KEY`, `BRDS_DRY_RUN`) from `.env` files into environment context.

---

## 6. Database & Cryptographic Integrity Layer

### 1. SQLite (`sqlite3` / `brds.db`)
- **Role:** Embedded, zero-configuration relational database.
- **Usage:** Persists active security incidents, feature vectors, and cached SHAP attributions for fast API retrieval.

### 2. HMAC-SHA256 & hashlib (Python Standard Library)
- **Role:** Cryptographic anti-tampering and authentication suite.
- **Usage:**
  - **API Authentication:** Constant-time `hmac.compare_digest` verification on incoming `X-BRDS-API-Key` headers.
  - **Alert Signing:** Cryptographic HMAC-SHA256 signatures on alert containers (`dry_run_alerts.json`).
  - **Arming Tokens:** Single-use HMAC `.arm_token` creation before invoking host containment.
  - **Model Integrity:** SHA-256 digest manifest verification (`lstm_model.sha256`) before PyTorch unpickling.

---

## 7. Frontend Visualization & Icon Libraries

### 1. Chart.js (v4.x CDN)
- **Role:** HTML5 Canvas-based chart rendering library.
- **Usage:** Renders the 30-window rolling threat profile risk curve with smooth linear interpolation and threshold indicator lines.

### 2. Lucide Icons (v0.x CDN)
- **Role:** Lightweight SVG icon suite.
- **Usage:** Renders security icons across the SOC dashboard UI (`shield-alert`, `activity`, `terminal`, `shield-check`, `loader-2`).

---

## 8. System Security & Endpoint Tools

### 1. Microsoft Sysmon (System Monitor v15+)
- **Role:** Windows service and kernel driver capturing detailed system activity.
- **Usage:** Generates raw event logs for Process Creation (Event 1), Network Connection (Event 3), Image Load (Event 7), Registry Modification (Event 12/13), and File Creation/Deletion (Event 11/23/26).

### 2. Windows Firewall (`netsh` / PowerShell Firewall Cmdlets)
- **Role:** Endpoint network filtering engine.
- **Usage:** Executed by `ContainHost.ps1` to apply inbound/outbound block rules during host isolation.

---

## 9. Automated Testing & Quality Assurance

### 1. PyTest (`pytest >= 9.0.0`)
- **Role:** Automated unit testing framework.
- **Usage:** Executes the 25-test suite covering backend endpoints, containment security, SQL wildcard escaping, watchdog gap alerts, PyTorch LSTM inference, and XAI gradient attributions.

---

## 10. Summary Tech Stack Table

| Category | Technology / Library | Version | Role in BRDS Project |
| :--- | :--- | :--- | :--- |
| **Core Runtimes** | Python | 3.14 | Core backend, ML pipeline, pipeline parsing, & daemon |
| **Automation** | PowerShell | 5.1 / 7+ | OS-level host isolation & process tree collapse |
| **Web UI** | JS (ES6) / HTML5 / CSS3 | Native | Dark-mode SOC Dashboard frontend |
| **Deep Learning** | PyTorch (`torch`) | $\ge 2.0.0$ | Deep LSTM sequence neural network model |
| **Machine Learning** | Scikit-Learn | $\ge 1.2.0$ | Baseline classifiers, anomaly detection, & scalers |
| **Explainable AI** | SHAP & Autograd | $\ge 0.42.0$ | PyTorch integrated gradient feature attributions |
| **Data Processing** | Pandas & NumPy | $\ge 2.0.0$ | Sliding window feature extraction & CSV handling |
| **Log Parsing** | Python-EVTX | $\ge 0.8.0$ | Native Windows Sysmon `.evtx` XML log parser |
| **Backend Web Framework** | Flask | $\ge 2.3.0$ | RESTful API server & blueprint routing |
| **Database ORM** | Flask-SQLAlchemy | $\ge 3.0.0$ | Database ORM & SQL wildcard escaping |
| **Database Engine** | SQLite (`brds.db`) | 3.x | Relational persistence for incidents & telemetry |
| **Web Security** | Flask-CORS | $\ge 4.0.0$ | CORS origin allowlist domain protection |
| **Cryptography** | HMAC-SHA256 / hashlib | Native | Alert signatures, arm tokens, & API key verification |
| **UI Visualization** | Chart.js | 4.x CDN | Real-time risk profile timeline canvas |
| **UI Icons** | Lucide Icons | CDN | SOC dashboard SVG icon suite |
| **Endpoint Monitoring** | Microsoft Sysmon | v15+ | Endpoint event logging kernel driver |
| **Automated Testing** | PyTest | $\ge 9.0.0$ | Automated test suite execution (25 tests) |
