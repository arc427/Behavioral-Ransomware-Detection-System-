# BRDS-PEC

## Behavioral Ransomware Detection System with Pre-Encryption Containment

> An AI-powered behavioral ransomware detection system that identifies malicious activity **before file encryption begins** using deep sequence modeling on Windows Sysmon telemetry.

---

## Overview

Traditional antivirus solutions rely on malware signatures or detect ransomware only after encryption has started. BRDS-PEC takes a different approach by monitoring **behavioral patterns** from Windows Sysmon telemetry and using a **multi-stage machine learning pipeline** to detect ransomware during its early execution phase.

The system is a **research prototype** with containment locked to dry-run mode. Once a high-confidence attack is identified, it:

- Creates HMAC-SHA256 signed alerts with cryptographic integrity verification
- Logs the intended host-isolation and process-tree termination actions (dry-run only)
- Generates explainable AI (SHAP / PyTorch Autograd) attribution reports
- Stores the incident in a SQLite database for forensic analysis via the SOC dashboard

---

## Evaluation Results

Trained on **20,402 behavioral windows** (2,785 attack + 17,617 genuine Windows 11 benign from the [SILRAD-1.0 dataset](https://github.com/JamilIsp/SILRAD-dataset)) with strict source-level splits preventing scenario leakage:

| Metric | Test Set |
|:---|:---|
| **Precision** | 99.53% |
| **Recall** | 99.48% |
| **F1 Score** | 99.51% |
| **ROC-AUC** | 0.998 |
| **False Positive Rate** | 0.22% |
| **Detection Window** | 5–15 seconds post-execution |

> **Note:** Detection lead time cannot yet be claimed — it requires verified encryption-start timestamps for each attack scenario. See [`docs/known_limitations.md`](docs/known_limitations.md) for full caveats.

---

## Key Features

- **Behavioral Detection** — monitors Sysmon event sequences, not file hashes
- **Two-Stage ML Pipeline** — Isolation Forest screening → LSTM sequence classification
- **Real Baseline Data** — 17,617 genuine Windows 11 benign windows from SILRAD-1.0
- **Cryptographic Alert Integrity** — HMAC-SHA256 signed alert containers and arm tokens
- **Explainable AI (XAI)** — PyTorch Autograd gradient attributions explain every alert
- **SOC Dashboard** — dark-mode real-time monitoring with Chart.js risk timeline
- **Dry-Run Containment** — host isolation and process tree collapse (logged, not executed)
- **29 Automated Tests** — covering backend, ML, containment, XAI, and SILRAD adapter

---

## System Architecture

```
Windows Sysmon (v15+) Event Logging (Event IDs 1, 3, 7, 11, 12, 13, 23, 26)
  ↓
Pipeline Parse & Temporal Aggregation (5-second Sliding Windows)
  ↓
Isolation Forest (Tier 1 — Anomaly Screening)
  ↓
Deep LSTM Sequence Classifier (Tier 2 — 2-layer Bidirectional LSTM)
  ↓
Risk Score ∈ [0.0, 1.0]
  ↓
≥ 0.85 → HMAC-SHA256 Signed Alert → Dry-Run Containment Log
  ↓
SOC Dashboard & XAI Attribution Modal
```

---

## Detection Pipeline

### Phase 1 — Telemetry Collection

Sysmon events are parsed from `.evtx` or `.log` files and filtered to security-relevant IDs:

| Event ID | Description |
|:---|:---|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | DLL / Image Loaded |
| 11 | File Creation |
| 12 | Registry Object Created |
| 13 | Registry Value Modified |
| 23 | File Delete (archived) |
| 26 | File Delete (logged) |

### Phase 2 — Feature Engineering

Events are aggregated into 5-second sliding windows per process, producing 17 numeric behavioral features: event counts by type, unique images/files/extensions, network destinations, suspicious path indicators, and composite activity scores.

### Phase 3 — AI Detection Engine

**Tier 1 — Isolation Forest:** Screens out normal system activity with unsupervised anomaly detection.

**Tier 2 — LSTM Classifier:** A 2-layer Bidirectional LSTM with hidden dimension 64, concatenated Mean + Max pooling across 30 timesteps, and sigmoid output. Loaded with `torch.load(..., weights_only=True)` and verified against a SHA-256 hash manifest.

### Phase 4 — Dry-Run Containment

When risk ≥ 0.85, the system **logs the intended response** without executing it:
- Network adapter isolation (`ContainHost.ps1` — dry-run)
- Process tree termination (`kill_process_tree.ps1` — dry-run)
- SHAP attribution report generation
- Incident database entry

> ⚠️ Live containment is intentionally disabled. See [`docs/known_limitations.md`](docs/known_limitations.md).

---

## Technology Stack

| Category | Technologies |
|:---|:---|
| **Core Runtime** | Python 3.14, PowerShell 5.1/7+ |
| **Deep Learning** | PyTorch ≥ 2.0.0 (LSTM Classifier) |
| **Machine Learning** | Scikit-Learn (Isolation Forest, Logistic Regression) |
| **Explainable AI** | SHAP, PyTorch Autograd Gradients |
| **Data Processing** | Pandas, NumPy, python-evtx |
| **Backend** | Flask, Flask-SQLAlchemy, Flask-CORS |
| **Database** | SQLite (`brds.db`) |
| **Frontend** | HTML5, CSS3, JavaScript (ES6), Chart.js |
| **Security** | HMAC-SHA256, SHA-256 model integrity, constant-time auth |
| **Testing** | PyTest (29 tests) |

---

## Project Structure

```
brds-pec/
├── pipeline/           # Sysmon parsing, filtering, temporal aggregation, SILRAD adapter
├── ml_engine/          # LSTM model, risk engine, SHAP explainer
├── containment/        # PowerShell scripts, alert integrity, trigger daemon
├── backend/            # Flask REST API, SQLAlchemy models, auth middleware
├── frontend/           # SOC dashboard (HTML/CSS/JS + Chart.js)
├── data/
│   ├── datasets/       # Raw datasets (Splunk, SILRAD, CSU, MLRAN, etc.)
│   ├── models/         # Trained model checkpoints and evaluation reports
│   └── processed/      # Feature-engineered CSVs and signed alert containers
├── scripts/            # Pipeline execution, model training, data preparation
├── docs/               # 22 documentation files (architecture, evaluation, etc.)
├── sysmon_config/      # Sysmon XML configuration
├── sandbox/            # VM detonation setup guide
└── tests/              # 29 automated tests
```

---

## Datasets

| Dataset | Role | Records |
|:---|:---|:---|
| **SILRAD-1.0** | Genuine Windows 11 benign baseline + 6 ransomware families | 196,840 events |
| **Splunk ATT&CK Data** | Ransomware attack execution traces (WannaCry, LockBit, Ryuk, Sodinokibi) | 2,785 windows |
| **CSU Ransomware** | Supplementary goodware telemetry | 271,993 rows |
| **MLRAN** | Supplementary goodware metadata | 2,550 rows |
| **RansomSet** | Supplementary benign system calls | 2,103 rows |

---

## Installation

Clone the repository:

```bash
git clone https://github.com/arc427/Behavioral-Ransomware-Detection-System-.git
cd Behavioral-Ransomware-Detection-System-
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure environment variables (copy and edit):

```bash
cp .env.example .env
```

Run the data preparation and model training pipeline:

```bash
python scripts/run_pipeline.py
python scripts/prepare_live_data.py
```

Start the backend API:

```bash
python backend/app.py
```

Open the SOC dashboard:

```
frontend/index.html
```

Run automated tests:

```bash
python -m pytest
```

---

## Requirements

| Requirement | Specification |
|:---|:---|
| **OS** | Windows 10 / Windows 11 |
| **Python** | 3.14+ |
| **RAM** | 8 GB minimum (16 GB recommended) |
| **GPU** | Optional (NVIDIA CUDA for faster LSTM training) |
| **Sysmon** | v15+ (for live telemetry collection) |

---

## Documentation

Full project documentation is available in [`docs/`](docs/):

- [Technical Requirements Document](docs/TRD.md)
- [Product Requirements Document](docs/PRD.md)
- [Architecture Scan Report](docs/architecture_scan_report.md)
- [Data Folder Report](docs/data_folder_report.md)
- [Tech Stack Report](docs/tech_stack_report.md)
- [Evaluation Report](docs/evaluation_report.md)
- [Security Audit Report](docs/security_audit_report.md)
- [Known Limitations](docs/known_limitations.md)
- [Presentation Slides](docs/presentation.md)

---

## Future Enhancements

1. **Family-Held-Out Evaluation** — validate detection on ransomware families unseen during training
2. **Encryption Start Timestamps** — enable detection lead-time measurement
3. **Central SIEM Integration** — connect to Splunk, Microsoft Sentinel, or Elastic Security
4. **Kernel Driver Containment** — move from PowerShell to kernel space for sub-millisecond response
5. **Adaptive Online Retraining** — continuous learning from enterprise baseline drift
6. **Multi-Host Orchestration** — distributed endpoint management and federated learning

---

## License

This project is intended for educational and research purposes.

Please ensure all ransomware testing is conducted inside isolated virtual environments.
