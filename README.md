# BRDS-PEC

## Behavioral Ransomware Detection System with Pre-Encryption Containment

> An AI-powered behavioral ransomware detection system that identifies malicious activity **before file encryption begins** and automatically isolates the infected host to minimize damage.

---

## Overview

Traditional antivirus solutions often rely on malware signatures or detect ransomware only after encryption has started. BRDS-PEC takes a different approach by monitoring **behavioral patterns** from Windows Sysmon telemetry and using a **multi-stage machine learning pipeline** to detect ransomware during its early execution phase.

Once a high-confidence attack is identified, the system automatically:

- Disconnects the host from the network
- Terminates the malicious process tree
- Generates explainable AI (SHAP) reports
- Logs the incident for forensic analysis

The goal is to stop ransomware **before encryption occurs**.

---

## Key Features

- Real-time Windows Sysmon monitoring
- Behavioral detection instead of signature matching
- Two-stage ML detection pipeline
  - Isolation Forest (Anomaly Detection)
  - LSTM (Sequence Classification)
- Automatic host containment
- Process tree termination
- Explainable AI using SHAP
- REST API backend
- Live SOC dashboard
- Incident logging and forensic support

---

# System Architecture

```
                 Windows Host
                      │
                      ▼
              Microsoft Sysmon
                      │
                      ▼
          EVTX Log Monitoring Agent
                      │
                      ▼
           Event Filtering & Parsing
                      │
                      ▼
      Feature Extraction (1-second vectors)
                      │
                      ▼
        Isolation Forest (Tier 1 Screening)
             │
     Normal ─┴────► Discard
             │
         Anomalous
             ▼
      LSTM Sequence Classifier
             │
      Risk Score (0.0–1.0)
             │
     <0.85 ─────► Continue Monitoring
             │
          ≥0.85
             ▼
 ┌─────────────────────────────────┐
 │ Automated Containment Engine    │
 │                                 │
 │ • Disable Network Adapter       │
 │ • Kill Process Tree             │
 │ • Store Incident                │
 │ • Generate SHAP Explanation     │
 └─────────────────────────────────┘
             │
             ▼
      Flask REST API
             │
             ▼
      SOC Monitoring Dashboard
```

---

# Detection Pipeline

## Phase 1 — Telemetry Collection

The monitoring agent continuously reads Windows Sysmon Event Logs and extracts only security-relevant events.

Supported Event IDs:

| Event ID | Description             |
| -------- | ----------------------- |
| 1        | Process Creation        |
| 3        | Network Connection      |
| 7        | DLL/Image Loaded        |
| 11       | File Creation           |
| 12       | Registry Object Created |
| 13       | Registry Value Modified |

---

## Phase 2 — Data Processing

Incoming telemetry is transformed into machine-learning-ready data.

Steps include:

- Event filtering
- JSON flattening
- One-hot encoding
- Feature extraction
- Temporal aggregation
- 1-second rolling feature vectors

---

## Phase 3 — AI Detection Engine

### Tier 1 — Isolation Forest

The first model removes normal system activity.

**Purpose**

- Reduce computational overhead
- Detect anomalous behavior
- Forward only suspicious activity

---

### Tier 2 — LSTM

Only anomalous sequences are evaluated by a two-layer LSTM.

The LSTM analyzes:

- Process execution order
- Registry modifications
- File activity
- Network behavior
- Temporal relationships

Output:

```
Risk Score ∈ [0,1]
```

Containment threshold:

```
Risk Score ≥ 0.85
```

---

## Phase 4 — Automated Containment

If the detection threshold is exceeded:

- Network adapters are disabled
- Malicious process tree is terminated
- Incident is logged
- SHAP explanations are generated
- Dashboard is updated in real time

---

# Technology Stack

## Languages

- Python 3.10+
- PowerShell
- HTML
- CSS
- JavaScript

## Machine Learning

- PyTorch
- Scikit-learn
- SHAP

## Data Processing

- pandas
- NumPy
- python-evtx

## Backend

- Flask
- SQLAlchemy
- SQLite (MVP)
- PostgreSQL (Future)

## Frontend

- HTML5
- CSS3
- JavaScript
- Chart.js

---

# Project Structure

```
brds-pec/
│
├── docs/
├── pipeline/
├── ml_engine/
├── containment/
├── backend/
├── frontend/
├── data/
├── scripts/
├── sandbox/
└── tests/
```

### Main Modules

| Module      | Purpose                            |
| ----------- | ---------------------------------- |
| pipeline    | Sysmon ingestion and preprocessing |
| ml_engine   | AI models and risk engine          |
| containment | Automated response scripts         |
| backend     | Flask REST API                     |
| frontend    | Monitoring dashboard               |
| data        | Datasets and trained models        |
| docs        | Design documentation               |
| tests       | Unit and integration tests         |

---

# Machine Learning Pipeline

```
Sysmon Logs
      │
      ▼
Feature Extraction
      │
      ▼
Isolation Forest
      │
      ▼
30 Event Sliding Window
      │
      ▼
LSTM Network
      │
      ▼
Risk Score
      │
      ▼
Containment Decision
```

---

# Explainable AI (XAI)

Each detection generates a SHAP explanation showing:

- Features contributing to the alert
- Positive risk indicators
- Negative risk indicators
- Feature importance ranking

This enables SOC analysts to understand _why_ the model isolated the host.

---

# Dashboard Features

The monitoring dashboard provides:

- Live risk score timeline
- Real-time Sysmon event stream
- Incident history
- Containment status
- SHAP waterfall visualization
- Agent health monitoring

---

# Database

The system stores information in four primary tables.

| Table               | Purpose                |
| ------------------- | ---------------------- |
| Raw_Telemetry       | Original Sysmon events |
| Feature_Vectors     | Aggregated ML inputs   |
| Incidents           | Confirmed detections   |
| Explainability_Logs | SHAP outputs           |

---

# Requirements

## Operating System

- Windows 10 / Windows 11

## Hardware

- 16 GB RAM minimum
- NVIDIA GPU (recommended)

## Dependencies

```
Python 3.10+
Sysmon
PowerShell 5.1+
```

---

# Installation

Clone the repository.

```bash
git clone https://github.com/yourusername/brds-pec.git
cd brds-pec
```

Install dependencies.

```bash
pip install -r requirements.txt
```

Configure Sysmon.

```text
Import:
sysmon_config/sysmon_config.xml
```

Run the pipeline.

```bash
python scripts/run_pipeline.py
```

Start the backend.

```bash
python backend/app.py
```

Launch the frontend.

Open:

```
frontend/index.html
```

---

# Future Improvements

- Federated learning
- Cloud deployment
- eBPF telemetry
- Distributed endpoint management
- Threat intelligence integration
- Active Directory support
- SIEM integration
- Multi-host orchestration

---

# Research Goals

- Detect ransomware before encryption
- Achieve >97% detection accuracy
- Maintain response latency below 500 ms
- Provide interpretable AI decisions
- Prevent lateral movement through immediate containment

# License

This project is intended for educational and research purposes.

Please ensure all ransomware testing is conducted inside isolated virtual environments.
