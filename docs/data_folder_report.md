# Behavioral Ransomware Detection System (BRDS)
## Comprehensive Data Directory Report (`data/`)

**System:** Behavioral Ransomware Detection System (`BRDS-PEC`)  
**Scope:** Complete breakdown and explanation of all databases, trained models, processed datasets, and raw dataset repositories stored under `data/`.  

---

## 1. Directory Structure Overview

```
data/
├── brds.db                           # SQLite Relational Database for runtime backend persistence
├── datasets/                         # Raw threat telemetry & benchmark security dataset repositories
│   ├── csu_ransomware/               # CSU Ransomware Dataset source
│   ├── mlran/                        # MLRAN dataset repository
│   ├── otrf_security_datasets/       # Open Threat Research Forge (OTRF) Sysmon EVTX logs
│   ├── ransomset/                    # RansomSet benchmark dataset
│   ├── silrad/                       # SILRAD Sysmon Dataset (Charles Sturt University & CSCRC, 196k events)
│   └── splunk_attack_data/           # Splunk Attack Data repository (Sysmon execution logs)
├── models/                           # Machine learning model checkpoints, scalers & manifests
│   ├── baseline_models.joblib        # Baseline Logistic Regression & Isolation Forest models
│   ├── baseline_report.json          # Performance evaluation metrics (Precision, Recall, ROC-AUC)
│   ├── lstm_model.pth                # PyTorch Deep LSTM Neural Network state dict
│   ├── lstm_model.scaler.joblib      # StandardScaler sidecar object (RCE protection)
│   └── lstm_model.sha256             # SHA-256 cryptographic hash manifest for lstm_model.pth
└── processed/                        # Feature-engineered CSVs & signed alert containers
    ├── csu_goodware_extracted.csv    # Extracted benign system telemetry from CSU dataset
    ├── dry_run_alerts.json           # HMAC-SHA256 signed JSON container for dry-run alerts
    ├── mlran_goodware_extracted.csv  # Extracted benign telemetry from MLRAN dataset
    ├── ransomset_goodware_extracted.csv # Extracted benign system activity from RansomSet
    ├── silrad_goodware_extracted.csv # Extracted Windows 11 benign telemetry from SILRAD dataset (176k events)
    ├── sysmon_attack_windows.csv     # Feature vectors for ransomware attack execution windows
    ├── sysmon_combined_windows.csv   # Aggregated dataset (2,785 attack + 17,613 genuine Windows 11 benign windows)
    ├── sysmon_windows.csv            # Fully scored telemetry dataset (input for brds.db)
    └── test_baseline_models.joblib   # Test fixture model used in automated pytest runs
```

---

## 2. Root Database File (`data/brds.db`)

### `brds.db` (3.9 MB SQLite Database)
- **Role:** SQLite relational database engine used by the Flask backend (`backend/routes/`) to serve the live SOC dashboard.
- **Key Tables:**
  1. `incidents`: Stores active ransomware alerts including fields: `id` (e.g., `INC-1`), `timestamp`, `computer` (hostname), `ransomware_family` (e.g., `WannaCry`, `LockBit`, `Ryuk`), `risk_score`, `process_id`, and `status` (`ACTIVE` / `CONTAINED`).
  2. `feature_vectors`: Stores 5-second windowed feature vectors extracted from Sysmon logs, indexed by `window_start` timestamp and `computer` host ID.
  3. `explainability_logs`: Caches computed SHAP / PyTorch integrated gradient attributions per incident for fast UI retrieval.

---

## 3. Models Directory (`data/models/`)

This directory contains trained machine learning artifacts, scalers, reports, and security verification manifests.

### 1. `baseline_models.joblib` (1.9 MB)
- **Description:** Serialized scikit-learn pipeline containing baseline supervised models (Logistic Regression, Isolation Forest anomaly detector, feature column list).
- **Usage:** Used as a lightweight linear prediction fallback and for baseline feature importance evaluation.

### 2. `baseline_report.json` (1.0 KB)
- **Description:** Structured JSON metrics report detailing model evaluation performance across validation and test splits.
- **Key Metrics Captured:** Precision (99.53%), Recall (99.48%), F1 Score (99.51%), ROC-AUC (0.998), False Positive Rate (0.22%), True Positives (1727), and False Positives (8).

### 3. `lstm_model.pth` (676 KB)
- **Description:** PyTorch binary state dictionary checkpoint for the primary **Deep LSTM Sequence Classifier** (`ml_engine/lstm/model.py`).
- **Architecture:** Features 2 LSTM layers with hidden dimension 64, concatenated Mean + Max pooling across all 30 sequence timesteps, and a dense linear output layer (`nn.Linear(256, 1)`). Achieves **99.71% validation accuracy**.

### 4. `lstm_model.scaler.joblib` (975 B)
- **Description:** Scikit-learn `StandardScaler` sidecar file containing feature mean and variance parameters fitted on the training dataset.
- **Security Role (RCE Protection):** Kept as a separate `.joblib` file so PyTorch can unpickle `lstm_model.pth` using strict `torch.load(..., weights_only=True)`, eliminating Python pickle deserialization Remote Code Execution (RCE) vulnerabilities.

### 5. `lstm_model.sha256` (64 B)
- **Description:** Cryptographic SHA-256 hash manifest containing the exact hex digest of `lstm_model.pth`.
- **Security Role:** Prior to loading the neural model during inference (`ml_engine/lstm/infer.py`), `infer.py` recalculates the SHA-256 hash of `lstm_model.pth` and asserts an exact match against `lstm_model.sha256` to prevent unauthorized model tampering or poison replacement.

---

## 4. Processed Data Directory (`data/processed/`)

This directory contains feature-engineered CSV datasets and signed alert containers generated during data preparation (`scripts/prepare_live_data.py`) and scoring (`scripts/score_windows.py`).

### 1. `sysmon_combined_windows.csv` (2.5 MB)
- **Description:** The primary aggregated dataset used for training and evaluating BRDS classifiers.
- **Contents:** Combines 2,785 ransomware attack execution windows (WannaCry, LockBit, Ryuk, Sodinokibi) with 17,617 genuine Windows 11 benign windows from the SILRAD dataset (20,402 total rows).
- **Features (22 Columns):** Includes administrative metadata (`computer`, `process_key`, `window_start`, `label`, `technique_id`, `scenario`, `source`) and 15 behavioral features (`event_count`, `unique_images`, `unique_files`, `unique_extensions`, `unique_destination_ips`, `suspicious_path_count`, `registry_activity_count`, `network_activity_count`, `event_1_count`, `event_3_count`, `event_7_count`, `event_11_count`, `event_12_count`, `event_13_count`, `event_23_count`, `event_26_count`).

### 2. `sysmon_attack_windows.csv` (720 KB)
- **Description:** Subset CSV containing only the 2,785 ransomware attack windows extracted from Sysmon logs of active ransomware family executions.

### 3. `sysmon_windows.csv` (1.31 MB)
- **Description:** The scored telemetry dataset produced by `scripts/score_windows.py`.
- **Contents:** Contains windowed telemetry enriched with model-predicted `risk_score` and `anomaly_score` columns. Used by `prepare_live_data.py` to seed `brds.db`.

### 4. `dry_run_alerts.json` (1.39 MB)
- **Description:** Signed JSON alert container file generated during offline scoring runs.
- **Security Role:** Contains all alerts with `risk_score >= 0.85` along with an overall HMAC-SHA256 signature string (`sig`). Verified by `containment/trigger_daemon.py` before issuing containment arm tokens.

### 5. Extracted Goodware Datasets:
- **`csu_goodware_extracted.csv` (19.48 MB):** Normal background system telemetry extracted from the CSU Ransomware Dataset.
- **`mlran_goodware_extracted.csv` (1.32 MB):** Extracted benign system behavioral telemetry from MLRAN.
- **`ransomset_goodware_extracted.csv` (137 KB):** Extracted non-malicious system activity from RansomSet.

### 6. `test_baseline_models.joblib` (61.3 KB)
- **Description:** Lightweight dummy model binary fixture used exclusively during automated unit testing (`pytest`) to verify model loading pipelines without heavy CPU overhead.

---

## 5. Raw Datasets Directory (`data/datasets/`)

Contains local clones of open-source security benchmark datasets used for extracting ransomware execution logs and benign system activity.

1. **`csu_ransomware/`:** CSU Ransomware Dataset repository containing multi-family ransomware execution logs.
2. **`mlran/`:** Machine Learning Ransomware Analysis Network dataset repository.
3. **`otrf_security_datasets/`:** Open Threat Research Forge (OTRF) Security Datasets containing raw Sysmon `.evtx` files for MITRE ATT&CK techniques.
4. **`ransomset/`:** RansomSet benchmark dataset repository.
5. **`splunk_attack_data/`:** Splunk Attack Data repository containing execution traces for families such as WannaCry, LockBit, Ryuk, and Sodinokibi.

---

## 6. Summary Matrix

| Path | File Type | Size | Primary Function |
| :--- | :--- | :--- | :--- |
| `data/brds.db` | SQLite Database | 3.9 MB | REST API persistence layer for incidents & feature vectors |
| `data/models/baseline_models.joblib` | Joblib Binary | 1.9 MB | Serialized Logistic Regression & Isolation Forest models |
| `data/models/baseline_report.json` | JSON Text | 1.0 KB | Evaluation metrics (Precision, Recall, ROC-AUC) |
| `data/models/lstm_model.pth` | PyTorch Binary | 676 KB | Deep LSTM Neural Network model weights |
| `data/models/lstm_model.scaler.joblib` | Joblib Binary | 975 B | Sidecar `StandardScaler` for secure `weights_only` loading |
| `data/models/lstm_model.sha256` | SHA-256 Text | 64 B | Integrity checksum manifest verifying `lstm_model.pth` |
| `data/processed/sysmon_combined_windows.csv` | CSV Dataset | 1.05 MB | Full combined training dataset (4,785 windowed rows) |
| `data/processed/sysmon_attack_windows.csv` | CSV Dataset | 720 KB | Ransomware attack windows subset (2,785 rows) |
| `data/processed/sysmon_windows.csv` | CSV Dataset | 1.31 MB | Scored telemetry dataset populating `brds.db` |
| `data/processed/dry_run_alerts.json` | Signed JSON | 1.39 MB | HMAC-SHA256 signed alert container for containment daemon |
| `data/processed/csu_goodware_extracted.csv` | CSV Dataset | 19.48 MB | Extracted CSU benign system telemetry |
| `data/processed/mlran_goodware_extracted.csv` | CSV Dataset | 1.32 MB | Extracted MLRAN benign system telemetry |
| `data/processed/ransomset_goodware_extracted.csv` | CSV Dataset | 137 KB | Extracted RansomSet benign system telemetry |
| `data/processed/test_baseline_models.joblib` | Joblib Binary | 61.3 KB | Unit test model fixture |
