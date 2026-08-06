# SILRAD-1.0 Dataset Exploration & Integration Analysis
## A Sysmon Incremental Learning System for Ransomware Analysis and Detection

**Dataset Name:** SILRAD (Sysmon Incremental Learning Dataset for Ransomware Analysis v1.0)  
**Authors:** Jamil Ispahany, Md Rafiqul Islam, M. Arif Khan, Md Zahidul Islam  
**Institution:** Charles Sturt University (Australia) & Cyber Security Cooperative Research Centre (CSCRC)  
**Status:** Explored & Analyzed for BRDS-PEC Integration  

---

## 1. Executive Summary

The **SILRAD-1.0 Dataset** is a high-quality, Sysmon-based behavioral telemetry dataset specifically collected to evaluate machine learning systems against modern ransomware and concept drift. 

Unlike older static malware benchmarks, SILRAD records real-time **Sysmon event logs from isolated Windows 11 virtual machines** running active ransomware payloads alongside 176,000+ real benign application events harvested from PortableApps utilities and background system services.

Integrating SILRAD into **BRDS-PEC** provides genuine Windows 11 benign background telemetry, eliminating reliance on synthetic benign data and expanding our ransomware family evaluation to modern threat groups including **BlackBasta, Hive, AvosLocker, and REvil**.

---

## 2. Dataset Composition & Metrics

```
SILRAD-1.0 Dataset (Total: ~196,840 Sysmon Events)
├── Goodware / Benign Events: 176,130 (89.5%)
└── Ransomware Events:         20,710 (10.5%)
```

### 2.1 Ransomware Sample Distribution (50 Active Samples across 6 Families)
1. **AvosLocker:** High-speed multi-threaded encryption & shadow copy deletion.
2. **BlackBasta:** Modern double-extortion ransomware targeting corporate endpoints.
3. **Conti:** Highly evasive, multi-threaded DLL payload execution.
4. **Hive:** Golang/Rust-based rapid file system wiper.
5. **LockBit (v2 / v3):** Mass file extension modification and registry Defender disabling.
6. **REvil (Sodinokibi):** Command-prompt subprocess spawning and network callback.

### 2.2 Sysmon Event IDs Captured
- **Event ID 1:** Process Creation (PID, ParentPID, Image, CommandLine, User).
- **Event ID 2:** File Creation Time Modification (Timestomping detection).
- **Event ID 3 & 22:** Network Connection & DNS Query (C2 IP addresses and domains).
- **Event ID 5:** Process Termination.
- **Event ID 7:** Image/DLL Load (Unwhitelisted DLL injection).
- **Event ID 8 & 25:** Remote Thread Creation & Process Tampering (Process hollowing).
- **Event ID 11:** File Creation (Mass file writes).
- **Event ID 12 & 13:** Registry Object / Value Modifications (Disabling Defender/UAC).
- **Event ID 17:** Named Pipe Event (Inter-process communication).
- **Event ID 23:** File Delete / Archive Wipe (Shadow copy & backup removal).

---

## 3. Dataset File Breakdown

The dataset contains 3 primary CSV files under `SILRAD-dataset/`:

| File Name | File Size | Row Count | Purpose & Usage |
| :--- | :--- | :--- | :--- |
| `fasttext-all-nofamily.csv` | **89.7 MB** | 196,840 | Complete unified dataset containing all benign and ransomware event records. |
| `fasttext-trainmodel.csv` | **18.3 MB** | ~40,000 | Prepared training split for offline and incremental online learning model fitting. |
| `fasttext-testmodel.csv` | **71.4 MB** | ~156,840 | Held-out testing split for validating detection metrics against online concept drift. |

---

## 4. Feature Schema (37 Columns)

```
Column Name         | Data Type | Description / Usage in BRDS Pipeline
--------------------+-----------+-------------------------------------------------------------
event.code          | Integer   | Sysmon Event ID (1, 2, 3, 5, 7, 8, 11, 12, 13, 17, 22, 23, 25)
ProcessGuid         | String    | Unique process identifier (matches BRDS process_key)
ProcessId           | Integer   | Windows Process ID (PID)
Image               | String    | Executable path (e.g., C:\Windows\System32\cmd.exe)
ParentImage         | String    | Parent process executable path
ParentProcessGuid   | String    | Parent process unique GUID
CommandLine         | String    | Process execution command-line arguments
TargetObject        | String    | Registry key / value path modified
TargetImage         | String    | Target process path for process access/injection
GrantedAccess       | String    | Windows access rights bitmask (e.g., 0x1F0FFF)
CallTrace           | Numeric   | FastText embedding of Win32 API call stack trace
EventType           | String    | Sysmon activity type description
SignatureStatus     | String    | Binary digital signature verification state
IsExecutable        | Boolean   | Flag indicating executable file creation
class               | Integer   | Target Label: 0 = Goodware (Benign), 1 = Ransomware
```

---

## 5. SILRAD Baseline Benchmark Results (from Authors' Study)

Using incremental online machine learning on SILRAD, the authors achieved the following benchmark performance metrics:

- **Accuracy:** **98.89%**
- **Precision:** **94.87%**
- **Recall:** **94.59%**
- **F1-Score:** **94.73%**
- **Matthews Correlation Coefficient (MCC):** **94.11%**

---

## 6. Integration Strategy into BRDS-PEC

### Step 1: Benign Telemetry Replacement
- Extract the 176,130 real Windows 11 benign events from `fasttext-all-nofamily.csv` where `class = 0`.
- Aggregate event records into 5-second sliding temporal windows using `pipeline/temporal_aggregator.py`.
- Replace synthetic benign data in `scripts/prepare_live_data.py` with genuine Windows 11 endpoint telemetry.

### Step 2: Expanded Ransomware Family Evaluation
- Map Sysmon events from **BlackBasta, Hive, AvosLocker, and REvil** into 30-step temporal sequence tensors (`ml_engine/lstm/dataset.py`).
- Validate `LSTMClassifier` recall against multi-family pre-encryption behaviors.

### Step 3: Concept Drift Evaluation
- Evaluate model decay over time using `fasttext-testmodel.csv` to measure how well the PyTorch LSTM generalizes as new ransomware families emerge.
