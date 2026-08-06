# Behavioral Ransomware Detection System (BRDS-PEC)
## Technical Requirements Document (TRD)

**System Architecture:** Multi-Tiered Neural Inference & Host Containment  
**Primary Frameworks:** PyTorch 2.0+, Flask 2.3+, Scikit-Learn 1.2+, PowerShell 5.1/7.0+  
**Target Platform:** Windows 10 / 11 / Windows Server 2019+  

---

## 1. System Architecture & Component Design

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            HOST ENDPOINT LAYER                               │
│     Sysmon Agent (v15+)  ──►  evtx_reader.py  ──►  temporal_aggregator.py    │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ 5-second Sliding Windows
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                           PIPELINE & WATCHDOG LAYER                          │
│     vectorizer.py  ──►  watchdog.py (Heartbeat Check)  ──►  POST /api/score/live│
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ Header Auth: X-BRDS-API-Key
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                        BACKEND INFERENCE & XAI ENGINE                        │
│    auth.py (@require_api_key) ──► lstm/infer.py (weights_only=True)         │
│    SHA-256 Check ──► LSTMClassifier ──► LSTMSHAPExplainer (PyTorch Autograd) │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ HMAC Signed Alert & .arm_token
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                      CONTAINMENT & PERSISTENCE LAYER                         │
│   SQLite (brds.db)  ◄──  trigger_daemon.py  ──► ContainHost.ps1 & kill_tree  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Feature Engineering & Temporal Aggregation

### 2.1 Sliding Window Aggregation
- **Window Duration:** 5 seconds sliding window per process and computer host.
- **Input Features (15 Behavioral Telemetry Metrics):**
  1. `event_count`: Total Sysmon events in 5s window.
  2. `unique_images`: Count of distinct executable binary paths.
  3. `unique_files`: Count of targeted file paths.
  4. `unique_extensions`: Count of new file extensions created.
  5. `unique_destination_ips`: Count of outgoing IP connections.
  6. `suspicious_path_count`: Execution count from `AppData/Local/Temp` or user directories.
  7. `registry_activity_count`: Registry modification events (Event IDs 12/13).
  8. `network_activity_count`: Network socket connection events (Event ID 3).
  9. `event_1_count`: Process creation events (Event ID 1).
  10. `event_3_count`: Network connection events.
  11. `event_7_count`: Image/DLL load events.
  12. `event_11_count`: File create events.
  13. `event_12_count`: Registry key create/delete events.
  14. `event_13_count`: Registry value set events.
  15. `event_23_count` & `event_26_count`: File deletion and wipe events.

---

## 3. Deep Learning Model Specification (`ml_engine/lstm/`)

### 3.1 Model Architecture (`LSTMClassifier`)
- **Layer 1:** PyTorch `nn.LSTM(input_dim=15, hidden_dim=64, num_layers=2, batch_first=True, dropout=0.2)`.
- **Pooling Layer:** Concatenated Mean Pooling (`torch.mean(out, dim=1)`) and Max Pooling (`torch.max(out, dim=1)[0]`) across all 30 sequence timesteps.
- **Output Layer:** `nn.Linear(hidden_dim * 4, 1)` followed by Sigmoid probability activation.
- **Performance:** **99.71% validation accuracy**, 98.69% precision, 100% recall.

### 3.2 Inference Hardening (`ml_engine/lstm/infer.py`)
- **RCE Mitigation:** Loads state dictionary using `torch.load(..., weights_only=True)`.
- **Integrity Validation:** Asserts SHA-256 digest of `lstm_model.pth` matches `lstm_model.sha256` prior to unpickling.
- **Sidecar Scaler:** Loads fitted `StandardScaler` from `.scaler.joblib` sidecar file.
- **Sequence Mean-Padding:** Front-pads short sequences (<30 steps) with feature mean vectors (`np.mean`) to prevent artificial risk score depression.

---

## 4. Host Containment & Security Specifications

### 4.1 HMAC-SHA256 Anti-Tampering (`containment/alert_integrity.py`)
- All alert containers (`dry_run_alerts.json`) are signed with HMAC-SHA256 digests (`sign_alerts`).
- Before triggering host isolation, `trigger_daemon.py` verifies alert signatures (`verify_and_load`) and generates a single-use `.arm_token`.

### 4.2 PowerShell Script Execution
- **`ContainHost.ps1`:** Invoked with `-Armed` switch. Disables active NICs (`Disable-NetAdapter`), flushes ARP/DNS (`Clear-DnsClientCache`), and configures Windows Firewall block rules (`netsh advfirewall firewall add rule`).
- **`kill_process_tree.ps1`:** Traverses CIM process trees (`Get-CimInstance Win32_Process`) to terminate ransomware sub-trees. Checks targets against `$PROTECTED_PROCESSES = @('lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'system', 'svchost', 'explorer', 'spoolsv', 'dwm')` to prevent BSOD crashes.
