# Behavioral Ransomware Detection System (BRDS-PEC)
## Enterprise Implementation & Production Deployment Guide

**Target System:** BRDS-PEC (Behavioral Ransomware Detection System with Pre-Encryption Containment)  
**Objective:** Complete operational roadmap to transition the prototype into a production-grade enterprise endpoint security solution.  

---

## 1. Executive Implementation Roadmap

Transitioning BRDS-PEC from a prototype/demo to an enterprise production environment follows a **5-Phase Engineering & Operations Framework**:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        BRDS-PEC PRODUCTION IMPLEMENTATION ROADMAP                      │
├─────────────────┬──────────────────┬──────────────────┬─────────────────┬──────────────┤
│ Phase 1:        │ Phase 2:         │ Phase 3: Model   │ Phase 4: Staged │ Phase 5:     │
│ Infrastructure  │ Endpoint Fleet   │ Calibration &    │ Deployment &    │ Operations & │
│ Hardening       │ Deployment       │ Benign Baseline  │ Containment Arm │ SOC Playbooks│
│                 │                  │                  │                 │              │
│ Secrets & Keys, │ Sysmon GPO/Intune│ Real Telemetry,  │ Dry-Run Mode,   │ SIEM / SOAR, │
│ PostgreSQL DB,  │ Win Service,     │ Retrain LSTM,    │ Canary Hosts,   │ XAI Triage,  │
│ Redis Queue     │ Watchdog Engine  │ Target FPR ≤0.1% │ Arm Token Check │ Model Drift  │
└────────┬────────┴────────┬─────────┴────────┬─────────┴────────┬────────┴──────┬───────┘
         │                 │                  │                  │               │
         ▼                 ▼                  ▼                  ▼               ▼
   [ Hardened Infra ] [ Fleet Deployed ] [ Zero FPR Model ] [ Live Active ] [ SOC Integrated ]
```

---

## 2. Phase 1: Infrastructure & Backend Hardening

### 1.1 Secrets & Key Management
- **Replace Default Environment Keys:** Never deploy default HMAC secret fallback keys in production.
- **Key Vault Integration:** Store `BRDS_API_KEY` and `BRDS_ALERT_HMAC_KEY` in enterprise secret managers (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).
- **High-Entropy Generation:** Generate cryptographically secure 256-bit production keys:
  ```powershell
  # Generate 256-bit secret key in PowerShell
  $bytes = New-Object Byte[] 32
  [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
  [Convert]::ToBase64String($bytes)
  ```

### 1.2 Database Migration (SQLite to PostgreSQL)
- **Replace SQLite (`brds.db`):** SQLite is unsuited for multi-node enterprise logging under concurrent write loads.
- **Migrate to PostgreSQL Cluster:** Update `SQLALCHEMY_DATABASE_URI` in `backend/config.py`:
  ```python
  SQLALCHEMY_DATABASE_URI = os.getenv(
      "DATABASE_URL", 
      "postgresql+psycopg2://brds_user:SecretPass@postgres-cluster.corp.internal:5432/brds_db"
  )
  ```

### 1.3 Asynchronous Queueing for High-Throughput Ingestion
- **Implement Message Queue:** Convert synchronous `POST /api/score/live` inference to an asynchronous task queue (Celery + Redis or Apache Kafka) to handle high-density Sysmon event bursts (>10,000 events/sec across thousands of endpoints).

---

## 3. Phase 2: Endpoint Fleet Deployment

### 2.1 Enterprise Sysmon Rollout via GPO / Intune
- Deploy Microsoft Sysmon v15+ across all corporate Windows workstations and servers using Group Policy Objects (GPO), Microsoft Intune, or MECM/SCCM.
- **Apply Production Ruleset:** Deploy `sysmon_config/sysmon_config.xml` capturing Event IDs 1, 3, 7, 9, 10, 11, 12, 13, 15, 23, 25, and 26.
  ```cmd
  :: Silent Enterprise Sysmon Installation Command
  sysmon64.exe -i sysmon_config\sysmon_config.xml -accepteula
  ```

### 2.2 Background Windows Service Package
- Package `pipeline/` (evtx parsing, temporal windowing, vectorization, watchdog) into a background Windows Service using PyInstaller and NSSM (Non-Sucking Service Manager):
  ```cmd
  nssm.exe install BRDS_Agent "C:\Program Files\BRDS\agent.exe"
  nssm.exe set BRDS_Agent Start SERVICE_AUTO_START
  ```

---

## 4. Phase 3: Model Calibration & Real Benign Telemetry Training

### 4.1 Replace Synthetic Benign Data with Clean Endpoint Baseline
- **Collect Real Telemetry:** Capture 2 to 4 weeks of non-malicious Sysmon event telemetry from clean enterprise workstations (software developers, HR, finance, IT admins, servers).
- **Retrain Classifier:** Merge real benign telemetry with ransomware attack scenarios and run `scripts/train_baseline.py` and `ml_engine/lstm/train.py`.

### 4.2 Threshold Calibration
- Calibrate the warning threshold (currently `0.60`) and containment threshold (currently `0.85`) against actual enterprise background noise to ensure a **Target False Positive Rate $\le 0.1\%$**.

---

## 5. Phase 4: Staged Deployment & Armed Containment

### 5.1 Stage 1 — Dry-Run Audit Mode (`BRDS_DRY_RUN=True`)
- Deploy BRDS across 50 to 100 canary endpoints in **Dry-Run Mode** for 14 days.
- Audit alerts in the SOC Dashboard (`frontend/`) and verify XAI feature attributions (`LSTMSHAPExplainer`). Ensure normal corporate administrative scripts do not trigger false alerts.

### 5.2 Stage 2 — Live Armed Containment (`BRDS_DRY_RUN=False`)
- **Enable Armed Containment:** Update environment configuration to `BRDS_DRY_RUN=False`.
- **Cryptographic Verification:** Confirm `containment/trigger_daemon.py` validates HMAC signatures on `dry_run_alerts.json` and issues a `.arm_token` before invoking:
  - `ContainHost.ps1 -Armed`: Disables active NICs, flushes ARP/DNS, and applies firewall block rules.
  - `kill_process_tree.ps1 -Armed`: Collapses ransomware process sub-trees while enforcing `$PROTECTED_PROCESSES` (`lsass`, `csrss`, `svchost`, etc.).

---

## 6. Phase 5: SOC Operations, SIEM Integration & Playbooks

### 6.1 Central SIEM / SOAR Connector
- Connect backend REST API endpoints (`GET /api/alerts`, `GET /api/health`) to enterprise SIEM platforms (Splunk, Microsoft Sentinel, Elastic Security, QRadar).

### 6.2 Host Recovery Playbook (Post-Containment Un-Isolation)
- Define host recovery procedures for SOC analysts to re-enable isolated endpoints after malware remediation:
  ```powershell
  # Host Recovery Script (Executed by SOC Administrator after remediation)
  Get-NetAdapter | Enable-NetAdapter
  netsh advfirewall firewall delete rule name="BRDS_ISOLATION_BLOCK"
  Clear-DnsClientCache
  ```

---

## 7. Operational Implementation Checklist

| Implementation Task | Target Component | Responsible Team | Verification |
| :--- | :--- | :--- | :--- |
| **1. Secrets Management** | AWS Vault / Azure Key Vault | SecOps / DevOps | High-entropy production keys configured |
| **2. DB Migration** | PostgreSQL Cluster | Database Engineering | `brds_db` schema migrated & tested |
| **3. Sysmon Deployment** | Sysmon v15+ via GPO | Endpoint Engineering | Active on 100% of Windows hosts |
| **4. Real Benign Baseline** | `scripts/train_baseline.py` | Data Science / ML Team | Models trained on real enterprise logs |
| **5. Dry-Run Audit (14 Days)**| SOC Dashboard (`frontend/`) | SOC Analysts | FPR $\le 0.1\%$; Zero false isolations |
| **6. Live Armed Containment** | `trigger_daemon.py` & `.arm_token` | SecOps / Incident Response | Host isolation & process tree collapse verified |
