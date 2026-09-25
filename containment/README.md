# Automated Containment Engine: Safety & Operational Guide

This directory contains the automated threat mitigation modules for the Behavioral Ransomware Detection System (BRDS-PEC). It provides host network isolation and recursive process tree collapse when an incident crosses the risk threshold ($\ge 0.85$).

> **Validation Status:** Guarded live containment capability is implemented with strict multi-gate safety checks, but remains pending end-to-end isolated-VM validation. Default operation is strictly dry-run.

---

## Safety Architecture: Multi-Gate Containment

To prevent accidental host lockouts or session termination during developer analysis while supporting authentic mitigation in isolated sandbox VMs, the containment engine implements a strict **Triple-Gate Execution Model**:

```
                       Alert Detected (Risk >= 0.85)
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
     BRDS_LAB_ENVIRONMENT_APPROVED  BRDS_LIVE_     HMAC .arm_token
               == "1"?          CONTAINMENT == "1"?    Valid?
                    │                │                │
                    └────────────────┼────────────────┘
                                     │
                       All True? ────┴─── No ──► Dry-Run Simulation Mode
                                     │           (Passes -DryRunOverride; logs only)
                                    Yes
                                     │
                                     ▼
                          Live Containment Mode
                          (Passes -Armed to PS1 scripts;
                           disables NICs, kills processes,
                           logs to containment_audit.jsonl,
                           updates Incident status to CONTAINED via API)
```

### 1. Dry-Run Mode (Default Safe State)
- **Condition**: Default when `BRDS_LAB_ENVIRONMENT_APPROVED != 1`, `BRDS_LIVE_CONTAINMENT != 1`, or when `.arm_token` is missing.
- **Behavior**: The trigger daemon passes `-DryRunOverride` to both PowerShell scripts.
- **Result**: Scripts log the actions they *would* take (`[DRY-RUN] Would disable adapter...`, `[DRY-RUN] Would terminate process...`) without disrupting network interfaces or terminating processes.
- **Auditing**: Written to `data/processed/containment_audit.jsonl` with `"mode": "DRY-RUN"`.

### 2. Lab Armed Mode (Isolated Sandbox VM Only)
- **Condition**: ALL THREE gates satisfied simultaneously:
  1. `BRDS_LAB_ENVIRONMENT_APPROVED=1` in daemon environment
  2. `BRDS_LIVE_CONTAINMENT=1` in daemon environment
  3. Valid HMAC-signed `.arm_token` present at `containment/.arm_token`
  4. `BRDS_API_KEY` configured for authenticated status updates
- **Behavior**: The daemon passes `-Armed` to the PowerShell scripts.
- **Actions Executed**:
  1. `kill_process_tree.ps1`: Recursively collapses the process tree for the malicious PID, safely respecting the protected system processes list (`lsass`, `csrss`, `services`, `explorer`, `svchost`, etc.).
  2. `ContainHost.ps1`: Disables all active network adapters via `Disable-NetAdapter` to cut off C2 command-and-control communication and lateral SMB propagation.
  3. `containment_audit.jsonl`: Appends a cryptographically auditable JSON record of executed actions, exit codes, and output.
  4. Backend Sync: Sends authenticated `POST /api/containment/status` with `status: "CONTAINED"` using `X-BRDS-API-Key` to synchronize SOC dashboard telemetry.

---

## Directory Components

- **`ContainHost.ps1`**: Host isolation script. Guarded via `$env:BRDS_LIVE_CONTAINMENT` and `-Armed`.
- **`kill_process_tree.ps1`**: Recursive bottom-up process killer. Protects critical Windows system processes.
- **`RollbackHost.ps1`**: Lab recovery utility. Re-enables disabled network adapters after detonation testing.
- **`trigger_daemon.py`**: Background monitoring daemon. Polls signed alerts every 1.5 seconds, verifies the safety gates, executes scripts, and writes durable containment audit logs.
- **`alert_integrity.py`**: HMAC-SHA256 signature verification for alert records and the activation arm token.

---

## How to Test in Your Isolated Lab VM

### Step 1: Generate an Arm Token
```powershell
$env:BRDS_ALERT_HMAC_KEY = "your-secret-lab-hmac-key"
python containment/trigger_daemon.py --create-arm-token
```

### Step 2: Arm the Environment and Start the Daemon
```powershell
$env:BRDS_LAB_ENVIRONMENT_APPROVED = "1"
$env:BRDS_LIVE_CONTAINMENT = "1"
$env:BRDS_ALERT_HMAC_KEY = "your-secret-lab-hmac-key"
$env:BRDS_API_KEY = "your-secret-api-key"
python containment/trigger_daemon.py
```

### Step 3: Rollback Network Adapters After Test
```powershell
$env:BRDS_LIVE_CONTAINMENT = "1"
.\containment\RollbackHost.ps1 -Armed
```
