# Automated Containment Engine: Safety & Operational Guide

This directory contains the automated threat mitigation modules for the Behavioral Ransomware Detection System (BRDS-PEC). It provides host network isolation and recursive process tree collapse when an incident crosses the risk threshold ($\ge 0.85$).

---

## Safety Architecture: Dual-Gate Containment

To prevent accidental host lockouts or session termination during developer analysis while supporting authentic, live mitigation in isolated sandbox VMs, the containment engine implements a strict **Dual-Gate Execution Model**:

```
                       Alert Detected (Risk >= 0.85)
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
       BRDS_LIVE_CONTAINMENT == "1"?       HMAC .arm_token Valid?
                    │                                 │
                    └────────────────┬────────────────┘
                                     │
                       Both True? ───┴─── No ──► Dry-Run Simulation Mode
                                     │           (Passes -DryRunOverride; logs only)
                                    Yes
                                     │
                                     ▼
                          Live Containment Mode
                          (Passes -Armed to PS1 scripts;
                           disables NICs, kills processes,
                           logs to containment_audit.jsonl,
                           updates Incident status to CONTAINED)
```

### 1. Dry-Run Mode (Default Safe State)
- **Condition**: Default when `BRDS_LIVE_CONTAINMENT` is unset (or != `1`) or when `.arm_token` is missing.
- **Behavior**: The trigger daemon passes `-DryRunOverride` to both PowerShell scripts.
- **Result**: Scripts log the actions they *would* take (`[DRY-RUN] Would disable adapter...`, `[DRY-RUN] Would terminate process...`) without disrupting network interfaces or terminating processes.
- **Auditing**: Written to `data/processed/containment_audit.jsonl` with `"mode": "DRY-RUN"`.

### 2. Lab Armed Mode (Isolated Sandbox VM Only)
- **Condition**: `BRDS_LIVE_CONTAINMENT=1` in the daemon's environment **AND** a valid HMAC-signed `.arm_token` generated via `BRDS_ALERT_HMAC_KEY`.
- **Behavior**: The daemon passes `-Armed` to the PowerShell scripts.
- **Actions Executed**:
  1. `kill_process_tree.ps1`: Recursively collapses the process tree for the malicious PID, safely respecting the protected system processes list (`lsass`, `csrss`, `services`, `explorer`, `svchost`, etc.).
  2. `ContainHost.ps1`: Disables all active network adapters via `Disable-NetAdapter` to cut off C2 command-and-control communication and lateral SMB propagation.
  3. `containment_audit.jsonl`: Appends a cryptographically auditable JSON record of executed actions, exit codes, and output.
  4. Backend Sync: Sends `POST /api/containment/status` with `status: "CONTAINED"` to synchronize SOC dashboard telemetry.

---

## Directory Components

- **`ContainHost.ps1`**: Host isolation script. Dual-gated via `$env:BRDS_LIVE_CONTAINMENT` and `-Armed`.
- **`kill_process_tree.ps1`**: Recursive bottom-up process killer. Protects critical Windows system processes.
- **`RollbackHost.ps1`**: Lab recovery utility. Re-enables disabled network adapters after detonation testing.
- **`trigger_daemon.py`**: Background monitoring daemon. Polls signed alerts every 1.5 seconds, verifies the dual gate, executes scripts, and writes durable containment audit logs.
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
$env:BRDS_LIVE_CONTAINMENT = "1"
python containment/trigger_daemon.py
```

### Step 3: Rollback Network Adapters After Test
```powershell
.\containment\RollbackHost.ps1 -Armed
```
