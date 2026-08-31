# BRDS-PEC: Live Production Pipeline & Active Containment Guide

This document provides complete, step-by-step instructions for running the **BRDS-PEC** system in **Live Production Mode** (Active Host Containment Enabled, Non-Dry-Run) using Microsoft Sysmon ETW telemetry.

> [!CAUTION]
> **Active Host Containment Warning:**
> Running in **ARMED (Non-Dry-Run)** mode allows the system to **physically disable network adapters** and **terminate malicious process trees** when a threat score reaches $\ge 0.85$. Ensure this is executed inside a Virtual Machine (VMware / VirtualBox) or isolated testbed!

---

## Prerequisites

1. **Operating System:** Windows 10/11 (Virtual Machine recommended).
2. **Python:** Python 3.10+ installed and added to system `PATH`.
3. **Microsoft Sysmon:** Sysmon v15+ installed on the Windows host.
   * Verify Sysmon installation:
     ```powershell
     sysmon.exe -s
     ```
   * Install Sysmon with custom config if not installed:
     ```powershell
     sysmon.exe -i sysmon_config.xml
     ```

---

## Step-by-Step Live Execution (4-Terminal Pipeline)

To run the complete end-to-end pipeline in **Live Armed Mode**, launch the following 4 terminal processes in order:

---

### Terminal 1: AI Backend REST API Server
Starts the Flask server hosting the PyTorch BiLSTM neural network, Isolation Forest models, SQLite database, and REST APIs.

```powershell
cd C:\Users\hp\Behavioral-Ransomware-Detection-System-
$env:BRDS_ALLOW_INSECURE_DEV_HMAC="1"
$env:PYTHONPATH="C:\Users\hp\Behavioral-Ransomware-Detection-System-"
python backend/app.py
```
*Expected Output:* Server initializes models and starts listening on `http://127.0.0.1:5000`.

---

### Terminal 2: Containment Trigger Daemon (**ARMED MODE / Non-Dry-Run**)
Monitors signed alert logs (`dry_run_alerts.json`), verifies HMAC-SHA256 digests and `.arm_token` authorization, and executes **physical host containment** when risk score $\ge 0.85$.

```powershell
cd C:\Users\hp\Behavioral-Ransomware-Detection-System-
$env:PYTHONPATH="C:\Users\hp\Behavioral-Ransomware-Detection-System-"
python containment/trigger_daemon.py --armed --interval 1.0
```
*Expected Output:*
```
[WARNING] Valid HMAC signed .arm_token verified! Mode: ARMED (Host isolation active!).
[*] Polling alerts every 1.0s...
```

> [!NOTE]
> Passing the `--armed` flag automatically generates a cryptographically signed `.arm_token` file in `containment/` and instructs the daemon to execute `ContainHost.ps1` and `kill_process_tree.ps1` with the `-Armed` switch.

---

### Terminal 3: Live Sysmon Kernel Event Watchdog Sensor
Hooks into the Windows Event Log (`Microsoft-Windows-Sysmon/Operational.evtx`), aggregates raw events into 5-second sliding windows via `pipeline/temporal_aggregator.py`, and streams feature vectors to the live API.

```powershell
cd C:\Users\hp\Behavioral-Ransomware-Detection-System-
$env:BRDS_API_KEY="dev-hmac-key"
$env:PYTHONPATH="C:\Users\hp\Behavioral-Ransomware-Detection-System-"
python pipeline/watchdog.py
```
*Expected Output:*
```
[*] Sysmon Watchdog initialized. Monitoring ETW / Event Logs...
[*] Streaming feature vectors to http://127.0.0.1:5000/api/score/live
```

---

### Step 4: Open SOC Dashboard
Open File Explorer, navigate to `frontend/`, and double-click `index.html` (or open `http://127.0.0.1:5000` in Google Chrome / Microsoft Edge).

---

### Terminal 4: Execute Zero-Day Attack Telemetry Stream
In a fourth terminal, launch the zero-day LockBit ransomware simulator (or execute a benign file-renaming PoC script inside a dummy folder):

```powershell
cd C:\Users\hp\Behavioral-Ransomware-Detection-System-
$env:PYTHONPATH="C:\Users\hp\Behavioral-Ransomware-Detection-System-"
python scripts/simulate_unseen_lockbit.py
```

---

## What Happens During Active Host Containment ($\text{Risk} \ge 0.85$)

When the threat score reaches **0.9992** at Window 6 (~6 seconds into execution):

1. **Network Adapter Disabled:** `ContainHost.ps1 -Armed` executes `Disable-NetAdapter -Name * -Confirm:$false`, physically disconnecting the machine's network interface cards.
2. **Process Tree Terminated:** `kill_process_tree.ps1 -Armed` recursively terminates the malicious process tree (`Stop-Process -Id $PID -Force`).
3. **Safety Protection:** Enforces `$PROTECTED_PROCESSES` denylist (`lsass.exe`, `csrss.exe`, `svchost.exe`) to prevent OS crash (BSOD).
4. **Dashboard Update:** The UI header turns crimson (`Host Isolated (Auto Containment)`), a toast notification slides in, and the incident status transitions to **CONTAINED (AUTO)**.

---

## Restoring the System After Containment

To restore host networking after an armed containment test:

```powershell
# Re-enable network adapters
Enable-NetAdapter -Name * -Confirm:$false

# Reset Windows Firewall rules
netsh advfirewall reset
```
