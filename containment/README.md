# Automated Containment Engine: Safety & Operational Guide

This directory contains the automated threat mitigation modules for the Behavioral Ransomware Detection System (BRDS-PEC). It outlines how network isolation and process tree termination scripts are triggered, and how to safely run them.

---

## Safety Mechanism: Dry-Run Mode vs. Live Containment

To prevent accidental host lockouts, remote session drops, or process crashes on developer machines, the containment engine implements a default **Dry-Run Mode**.

### 1. Dry-Run Mode (Default Safety)

By default, the environment variable `BRDS_DRY_RUN` is set to `1` (or undefined).

- **Behavior**: When a ransomware alert with a risk score $\ge 0.85$ is detected, the trigger daemon passes the `-DryRun` flag to both PowerShell scripts.
- **Result**: The scripts **log their intended actions** to the terminal and database without executing them:
  - _Network adapter_: Logs `"DRY RUN: Disabling adapter Ethernet0"` but does **not** disable it.
  - _Process tree_: Logs `"DRY RUN: Terminating process tree for PID 4820"` but does **not** kill it.
  - _Purpose_: Allows you to test the entire ingestion, scoring, and daemon pipeline safely on your local host without losing connection.

### 2. Live Containment Mode (Real Threat Isolation)

To arm the system for actual threat isolation (e.g., inside your sandbox VM), you must explicitly turn off dry-run safety:

```powershell
# Set environment variable to 0 in your terminal session
$env:BRDS_DRY_RUN = "0"

# Run the daemon
python containment/trigger_daemon.py
```

- **Behavior**: The daemon calls the PowerShell containment scripts without the `-DryRun` flag.
- **Result**: **Live execution takes place immediately**:
  - **Process Tree Collapse**: `kill_process_tree.ps1` runs WMI/CIM queries to terminate the ransomware binary and all child processes it spawned, halting encryption in progress.
  - **Host Isolation**: `ContainHost.ps1` runs `Disable-NetAdapter` to turn off all network adapters (Ethernet, Wi-Fi, virtual adapters), severing the network connection to block the ransomware from spreading laterally to servers or domain controllers.

---

## Directory Components

- **`ContainHost.ps1`**: The host isolation script. Identifies all active net adapters and disables them.
- **`kill_process_tree.ps1`**: The recursive process tree termination script. Traces child processes using parent PID relationships and terminates them bottom-up.
- **`trigger_daemon.py`**: The background monitoring daemon. Polls `dry_run_alerts.json` (or the database alerts table) every 1.5 seconds and triggers script executions.

---

> [!WARNING]
> Do **NOT** run the daemon with `$env:BRDS_DRY_RUN = "0"` on your host machine or via a remote SSH/RDP session, as disabling the network adapters will instantly disconnect your session. Only arm live containment inside the isolated Sandbox VM environment.
