# Safe Sandbox VM Setup Guide for Ransomware Detonation

This guide details the steps required to set up an isolated Virtual Machine (VM) sandbox environment to safely detonate and analyze real ransomware samples (e.g., WannaCry, Ryuk, LockBit) using the **Behavioral Ransomware Detection System (BRDS-PEC)**.

> [!CAUTION]
> Ransomware is highly destructive malware. Running ransomware on a host machine will result in catastrophic data loss. You **MUST** perform all detonation testing inside an isolated, non-production virtual machine environment following this guide.

---

## 1. Hypervisor & Virtual Machine Selection

1. **Hypervisor**: Install a standard hypervisor like **VirtualBox** (Open Source) or **VMware Workstation Pro / Player**.
2. **Guest Operating System**: Set up a clean virtual machine running **Windows 10, 11**, or **Windows Server 2019/2022**.
3. **VM Snapshot Baseline**:
   - Before downloading or running any malware, update Windows and install the necessary dependencies (Python 3.10+, Git).
   - Shut down the VM and take a **Snapshot** named `Baseline_Clean`. This allows you to immediately revert the VM to a clean state after each ransomware detonation.

---

## 2. Hardened Network Isolation (Crucial)

Ransomware often scans local subnets to encrypt shared drives and spreads laterally using exploits (like EternalBlue) or brute-force credentials. To prevent this:

1. **Remove WAN/Internet Adapters**:
   - In the VM settings, disconnect or remove any adapters set to **NAT** or **Bridged**.
2. **Configure Host-Only Networking**:
   - Add a single network adapter set to **Host-Only Adapter** (VirtualBox) or **Host-only** (VMware).
   - Ensure the Host-Only network DHCP server is configured with a restricted subnet (e.g., `192.168.56.0/24`) and that routing/forwarding to the host's physical network card is disabled.
3. **Turn Off Shared Folders**:
   - Disable any Shared Folders between the guest VM and the host operating system.
   - Disable Clipboard sharing and Drag-and-Drop in the hypervisor settings.

---

## 3. Sysmon Log Collection Setup

The BRDS ML pipeline relies on Sysmon event logs to collect process, file, registry, and network telemetry.

1. **Download Sysmon**: Download Microsoft Sysinternals **System Monitor (Sysmon)** inside the VM.
2. **Install with BRDS Configuration**:
   - Open an Administrator PowerShell/Command Prompt.
   - Run the installation pointing to the BRDS configuration file:
     ```cmd
     sysmon.exe -i sysmon_config/sysmon_config.xml
     ```
   - This configuration includes rules specifically optimized to log file modifications, deletions, network connections, and process creations.

---

## 4. Install BRDS Agent & Dependencies

1. **Clone the Repository**: Clone the repository or copy the project files to the VM.
2. **Install Python Packages**:
   - Open PowerShell inside the project directory and run:
     ```powershell
     pip install -r requirements.txt
     ```
3. **Initialize the SQL Database**:
   - Set up the SQLite database schema by running:
     ```powershell
     python -m backend.db.init_db
     ```
4. **Pre-seed Telemetry & Baseline Models**:
   - Seed the database and train the baseline model:
     ```powershell
     python scripts/prepare_live_data.py
     ```

---

## 5. Starting the BRDS Services

To run the live detection system, start the following three components in separate terminal windows:

### A. Live Log Parser Ingestion Pipeline

Monitors the Sysmon Event Logs, extracts 1-second rolling behavioral feature counts, and appends them:

```powershell
python scripts/run_pipeline.py
```

### B. SOC Backend Web Server

Serves the REST API and provides telemetry/alerts to the dashboard:

```powershell
python -m backend.app
```

### C. Active Containment Daemon

Polls the database and triggers PowerShell containment adapters:

```powershell
# Set dry-run mode to 0 to enable live process-killing and network adapter disabling
$env:BRDS_DRY_RUN = "0"
python containment/trigger_daemon.py
```

---

## 6. Malware Detonation & Automated Response

1. **Launch the Dashboard**: Open `frontend/index.html` in a browser to monitor the live telemetry graphs and risk timeline.
2. **Detonate Ransomware**:
   - Transfer your target ransomware test binary (e.g., WannaCry) into the VM.
   - Run the binary as an Administrator.
3. **Observe Automated Mitigation**:
   - Within seconds, as the ransomware starts spawning processes and deleting files, the rolling features (like `file_activity_count` and `unique_extensions`) will spike.
   - The ML models will recalculate the risk score.
   - Once the risk score crosses the **Warning Threshold (0.60)**, an alert card is logged in the SOC panel.
   - Once it crosses the **Containment Threshold (0.85)**, the active containment engine:
     - Automatically calls `containment/kill_process_tree.ps1` to collapse the ransomware process tree and child processes.
     - Calls `containment/ContainHost.ps1` to disable all active network adapters, isolating the host.
4. **Revert VM**: After the analysis is complete, revert the VM to the `Baseline_Clean` snapshot before executing any further tests.
