# Threat Modeling & Security Risk Analysis Report

This report evaluates the **Behavioral Ransomware Detection System (BRDS-PEC)** against advanced evasion tactics, environment-aware malware, false positive triggers, and resource exhaustion vectors.

---

## 1. Evasion through 'Low and Slow' Techniques

### Threat Vector

If ransomware encrypts files at a very slow pace or uses non-standard I/O operations, it aims to fly below the behavioral activity spikes that trigger detection.

### System Response & Analysis

- **Temporal Window Limits**:
  - The system aggregates Sysmon logs into 5-second temporal windows. A "Low and Slow" ransomware variant that encrypts 1 file every 10 seconds will register a `file_activity_count` of 0 or 1 per window.
  - The **Baseline Isolation Forest** model will treat this as normal idle system behavior (which frequently performs sporadic background log writes).
- **LSTM Sequence Context**:
  - The **LSTM Sequence Engine** looks at a sliding context of 30 steps (150 seconds). While this captures temporal correlation better than single-window checks, an attacker who spreads encryption over hours (e.g., 1 file every 10 minutes) will easily slide out of the 150-second LSTM context window.
- **Detection Floor**:
  - The minimum activity threshold (Detection Floor) required to bypass the system is **fewer than 2 file modifications/deletions per 5-second window** combined with **standard file extension retention** (encrypting in-place without renaming extensions).
- **Non-Standard I/O Bypass**:
  - If the ransomware uses raw disk sector writes (e.g., calling `CreateFile` on `\\.\PhysicalDrive0`) or memory-mapped files (`CreateFileMapping`/`MapViewOfFile`), standard high-level Sysmon File Create/Delete events (Event IDs 11/23/26) may not trigger. Sysmon relies on file system mini-filter drivers; direct block device writes bypass these filters entirely.

---

## 2. Environment Awareness

### Threat Vector

Malware can inspect the system to identify if it is being monitored or analyzed, programmatically going dormant or disabling the agents.

### System Response & Analysis

- **Visibility of Hooks**:
  - The BRDS agent relies on the Microsoft **Sysmon** service and kernel driver (`SysmonDrv`), a Python ingestion script (`run_pipeline.py`), and a Python containment daemon (`trigger_daemon.py`).
- **Evasion Execution**:
  - An attacker with standard user or Administrator privileges can detect these indicators:
    - Querying loaded kernel drivers (`fltMC.exe` or checking for `SysmonDrv`).
    - Querying active services for `Sysmon`.
    - Scanning running processes for Python executors or files referencing `trigger_daemon`.
  - If detected, the ransomware can suspend its threads, delete its payload, or mimic harmless operations (e.g., writing dummy logs) until the monitoring tools are removed.
  - If the ransomware gains Administrator/SYSTEM privileges, it can directly terminate the Python processes or stop/disable the Sysmon service, blinding the detection system.

---

## 3. False Positive & False Negative Triggers

### Threat Vector

Legitimate, system-heavy processes that perform high-frequency file, registry, or network operations can mimic ransomware behavior, triggering accidental host isolation (Denial of Service).

### Mimicking Processes

- **Local Backups & File Synchronization (OneDrive, Dropbox, Google Drive)**:
  - Read thousands of files, write compressed/encrypted blocks, write temporary hidden files (e.g., `.tmp` or `.sync`), and delete the original files in bulk. This mimics ransomware entropy and extension-change ratios, crossing the `0.85` threshold.
- **System Updates (Windows Update)**:
  - Writes hundreds of files, modifies critical system registry keys, and deletes installer folders, causing spikes in `event_count`, `registry_activity_count`, and `suspicious_path_count` (e.g., `C:\Windows\SoftwareDistribution`).
- **Software Compilations & Database Indexing (Visual Studio, IntelliJ, MS SQL Server)**:
  - Spawns compiler child processes, writes thousands of temporary intermediate files (e.g., `.obj`, `.pdb`, `.class`), and indexes large text blocks, causing spikes in file activity counts.

### Mitigation Required for Production

- Implement strict **Sysmon XML configuration exclusions** to filter out trusted signed binaries (e.g., `onedrive.exe`, `MsMpEng.exe`).
- Add **process path whitelisting** in the python vectorizer to ignore trusted system-critical sign-offs.

---

## 4. Resource Exhaustion & Fail-Open Behavior

### Threat Vector

An attacker floods the system with high-entropy, high-volume benign operations (like copying thousands of compressed `.zip` files) to overwhelm the processor or log queues.

### System Response & Analysis

- **Fail-Open vs. Fail-Closed**:
  - The Python ingestion parser (`run_pipeline.py`) reads and aggregates logs sequentially.
  - **In processing queues**: Under a massive flood of logs, the Python script will lag behind the real-time event stream.
  - **Result**: The system **fails-open**. If the attacker detonates ransomware during a flood, the encryption may complete before the parser processes the backlog and calculates the $\ge 0.85$ risk score.
  - **In memory exhaustion**: If the Python buffer memory is overwhelmed, the script will crash (Out of Memory). Because the containment daemon relies on the API server to receive alert scores, a crashed parser stops the containment engine, allowing the ransomware to execute unchecked (Fail-Open).
- **Mitigation Required for Production**:
  - Implement a high-performance compiled parser (written in Go or Rust) rather than Python for real-time log ingestion.
  - Enforce **backpressure rate-limiting** on the Windows Event log buffer to drop excess logs or alert administrators when processing delay exceeds a safety threshold.
