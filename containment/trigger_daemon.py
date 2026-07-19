import time
import json
import subprocess
import os
import sys
import argparse
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_ALERTS_PATH = ROOT / "data/processed/dry_run_alerts.json"
CONTAIN_HOST_SCRIPT = Path(__file__).parent / "ContainHost.ps1"
KILL_PROCESS_SCRIPT = Path(__file__).parent / "kill_process_tree.ps1"

def run_powershell(script_path: Path, args: list[str]) -> str:
    """Execute a PowerShell containment script and capture output."""
    cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(script_path)] + args
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        return f"Error executing script: {e.stderr}\nOutput: {e.stdout}"

def poll_alerts(alerts_path: Path, processed_alerts: set[str]) -> None:
    """Read the alerts file and execute containment actions for new high-risk alerts."""
    if not alerts_path.exists():
        return
        
    try:
        with open(alerts_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if content:
                alerts = json.loads(content)
            else:
                alerts = []
    except Exception as e:
        print(f"Error reading or parsing alerts: {e}")
        return
        
    for alert in alerts:
        # Construct a unique key for the alert to prevent duplicate containment triggers
        alert_id = alert.get("window_start") or alert.get("timestamp")
        if not alert_id or alert_id in processed_alerts:
            continue
            
        risk_score = float(alert.get("risk_score", 0.0))
        if risk_score >= 0.85:
            print(f"\n[ALERT DETECTED] ID: {alert_id} | Risk: {risk_score:.2f}")
            
            # Extract target process ID from process_key metadata e.g. "wannacry.exe:4920"
            proc_key = alert.get("process_key", "")
            pid = None
            if ":" in proc_key:
                try:
                    pid = int(proc_key.split(":")[-1])
                except ValueError:
                    pass
            
            # Execute malicious process termination
            if pid:
                print(f"[CONTAINMENT] Invoking process tree collapse script for PID: {pid}...")
                proc_output = run_powershell(KILL_PROCESS_SCRIPT, ["-ParentPid", str(pid)])
                print(proc_output.strip())
            else:
                print("[WARN] Alert has no valid process ID associated. Skipping process termination.")
            
            # Execute host isolation
            print("[CONTAINMENT] Invoking host network isolation script...")
            net_output = run_powershell(CONTAIN_HOST_SCRIPT, [])
            print(net_output.strip())
            
        processed_alerts.add(alert_id)

def main() -> None:
    parser = argparse.ArgumentParser(description="BRDS-PEC Automated Containment Daemon")
    parser.add_argument("--alerts-path", type=Path, default=DEFAULT_ALERTS_PATH, help="Path to dry_run_alerts.json file")
    parser.add_argument("--interval", type=float, default=1.5, help="Polling interval in seconds")
    parser.add_argument("--one-shot", action="store_true", help="Run once and exit (for verification/testing)")
    args = parser.parse_args()
    
    print("[BRDS-PEC] Containment Trigger Daemon initialized.")
    print(f"Alert database location: {args.alerts_path}")
    
    # Establish baseline to ignore pre-existing alerts on startup
    processed_alerts = set()
    if args.alerts_path.exists():
        try:
            with open(args.alerts_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    alerts = json.loads(content)
                    for alert in alerts:
                        alert_id = alert.get("window_start") or alert.get("timestamp")
                        if alert_id:
                            processed_alerts.add(alert_id)
        except Exception as e:
            print(f"Error parsing baseline alerts: {e}")
            
    print(f"Ignored {len(processed_alerts)} historical alerts. Ready to intercept active threats.")
    
    # Enable dry-run mode environment variable if not explicitly armed to 0
    if os.environ.get("BRDS_DRY_RUN") != "0":
        os.environ["BRDS_DRY_RUN"] = "1"
        print("[SAFETY] BRDS_DRY_RUN = 1 (Dry-Run Enabled). Host network adapter and processes will not be disrupted.")
    else:
        print("[WARNING] BRDS_DRY_RUN = 0 (Armed). Host isolation and process termination are fully active!")
        
    if args.one_shot:
        poll_alerts(args.alerts_path, processed_alerts)
        print("[BRDS-PEC] One-shot polling run finished.")
        return
        
    try:
        while True:
            poll_alerts(args.alerts_path, processed_alerts)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[BRDS-PEC] Containment Trigger Daemon shut down.")

if __name__ == "__main__":
    main()
