"""
Ransomware Attack Simulator for BRDS-PEC Demonstration.
Streams historical ransomware telemetry to the live dashboard.
"""

import argparse
import json
import time
import requests
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "processed" / "sysmon_attack_windows.csv"
API_URL = "http://127.0.0.1:5000/api/score/live"
API_KEY = "dev-hmac-key"

# Map source paths to friendly names for the CLI
FAMILY_MAP = {
    "atomic-t1059": str(ROOT / "data/datasets/splunk_attack_data/datasets/attack_techniques/T1059.001/atomic_red_team/windows-sysmon.log"),
    "atomic-t1105": str(ROOT / "data/datasets/splunk_attack_data/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon.log"),
    "atomic-t1490": str(ROOT / "data/datasets/splunk_attack_data/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log"),
    "ransomware-notes": str(ROOT / "data/datasets/splunk_attack_data/datasets/attack_techniques/T1490/ransomware_notes/windows-sysmon.log"),
    "dcrypt": str(ROOT / "data/datasets/splunk_attack_data/datasets/attack_techniques/T1486/dcrypt/windows-sysmon.log"),
    "samsam": str(ROOT / "data/datasets/splunk_attack_data/datasets/attack_techniques/T1486/sam_sam_note/windows-sysmon.log")
}

def main():
    parser = argparse.ArgumentParser(description="Simulate a ransomware attack on the live dashboard.")
    parser.add_argument("--family", type=str, choices=list(FAMILY_MAP.keys()), default="samsam",
                        help="The ransomware family trace to replay.")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Seconds to wait between sending each telemetry window.")
    args = parser.parse_args()

    if not DATA_PATH.exists():
        print(f"[!] Error: Attack dataset not found at {DATA_PATH}")
        return

    print(f"[*] Loading attack dataset...")
    df = pd.read_csv(DATA_PATH)
    
    source_path = FAMILY_MAP[args.family]
    # Use string contains to match the source robustly across OS paths
    attack_windows = df[df["source"].str.contains(Path(source_path).name, regex=False, na=False)].sort_values("window_start")
    
    if attack_windows.empty:
        # Fallback to checking the parent directory name if the file name alone is ambiguous
        parent_dir = Path(source_path).parent.name
        attack_windows = df[df["source"].str.contains(parent_dir, regex=False, na=False)].sort_values("window_start")

    if attack_windows.empty:
        print(f"[!] Error: No data found for family {args.family} using path {source_path}")
        return

    print(f"[*] Found {len(attack_windows)} telemetry windows for {args.family}.")
    print(f"[*] Beginning live simulation. Sending to {API_URL} every {args.delay} seconds...")
    print(f"[*] Open your dashboard at http://127.0.0.1:5000/ to watch the attack.\n")

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }

    feature_cols = [
        'event_count', 'unique_images', 'unique_files', 'unique_extensions', 
        'unique_destination_ips', 'suspicious_path_count', 'file_activity_count', 
        'registry_activity_count', 'network_activity_count', 'event_1_count', 
        'event_3_count', 'event_7_count', 'event_11_count', 'event_12_count', 
        'event_13_count', 'event_23_count', 'event_26_count'
    ]

    for idx, (_, row) in enumerate(attack_windows.iterrows(), 1):
        features = {col: int(row[col]) for col in feature_cols if col in row}
        
        # We override the historical timestamp with the current live time so the dashboard accepts it natively
        current_time = datetime.now(timezone.utc).isoformat()
        
        payload = {
            "computer": "BRDS-DEMO-VICTIM",
            "process_key": f"demo_ransomware.exe:666",
            "window_start": current_time,
            "label": 1,
            "technique_id": args.family,
            "scenario": args.family,
            "source": "live-simulator",
            "features": features
        }

        try:
            resp = requests.post(API_URL, json=payload, headers=headers)
            if resp.status_code == 200:
                result = resp.json()
                score = result.get("risk_score", 0.0)
                alert = "[ALERT CREATED]" if result.get("alert_created") else ""
                print(f"[{idx}/{len(attack_windows)}] Sent window -> Risk Score: {score:.4f} {alert}")
            else:
                print(f"[!] HTTP {resp.status_code}: {resp.text}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Connection failed: {e}. Is the backend running?")
            
        time.sleep(args.delay)
        
    print("\n[*] Simulation complete.")

if __name__ == "__main__":
    main()
