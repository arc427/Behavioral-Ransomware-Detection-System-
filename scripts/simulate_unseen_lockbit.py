"""
Zero-Day Ransomware Simulator (Unseen Family: LockBit)
Generates purely synthetic behavioral telemetry modeling a LockBit infection 
and streams it live to the dashboard API. 

This family was NOT in the training dataset.
"""

import time
import requests
from datetime import datetime, timezone

API_URL = "http://127.0.0.1:5000/api/score/live"
API_KEY = "dev-hmac-key"

def generate_lockbit_trace():
    """Generates 30 synthetic windows (2.5 minutes of telemetry) mimicking LockBit."""
    trace = []
    
    # Base feature template (all zeros)
    def base_features():
        return {
            'event_count': 0, 'unique_images': 1, 'unique_files': 0, 'unique_extensions': 0, 
            'unique_destination_ips': 0, 'suspicious_path_count': 0, 'file_activity_count': 0, 
            'registry_activity_count': 0, 'network_activity_count': 0, 'event_1_count': 0, 
            'event_3_count': 0, 'event_7_count': 0, 'event_11_count': 0, 'event_12_count': 0, 
            'event_13_count': 0, 'event_23_count': 0, 'event_26_count': 0
        }

    # Window 1-2: Initial payload execution and discovery (Quiet)
    for _ in range(2):
        f = base_features()
        f['event_count'] = 4
        f['event_1_count'] = 1  # Process creations
        trace.append(f)
        
    # Window 3: Shadow copy deletion (vssadmin.exe / wmic.exe)
    f = base_features()
    f['event_count'] = 12
    f['event_1_count'] = 2
    f['registry_activity_count'] = 2
    f['event_13_count'] = 2
    f['suspicious_path_count'] = 1
    trace.append(f)
    
    # Window 4-5: Service stopping (net stop / sc stop)
    for _ in range(2):
        f = base_features()
        f['event_count'] = 25
        f['event_1_count'] = 10
        trace.append(f)
        
    # Window 6-30: Massive file encryption phase (Renaming/Overwriting)
    # LockBit encrypts incredibly fast and drops a .lockbit extension.
    for i in range(25):
        f = base_features()
        f['event_count'] = 6 + (i % 3)
        f['file_activity_count'] = 4 + (i % 3)
        f['unique_files'] = 4
        f['unique_extensions'] = 2  # The original extension + .lockbit
        f['event_11_count'] = 2   # File creations (ransom notes + encrypted files)
        f['event_23_count'] = 2   # File deletions (removing the original unencrypted files)
        trace.append(f)
        
    return trace

def main():
    print("[*] Generating synthetic zero-day trace for unseen family: LockBit")
    trace = generate_lockbit_trace()
    
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }

    print(f"[*] Beginning live simulation. Sending to {API_URL} every 2 seconds...")
    print(f"[*] Open your dashboard at http://127.0.0.1:5000/ to watch the zero-day attack.\n")

    for idx, features in enumerate(trace, 1):
        current_time = datetime.now(timezone.utc).isoformat()
        
        payload = {
            "computer": "BRDS-DEMO-VICTIM",
            "process_key": f"LB3_decryptor.exe:1337",
            "window_start": current_time,
            "label": 1,
            "technique_id": "synthetic_lockbit",
            "scenario": "lockbit",
            "source": "synthetic-zero-day",
            "features": features
        }

        try:
            resp = requests.post(API_URL, json=payload, headers=headers)
            if resp.status_code == 200:
                result = resp.json()
                score = result.get("risk_score", 0.0)
                alert = "[ALERT CREATED]" if result.get("alert_created") else ""
                print(f"[{idx}/{len(trace)}] Sent Window -> Risk Score: {score:.4f} {alert}")
            else:
                print(f"[!] HTTP {resp.status_code}: {resp.text}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Connection failed: {e}. Is the backend running?")
            
        time.sleep(2.0)
        
    print("\n[*] Simulation complete.")

if __name__ == "__main__":
    main()
