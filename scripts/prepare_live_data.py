import pandas as pd
import numpy as np
import subprocess
from pathlib import Path

import sys

# Paths
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
    
processed_dir = ROOT / "data/processed"
models_dir = ROOT / "data/models"

attack_path = processed_dir / "sysmon_attack_windows.csv"
combined_path = processed_dir / "sysmon_combined_windows.csv"
telemetry_output_path = processed_dir / "sysmon_windows.csv"
alerts_output_path = processed_dir / "dry_run_alerts.json"

print("Preparing live data...")

if not attack_path.exists():
    raise FileNotFoundError(f"Missing base attack dataset at {attack_path}")

# 1. Read attack windows
df_attack = pd.read_csv(attack_path)
n_attack = len(df_attack)
print(f"Loaded {n_attack} attack windows.")

# 2. Synthesize Benign Windows (label 0)
# We will create 2000 benign windows. Benign system traffic has very low activity rates.
n_benign = 2000
rng = np.random.default_rng(42)

# Get feature columns (all columns that are not administrative metadata)
meta_cols = ['computer', 'process_key', 'window_start', 'label', 'technique_id', 'scenario', 'source']
feature_cols = [c for c in df_attack.columns if c not in meta_cols]

benign_rows = []
system_processes = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Program Files\Windows Defender\MsMpEng.exe",
    r"C:\Windows\System32\cmd.exe"
]

start_time = pd.Timestamp("2026-07-19T00:00:00Z")

for i in range(n_benign):
    # Base metadata
    proc = rng.choice(system_processes)
    timestamp = start_time + pd.Timedelta(seconds=i*5) # 5-second steps
    
    row = {
        'computer': 'BRDS-WIN11-SEC',
        'process_key': f"{proc}:{rng.integers(1000, 9000)}",
        'window_start': timestamp.isoformat(),
        'label': 0,
        'technique_id': 'benign',
        'scenario': 'benign',
        'source': fr"C:\Windows\System32\benign-logs-{(i % 3) + 1}"
    }
    
    # Add features: low counts for benign activity
    for col in feature_cols:
        if col == 'event_count':
            row[col] = rng.integers(1, 6) # 1-5 events per window
        elif col in ('unique_images', 'unique_files'):
            row[col] = rng.choice([0, 1])
        elif col in ('event_7_count', 'event_12_count'):
            # Image load / registry activity is common in normal system
            row[col] = rng.choice([0, 1, 2])
        elif col in ('file_activity_count', 'registry_activity_count'):
            row[col] = rng.choice([0, 1, 2])
        else:
            # Most features like shadow copy deletion (event 1/23/26) or network are 0
            row[col] = 0
            
    benign_rows.append(row)

df_benign = pd.DataFrame(benign_rows)
print(f"Generated {n_benign} synthetic benign windows.")

# 3. Combine attack and benign windows
df_combined = pd.concat([df_attack, df_benign], ignore_index=True)
df_combined.to_csv(combined_path, index=False)
print(f"Saved combined dataset ({len(df_combined)} rows) to {combined_path}")

# 4. Train the baseline model using scripts/train_baseline.py
print("\nTraining baseline model with combined dataset...")
train_cmd = [
    "python", 
    str(ROOT / "scripts/train_baseline.py"), 
    "--input", str(combined_path),
    "--model-output", str(models_dir / "baseline_models.joblib"),
    "--report-output", str(models_dir / "baseline_report.json")
]
subprocess.run(train_cmd, check=True)
print("Model training complete.")

# 5. Score the windows to generate live telemetry and alerts
print("\nScoring telemetry windows...")
score_cmd = [
    "python",
    str(ROOT / "scripts/score_windows.py"),
    "--input", str(combined_path),
    "--model", str(models_dir / "baseline_models.joblib"),
    "--output", str(alerts_output_path)
]
subprocess.run(score_cmd, check=True)
print("Scoring complete. Alerts written to dry_run_alerts.json.")

# Copy the scored combined dataset with risk scores to data/processed/sysmon_windows.csv
# This mimics the live telemetry database table
from ml_engine.risk_engine import RiskEngine
scored_df = RiskEngine(models_dir / "baseline_models.joblib").score(df_combined)
scored_df.to_csv(telemetry_output_path, index=False)
print(f"Wrote scored telemetry dataset to {telemetry_output_path}")

# 6. Populate SQLite database
print("\nPopulating SQLite database tables...")
import json
from backend.app import create_app
from backend.models import db
from backend.models.incidents import Incident
from backend.models.feature_vectors import FeatureVector
from pipeline.vectorizer import feature_columns

app = create_app()
with app.app_context():
    # 6a. Populate telemetry feature vectors
    print("Clearing old telemetry feature vectors from SQL...")
    FeatureVector.query.delete()
    
    features = feature_columns(scored_df)
    
    print("Inserting feature vectors into database...")
    db_vectors = []
    for _, row in scored_df.iterrows():
        feat_dict = {f: float(row[f]) for f in features if pd.notna(row[f])}
        vec = FeatureVector(
            computer=str(row['computer']),
            process_key=str(row['process_key']),
            window_start=str(row['window_start']),
            label=int(row['label']),
            technique_id=str(row['technique_id']),
            scenario=str(row['scenario']),
            source=str(row['source']),
            risk_score=float(row['risk_score']) if pd.notna(row['risk_score']) else None,
            anomaly_score=float(row['anomaly_score']) if pd.notna(row['anomaly_score']) else None,
            features_json=json.dumps(feat_dict)
        )
        db_vectors.append(vec)
        
    db.session.bulk_save_objects(db_vectors)
    
    # 6b. Populate incidents alerts
    print("Clearing old incidents from SQL...")
    Incident.query.delete()
    
    if alerts_output_path.exists():
        print("Inserting incidents into database...")
        with open(alerts_output_path, "r", encoding="utf-8") as f:
            alerts = json.load(f)
            
        db_incidents = []
        for item in alerts:
            inc = Incident(
                timestamp=str(item.get("timestamp") or item.get("window_start")),
                computer=str(item.get("computer", "BRDS-WIN11-SEC")),
                ransomware_family=str(item.get("technique_id", "Ransomware")),
                risk_score=float(item.get("risk_score", 0.0)),
                process_id=int(str(item.get("process_key", "")).split(":")[-1]) if ":" in str(item.get("process_key", "")) and str(item.get("process_key", "")).split(":")[-1].isdigit() else 9999,
                status="ACTIVE"
            )
            db_incidents.append(inc)
            
        db.session.bulk_save_objects(db_incidents)
        
    db.session.commit()
    print("SQLite database population complete!")

print("Live data preparation successful!")
