import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict
import datetime

class SILRADAdapter:
    """
    Adapter for the SILRAD dataset.
    Converts raw SILRAD CSV records into BRDS aggregated windows.
    """

    def __init__(self, dataset_path=None):
        if dataset_path is None:
            dataset_path = Path(__file__).resolve().parent.parent / "data" / "datasets" / "silrad" / "fasttext-all-nofamily.csv"
        self.dataset_path = Path(dataset_path)

    def load_raw_data(self):
        """Loads raw SILRAD CSV records."""
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"SILRAD dataset file not found at: {self.dataset_path}")

        df = pd.read_csv(self.dataset_path)
        return df

    def convert_events_to_windows(self, df=None, events_per_window=10):
        """
        Produce windows from the SILRAD Sysmon CSV.
        The dataset contains raw Sysmon fields like event.code, ProcessGuid, Image, TargetObject.
        """
        if df is None:
            df = self.load_raw_data()

        windows = []
        chunk_size = events_per_window
        total_rows = len(df)
        
        # We simulate window boundaries by chunking events sequentially per class
        # (Assuming the CSV is grouped by execution sequence)
        
        for i in range(0, total_rows, chunk_size):
            chunk = df.iloc[i : i + chunk_size]
            if len(chunk) == 0:
                continue

            # Determine window majority label
            label = int(chunk["class"].mode()[0]) if "class" in chunk.columns else 0

            # Extract event ID counts
            event_codes = chunk["event.code"].fillna(0).astype(int).values
            event_1_count = int(np.sum(event_codes == 1))
            event_3_count = int(np.sum(event_codes == 3))
            event_7_count = int(np.sum(event_codes == 7))
            event_11_count = int(np.sum(event_codes == 11))
            event_12_count = int(np.sum(event_codes == 12))
            event_13_count = int(np.sum(event_codes == 13))
            event_23_count = int(np.sum(event_codes == 23))
            event_26_count = int(np.sum(event_codes == 26))

            file_activity_count = event_11_count + event_23_count + event_26_count
            registry_activity_count = event_12_count + event_13_count
            network_activity_count = event_3_count

            # Extract features from textual fields
            images = chunk["Image"].dropna().astype(str).values if "Image" in chunk.columns else []
            targets = chunk["TargetObject"].dropna().astype(str).values if "TargetObject" in chunk.columns else []
            cmdlines = chunk["CommandLine"].dropna().astype(str).values if "CommandLine" in chunk.columns else []

            unique_images = len(np.unique(images)) if len(images) > 0 else 0
            unique_files = len(np.unique(targets)) if len(targets) > 0 else 0
            
            # Simple heuristic for extensions: grab last 4 chars if it has a dot
            exts = [t.split('.')[-1][:4].lower() for t in targets if '.' in t.split('\\')[-1]]
            unique_extensions = len(np.unique(exts)) if len(exts) > 0 else 0
            
            unique_destination_ips = len(np.unique(targets)) if network_activity_count > 0 else 0
            
            suspicious_path_count = 0
            suspicious_keywords = ["vssadmin", "wbemtest", "bcdedit", "wmic", "powershell", "cmd.exe /c"]
            for cmd in cmdlines:
                if any(kw in cmd.lower() for kw in suspicious_keywords):
                    suspicious_path_count += 1

            window_record = {
                "window_start": (pd.Timestamp("2026-08-06T00:00:00Z") + pd.Timedelta(seconds=i)).isoformat(),
                "computer": "WIN11-ENDPOINT-01",
                "process_key": f"PROC-SILRAD-{i // chunk_size:05d}",
                "event_count": len(chunk),
                "unique_images": unique_images,
                "unique_files": unique_files,
                "unique_extensions": unique_extensions,
                "unique_destination_ips": unique_destination_ips,
                "suspicious_path_count": suspicious_path_count,
                "file_activity_count": file_activity_count,
                "registry_activity_count": registry_activity_count,
                "network_activity_count": network_activity_count,
                "event_1_count": event_1_count,
                "event_3_count": event_3_count,
                "event_7_count": event_7_count,
                "event_11_count": event_11_count,
                "event_12_count": event_12_count,
                "event_13_count": event_13_count,
                "event_23_count": event_23_count,
                "event_26_count": event_26_count,
                "label": label,
                "scenario": "SILRAD_WINDOWS11_BENIGN" if label == 0 else "SILRAD_RANSOMWARE_ATTACK",
                "source": f"silrad_dataset_log_{((i // chunk_size) % 5) + 1}",
                "source_kind": "benign" if label == 0 else "attack",
                "dataset_source": "silrad",
                "representation": "raw_sysmon",
            }
            windows.append(window_record)

        return pd.DataFrame(windows)
