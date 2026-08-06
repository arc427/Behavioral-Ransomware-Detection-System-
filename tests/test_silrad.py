import unittest
import pandas as pd
from pathlib import Path
from pipeline.silrad_adapter import SILRADAdapter

class TestSILRADAdapter(unittest.TestCase):

    def setUp(self):
        self.dataset_path = Path(__file__).resolve().parents[1] / "data" / "datasets" / "silrad" / "fasttext-all-nofamily.csv"
        self.adapter = SILRADAdapter(self.dataset_path)

    def test_dataset_exists(self):
        self.assertTrue(self.dataset_path.exists(), f"SILRAD dataset file not found at {self.dataset_path}")

    def test_load_raw_data(self):
        df_raw = self.adapter.load_raw_data()
        self.assertGreater(len(df_raw), 0)
        self.assertIn("class", df_raw.columns)
        self.assertIn("event.code", df_raw.columns)

    def test_convert_events_to_windows(self):
        df_raw = self.adapter.load_raw_data()
        df_windows = self.adapter.convert_events_to_windows(df_raw.head(200), events_per_window=10)
        self.assertGreater(len(df_windows), 0)
        self.assertIn("event_count", df_windows.columns)
        self.assertIn("file_activity_count", df_windows.columns)
        self.assertIn("registry_activity_count", df_windows.columns)
        self.assertIn("network_activity_count", df_windows.columns)
        self.assertIn("label", df_windows.columns)
        self.assertTrue((df_windows["representation"] == "raw_sysmon").all())

if __name__ == "__main__":
    unittest.main()
