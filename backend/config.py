"""Runtime paths and safe defaults for the read-only dashboard API."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "data" / "models"
ALERTS_PATH = PROCESSED_DIR / "dry_run_alerts.json"
TELEMETRY_PATH = PROCESSED_DIR / "sysmon_windows.csv"
MODEL_PATH = MODEL_DIR / "baseline_models.joblib"
REPORT_PATH = MODEL_DIR / "baseline_report.json"
MAX_PAGE_SIZE = 1_000
