"""Runtime paths and safe defaults for the read-only dashboard API."""

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "data" / "models"
ALERTS_PATH = PROCESSED_DIR / "dry_run_alerts.json"
TELEMETRY_PATH = PROCESSED_DIR / "sysmon_windows.csv"
MODEL_PATH = MODEL_DIR / "baseline_models.joblib"
REPORT_PATH = MODEL_DIR / "baseline_report.json"
MAX_PAGE_SIZE = 1_000
DATABASE_PATH = PROJECT_ROOT / "data" / "brds.db"
SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATABASE_PATH}"
LSTM_MODEL_PATH = MODEL_DIR / "lstm_model.pth"

# Tier-1 Isolation Forest continuous screening threshold.
# PROVISIONAL CALIBRATION CANDIDATE — NOT a validated production threshold.
# Derived from sensitivity analysis on the held-out test split.
# The current VM validation candidate is -0.188196 (set via BRDS_IF_SCREENING_THRESHOLD).
# Calibrate on target environment data before production deployment.
DEFAULT_IF_SCREENING_THRESHOLD = -0.167461
IF_SCREENING_THRESHOLD = float(
    os.environ.get("BRDS_IF_SCREENING_THRESHOLD")
    or os.environ.get("IF_SCREENING_THRESHOLD")
    or DEFAULT_IF_SCREENING_THRESHOLD
)
