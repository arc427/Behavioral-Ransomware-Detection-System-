"""Score windowed Sysmon telemetry via Isolation Forest → LSTM; write dry-run alerts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import config
from ml_engine.two_stage_pipeline import TwoStageInferencePipeline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Windowed CSV emitted by run_pipeline.py")
    parser.add_argument("--model", type=Path, default=ROOT / "data/models/baseline_models.joblib")
    parser.add_argument("--lstm-model", type=Path, default=config.LSTM_MODEL_PATH)
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed/dry_run_alerts.json")
    parser.add_argument("--threshold", type=float, default=0.85, help="LSTM alert threshold (Tier 2)")
    args = parser.parse_args()

    pipeline = TwoStageInferencePipeline(
        args.model,
        lstm_model_path=args.lstm_model,
        lstm_alert_threshold=args.threshold,
    )
    scored = pipeline.score_dataframe(pd.read_csv(args.input))
    alerts = scored[scored["would_alert"]].copy()
    fields = [
        field
        for field in (
            "timestamp",
            "window_start",
            "computer",
            "process_key",
            "source",
            "technique_id",
            "scenario",
            "anomaly_score",
            "isolation_forest_anomalous",
            "isolation_forest_decision",
            "lstm_invoked",
            "lstm_score",
            "lstm_decision",
            "risk_score",
            "would_alert",
            "mode",
        )
        if field in alerts
    ]
    from containment.alert_integrity import sign_alerts

    alert_records = alerts.loc[:, fields].to_dict(orient="records")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(sign_alerts(alert_records), encoding="utf-8")
    print(f"Dry run: {len(alerts)} alerts written to {args.output}; no containment action was taken.")


if __name__ == "__main__":
    main()
