"""Score windowed Sysmon telemetry and write dry-run alerts; never contains a host."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml_engine.risk_engine import RiskEngine


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Windowed CSV emitted by run_pipeline.py")
    parser.add_argument("--model", type=Path, default=ROOT / "data/models/baseline_models.joblib")
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed/dry_run_alerts.json")
    parser.add_argument("--threshold", type=float, default=0.85)
    args = parser.parse_args()
    scored = RiskEngine(args.model, threshold=args.threshold).score(pd.read_csv(args.input))
    alerts = scored[scored["would_alert"]].copy()
    fields = [field for field in ("timestamp", "window_start", "computer", "process_key", "source", "technique_id", "scenario", "risk_score", "anomaly_score", "would_alert", "mode") if field in alerts]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(alerts.loc[:, fields].to_json(orient="records", date_format="iso", indent=2), encoding="utf-8")
    print(f"Dry run: {len(alerts)} alerts written to {args.output}; no containment action was taken.")


if __name__ == "__main__":
    main()
