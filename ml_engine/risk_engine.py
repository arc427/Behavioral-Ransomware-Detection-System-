"""Dry-run model scoring; containment remains deliberately outside this module."""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd


class RiskEngine:
    def __init__(self, model_path: str | Path, threshold: float = 0.85):
        self.artifacts = joblib.load(model_path)
        self.threshold = threshold

    def score(self, windows: pd.DataFrame) -> pd.DataFrame:
        names = self.artifacts["feature_names"]
        features = windows.reindex(columns=names, fill_value=0).fillna(0)
        probability = self.artifacts["supervised_model"].predict_proba(features)[:, 1]
        anomaly = -self.artifacts["isolation_forest"].decision_function(features)
        result = windows.copy()
        result["risk_score"] = probability
        result["anomaly_score"] = anomaly
        result["would_alert"] = probability >= self.threshold
        result["mode"] = "dry_run"
        return result
