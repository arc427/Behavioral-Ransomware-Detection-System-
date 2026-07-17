"""Isolation Forest inference helpers."""

from __future__ import annotations

import pandas as pd


def anomaly_scores(model, features: pd.DataFrame) -> pd.Series:
    """Return higher-is-more-suspicious scores from a fitted Isolation Forest pipeline."""
    return pd.Series(-model.decision_function(features), index=features.index, name="anomaly_score")
