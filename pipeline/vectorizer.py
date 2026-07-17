"""Model-ready feature selection for aggregated telemetry windows."""

from __future__ import annotations

import pandas as pd


IDENTIFIER_COLUMNS = frozenset({"computer", "process_key", "window_start", "label", "technique_id", "scenario", "source"})


def feature_columns(frame: pd.DataFrame) -> list[str]:
    """Return a stable list of numeric behavioral features."""
    return [column for column in frame.columns if column not in IDENTIFIER_COLUMNS and pd.api.types.is_numeric_dtype(frame[column])]


def vectorize(frame: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Return numeric features, safely filling missing values for model training."""
    columns = feature_columns(frame)
    return frame.loc[:, columns].fillna(0).astype(float), columns
