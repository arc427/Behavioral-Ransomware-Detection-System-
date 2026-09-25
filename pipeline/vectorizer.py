"""Model-ready feature selection for aggregated telemetry windows."""

from __future__ import annotations

import pandas as pd


IDENTIFIER_COLUMNS = frozenset({
    "computer", "process_key", "window_start", "label", "technique_id", "scenario",
    "source", "source_kind", "dataset_source", "representation",
})

CANONICAL_FEATURE_NAMES: tuple[str, ...] = (
    "event_count",
    "unique_images",
    "unique_files",
    "unique_extensions",
    "unique_destination_ips",
    "suspicious_path_count",
    "file_activity_count",
    "registry_activity_count",
    "network_activity_count",
    "event_1_count",
    "event_3_count",
    "event_7_count",
    "event_11_count",
    "event_12_count",
    "event_13_count",
    "event_23_count",
    "event_26_count",
)


def validate_feature_schema(columns: list[str] | tuple[str, ...] | set[str] | frozenset[str], strict: bool = False) -> list[str]:
    """Check whether a column collection covers canonical behavioral features.
    
    Returns list of missing canonical feature names. If strict=True, raises ValueError on missing features.
    """
    col_set = set(columns)
    missing = [c for c in CANONICAL_FEATURE_NAMES if c not in col_set]
    if missing and strict:
        raise ValueError(f"Schema validation failed: missing canonical features: {missing}")
    return missing


def feature_columns(frame: pd.DataFrame) -> list[str]:
    """Return a stable list of numeric behavioral features."""
    return [column for column in frame.columns if column not in IDENTIFIER_COLUMNS and pd.api.types.is_numeric_dtype(frame[column])]


def vectorize(frame: pd.DataFrame, strict: bool = False) -> tuple[pd.DataFrame, list[str]]:
    """Return numeric features, safely validating and filling missing values for model training."""
    columns = feature_columns(frame)
    validate_feature_schema(columns, strict=strict)
    return frame.loc[:, columns].fillna(0).astype(float), columns

