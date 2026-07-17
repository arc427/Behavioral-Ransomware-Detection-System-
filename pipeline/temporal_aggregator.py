"""Turn timestamped Sysmon events into per-process behavioral windows."""

from __future__ import annotations

from typing import Any

import pandas as pd

from .flatten_encode import file_extension, is_suspicious_path


EVENT_FEATURES = (1, 3, 7, 11, 12, 13, 23, 26)


def aggregate_process_windows(events: list[dict[str, Any]], window_seconds: int = 5) -> pd.DataFrame:
    """Aggregate events by computer, process and fixed UTC time window."""
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if not events:
        return pd.DataFrame()

    frame = pd.DataFrame(events).copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["timestamp"])
    if frame.empty:
        return pd.DataFrame()
    for column in ("computer", "process_guid", "process_id", "image", "target_filename", "target_object", "destination_ip"):
        if column not in frame:
            frame[column] = ""
        frame[column] = frame[column].fillna("").astype(str)
    frame["process_key"] = frame["process_guid"]
    # Some Sysmon records use an all-zero GUID when no process correlation exists.
    # Treat it like a missing key rather than combining unrelated processes.
    missing_guid = frame["process_key"].isin({"", "{00000000-0000-0000-0000-000000000000}"})
    frame.loc[missing_guid, "process_key"] = (
        frame["process_id"] + ":" + frame["image"]
    )
    frame["window_start"] = frame["timestamp"].dt.floor(f"{window_seconds}s")
    frame["is_suspicious_path"] = frame["target_filename"].map(is_suspicious_path)
    frame["extension"] = frame["target_filename"].map(file_extension)
    group_columns = ["computer", "process_key", "window_start"]
    rows: list[dict[str, Any]] = []
    for key, group in frame.groupby(group_columns, dropna=False, sort=True):
        row: dict[str, Any] = dict(zip(group_columns, key))
        row["event_count"] = len(group)
        row["unique_images"] = group["image"].nunique()
        row["unique_files"] = group["target_filename"].replace("", pd.NA).nunique()
        row["unique_extensions"] = group["extension"].replace("", pd.NA).nunique()
        row["unique_destination_ips"] = group["destination_ip"].replace("", pd.NA).nunique()
        row["suspicious_path_count"] = int(group["is_suspicious_path"].sum())
        row["file_activity_count"] = int(group["event_id"].isin([11, 23, 26]).sum())
        row["registry_activity_count"] = int(group["event_id"].isin([12, 13]).sum())
        row["network_activity_count"] = int((group["event_id"] == 3).sum())
        for event_id in EVENT_FEATURES:
            row[f"event_{event_id}_count"] = int((group["event_id"] == event_id).sum())
        rows.append(row)
    return pd.DataFrame(rows).sort_values(group_columns).reset_index(drop=True)
