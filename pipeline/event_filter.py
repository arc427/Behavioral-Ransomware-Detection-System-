"""Selection and validation of telemetry events used by the model."""

from __future__ import annotations

from typing import Any, Iterable


SYSMON_EVENT_IDS = frozenset({1, 3, 7, 11, 12, 13, 23, 26})


def filter_sysmon_events(
    events: Iterable[dict[str, Any]], event_ids: frozenset[int] = SYSMON_EVENT_IDS
) -> list[dict[str, Any]]:
    """Keep supported Sysmon events with a timestamp and process identifier."""
    kept: list[dict[str, Any]] = []
    for event in events:
        try:
            event_id = int(event.get("event_id"))
        except (TypeError, ValueError):
            continue
        if event_id not in event_ids or not event.get("timestamp"):
            continue
        if not (event.get("process_guid") or event.get("process_id")):
            continue
        normalized = dict(event)
        normalized["event_id"] = event_id
        kept.append(normalized)
    return kept
