"""Read-only telemetry endpoints for the SOC dashboard."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from flask import Blueprint, current_app, jsonify, request


telemetry_bp = Blueprint("telemetry", __name__)


def _page_args() -> tuple[int, int]:
    try:
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return 100, 0
    return max(1, min(limit, current_app.config["MAX_PAGE_SIZE"])), max(0, offset)


@telemetry_bp.get("/api/telemetry")
def telemetry():
    path = Path(current_app.config["TELEMETRY_PATH"])
    if not path.exists():
        return jsonify({"items": [], "total": 0, "message": "No windowed telemetry dataset is available."})
    frame = pd.read_csv(path)
    for query_name, column in (("host", "computer"), ("technique", "technique_id"), ("source", "source")):
        value = request.args.get(query_name)
        if value and column in frame:
            frame = frame[frame[column].astype(str).str.contains(value, case=False, na=False)]
    limit, offset = _page_args()
    page = frame.iloc[offset : offset + limit].where(pd.notna(frame), None)
    return jsonify({"items": page.to_dict(orient="records"), "total": len(frame), "limit": limit, "offset": offset})
