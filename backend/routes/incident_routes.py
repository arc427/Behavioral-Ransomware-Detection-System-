"""Read-only dry-run alert endpoints. No endpoint can trigger containment."""

from __future__ import annotations

import json
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from .telemetry_routes import _page_args


incident_bp = Blueprint("incidents", __name__)


def _alerts() -> list[dict]:
    path = Path(current_app.config["ALERTS_PATH"])
    if not path.exists():
        return []
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return content if isinstance(content, list) else []


@incident_bp.get("/api/alerts")
@incident_bp.get("/api/incidents")
def alerts():
    items = _alerts()
    for name in ("host", "technique", "scenario"):
        value = request.args.get(name)
        field = {"host": "computer", "technique": "technique_id", "scenario": "scenario"}[name]
        if value:
            items = [item for item in items if value.lower() in str(item.get(field, "")).lower()]
    try:
        minimum_risk = float(request.args.get("min_risk", 0))
    except ValueError:
        minimum_risk = 0
    items = [item for item in items if float(item.get("risk_score", 0)) >= minimum_risk]
    items.sort(key=lambda item: item.get("risk_score", 0), reverse=True)
    limit, offset = _page_args()
    return jsonify({"items": items[offset : offset + limit], "total": len(items), "limit": limit, "offset": offset, "mode": "dry_run"})
