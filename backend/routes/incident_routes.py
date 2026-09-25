"""Read-only dry-run alert and pipeline decision audit endpoints."""

from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy.exc import OperationalError

from backend.models.incidents import Incident
from containment.alert_integrity import verify_and_load
from .telemetry_routes import _page_args, _safe_like

incident_bp = Blueprint("incidents", __name__)


def _alerts() -> list[dict]:
    path = Path(current_app.config["ALERTS_PATH"])
    if not path.exists():
        return []
    try:
        return verify_and_load(path)
    except Exception:
        return []


@incident_bp.get("/api/alerts")
@incident_bp.get("/api/incidents")
def alerts():
    use_offline = (os.environ.get("BRDS_USE_OFFLINE_BENCHMARK") == "1")

    db_available = False
    total = 0
    try:
        query = Incident.query
        total = query.count()
        db_available = True
    except OperationalError:
        pass

    if use_offline or (not db_available):
        # OFFLINE MODE: Read from historical JSON alert file
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
        total = len(items)
        items = items[offset : offset + limit]
    else:
        # LIVE MODE: Query strictly from SQL database
        for query_name, field in (
            ("host", Incident.computer),
            ("technique", Incident.ransomware_family),
        ):
            value = request.args.get(query_name)
            if value:
                query = query.filter(field.ilike(f"%{_safe_like(value)}%", escape="\\"))

        try:
            minimum_risk = float(request.args.get("min_risk", 0.0))
            if minimum_risk > 0:
                query = query.filter(Incident.risk_score >= minimum_risk)
        except ValueError:
            pass

        total = query.count()
        query = query.order_by(Incident.risk_score.desc())
        limit, offset = _page_args()
        incidents = query.offset(offset).limit(limit).all()
        items = [inc.to_dict() for inc in incidents]

    return jsonify({"items": items, "total": total, "limit": limit, "offset": offset, "mode": "dry_run"})


@incident_bp.get("/api/pipeline_decisions")
def pipeline_decisions():
    """Return the per-window two-stage inference audit log.

    Query parameters:
      computer   — filter by host (substring match)
      would_alert — '1' to return only alerting windows, '0' for non-alerting
      lstm_invoked — '1' / '0'
      limit, offset — pagination (max 1000)
    """
    from backend.models.pipeline_decisions import PipelineDecision

    try:
        query = PipelineDecision.query
    except OperationalError:
        return jsonify({"items": [], "total": 0, "error": "audit table unavailable"}), 503

    computer_filter = request.args.get("computer")
    if computer_filter:
        query = query.filter(
            PipelineDecision.computer.ilike(f"%{_safe_like(computer_filter)}%", escape="\\")
        )

    would_alert_filter = request.args.get("would_alert")
    if would_alert_filter in ("1", "0"):
        query = query.filter(PipelineDecision.would_alert == (would_alert_filter == "1"))

    lstm_invoked_filter = request.args.get("lstm_invoked")
    if lstm_invoked_filter in ("1", "0"):
        query = query.filter(PipelineDecision.lstm_invoked == (lstm_invoked_filter == "1"))

    total = query.count()
    query = query.order_by(PipelineDecision.id.desc())
    limit, offset = _page_args()
    rows = query.offset(offset).limit(limit).all()
    items = [row.to_dict() for row in rows]

    return jsonify({"items": items, "total": total, "limit": limit, "offset": offset})
