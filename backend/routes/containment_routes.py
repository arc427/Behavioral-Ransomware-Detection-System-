"""Containment action endpoints.

POST /api/containment/status — called by trigger_daemon.py to persist the
    result of a containment action (status: CONTAINED | DRY_RUN_CONTAINED)
    back into the Incident table so the dashboard reflects reality.

This endpoint never triggers containment itself — it only records what the
daemon already did.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from sqlalchemy.exc import OperationalError

from backend.auth import require_api_key
from backend.models import db
from backend.models.incidents import Incident

containment_bp = Blueprint("containment", __name__)

ALLOWED_STATUSES = frozenset({"CONTAINED", "DRY_RUN_CONTAINED", "ACTIVE", "DISMISSED"})


@containment_bp.post("/api/containment/status")
@require_api_key
def update_containment_status():
    """Persist a containment result from the daemon into the Incident table.

    Body JSON:
        window_start  str  — timestamp that identifies the incident
        computer      str  — host name
        status        str  — one of CONTAINED | DRY_RUN_CONTAINED | ACTIVE | DISMISSED
    """
    data = request.get_json() or {}
    window_start = data.get("window_start")
    computer = data.get("computer")
    new_status = data.get("status", "").upper()

    if not window_start or not computer:
        return jsonify({"error": "window_start and computer are required"}), 400

    if new_status not in ALLOWED_STATUSES:
        return jsonify({
            "error": f"Invalid status '{new_status}'. Allowed: {sorted(ALLOWED_STATUSES)}"
        }), 400

    try:
        incident = Incident.query.filter_by(
            timestamp=window_start, computer=computer
        ).first()
    except OperationalError:
        return jsonify({"error": "database unavailable"}), 503

    if incident is None:
        return jsonify({
            "status": "not_found",
            "detail": f"No incident for window_start={window_start} computer={computer}",
        }), 404

    incident.status = new_status
    db.session.commit()

    return jsonify({
        "status": "updated",
        "incident_id": f"INC-{incident.id}",
        "computer": computer,
        "window_start": window_start,
        "new_status": new_status,
    })
