"""Explainability API placeholder with an explicit availability state."""

from flask import Blueprint, jsonify


xai_bp = Blueprint("xai", __name__)


@xai_bp.get("/api/explanations/<alert_id>")
def explanation(alert_id: str):
    return jsonify({"alert_id": alert_id, "available": False, "message": "SHAP explanations are not generated in dry-run baseline mode."}), 404
