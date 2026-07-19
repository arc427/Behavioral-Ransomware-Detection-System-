from flask import Blueprint, jsonify, current_app
from backend.models import db
from backend.models.incidents import Incident
from backend.models.feature_vectors import FeatureVector
from backend.models.explainability_logs import ExplainabilityLog
from ml_engine.xai.shap_explainer import SHAPExplainer
from sqlalchemy.exc import OperationalError

xai_bp = Blueprint("xai", __name__)


@xai_bp.get("/api/explanations/<alert_id>")
def explanation(alert_id: str):
    # 1. Check if explanations are already saved in explainability_logs table
    try:
        saved_logs = ExplainabilityLog.query.filter_by(alert_id=alert_id).all()
        if saved_logs:
            attributions = [{"feature_name": log.feature_name, "importance_value": log.importance_value} for log in saved_logs]
            return jsonify({
                "alert_id": alert_id,
                "available": True,
                "attributions": attributions
            })
    except OperationalError:
        saved_logs = []

    # 2. If not saved, find the incident and corresponding feature vector to compute them
    try:
        # Search by Incident ID or Incident timestamp
        incident = Incident.query.filter((Incident.id == alert_id) | (Incident.timestamp == alert_id)).first()
        if not incident:
            return jsonify({"alert_id": alert_id, "available": False, "message": "Incident alert not found."}), 404
            
        # Find feature vector matching the incident's timestamp
        vector = FeatureVector.query.filter_by(window_start=incident.timestamp).first()
        if not vector:
            return jsonify({"alert_id": alert_id, "available": False, "message": "Telemetry feature vector not found."}), 404
            
        # 3. Compute explanations dynamically
        explainer = SHAPExplainer(current_app.config.get("MODEL_PATH"))
        attributions = explainer.explain(vector.to_dict())
        
        # Save computed attributions to SQL database
        db_logs = []
        for attr in attributions:
            log = ExplainabilityLog(
                alert_id=alert_id,
                feature_name=attr["feature_name"],
                importance_value=attr["importance_value"]
            )
            db_logs.append(log)
        db.session.bulk_save_objects(db_logs)
        db.session.commit()
        
        return jsonify({
            "alert_id": alert_id,
            "available": True,
            "attributions": attributions
        })
    except Exception as e:
        # Fallback if SQLite/model is not initialized: return mock explanations to keep frontend active
        mock_attributions = [
            {"feature_name": "file_activity_count", "importance_value": 0.45},
            {"feature_name": "unique_extensions", "importance_value": 0.35},
            {"feature_name": "suspicious_path_count", "importance_value": 0.15},
            {"feature_name": "registry_activity_count", "importance_value": 0.05}
        ]
        return jsonify({
            "alert_id": alert_id,
            "available": True,
            "attributions": mock_attributions,
            "fallback": True,
            "error": str(e)
        })
