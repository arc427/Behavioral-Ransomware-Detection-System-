"""Read-only telemetry endpoints for the SOC dashboard."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from flask import Blueprint, current_app, jsonify, request


from backend.models.feature_vectors import FeatureVector


from sqlalchemy.exc import OperationalError

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
    try:
        query = FeatureVector.query
        total = query.count()
        use_sql = (total > 0)
    except OperationalError:
        use_sql = False
    
    if use_sql:
        # Query from SQL database
        for query_name, field in (("host", FeatureVector.computer), 
                                   ("technique", FeatureVector.technique_id), 
                                   ("source", FeatureVector.source)):
            value = request.args.get(query_name)
            if value:
                query = query.filter(field.ilike(f"%{value}%"))
                
        total = query.count()
        limit, offset = _page_args()
        vectors = query.offset(offset).limit(limit).all()
        items = [v.to_dict() for v in vectors]
    else:
        # Fallback to CSV file reading
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
        items = page.to_dict(orient="records")
        total = len(frame)
        
    return jsonify({"items": items, "total": total, "limit": limit, "offset": offset})


@telemetry_bp.post("/api/score/live")
def score_live():
    """Ingests a new telemetry window, runs LSTM sequence inference, writes alert if needed, and returns the score."""
    import json
    from backend.models import db
    from backend.models.incidents import Incident
    
    data = request.get_json() or {}
    computer = data.get("computer", "BRDS-WIN11-SEC")
    process_key = data.get("process_key", "unknown:9999")
    window_start = data.get("window_start")
    
    if not window_start:
        return jsonify({"error": "window_start is required"}), 400
        
    # Extract features
    features = data.get("features", {})
    
    # 1. Save new FeatureVector to SQL database
    vec = FeatureVector(
        computer=computer,
        process_key=process_key,
        window_start=window_start,
        label=int(data.get("label", 0)),
        technique_id=str(data.get("technique_id", "unknown")),
        scenario=str(data.get("scenario", "unknown")),
        source=str(data.get("source", "live-ingestion")),
        features_json=json.dumps(features)
    )
    db.session.add(vec)
    db.session.commit()
    
    # 2. Calculate dynamic LSTM sequence score
    lstm_score = 0.0
    lstm_infer = current_app.config.get("LSTM_INFER")
    if lstm_infer:
        # Fetch the last 30 windows for this host (chronologically sorted)
        history = FeatureVector.query.filter(FeatureVector.computer == computer)\
            .filter(FeatureVector.window_start <= window_start)\
            .order_by(FeatureVector.window_start.desc())\
            .limit(30).all()
        history.reverse() # Sort ascending
        
        if history:
            rows = [h.to_dict() for h in history]
            df = pd.DataFrame(rows)
            try:
                lstm_score = float(lstm_infer.score_sequence(df))
            except Exception as e:
                current_app.logger.error(f"LSTM inference error: {e}")
                
    # Update FeatureVector risk_score
    vec.risk_score = lstm_score
    
    # 3. Trigger alert and active containment if score >= 0.85
    triggered = False
    if lstm_score >= 0.85:
        existing = Incident.query.filter_by(timestamp=window_start, computer=computer).first()
        if not existing:
            triggered = True
            inc = Incident(
                timestamp=window_start,
                computer=computer,
                ransomware_family=vec.technique_id,
                risk_score=lstm_score,
                process_id=int(process_key.split(":")[-1]) if ":" in process_key and process_key.split(":")[-1].isdigit() else 9999,
                status="ACTIVE"
            )
            db.session.add(inc)
            
            # Write alert to JSON file for trigger daemon intercept
            alerts_path = Path(current_app.config["ALERTS_PATH"])
            alerts = []
            if alerts_path.exists():
                try:
                    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
                  # Make sure it's a list
                    if not isinstance(alerts, list):
                        alerts = []
                except Exception:
                    pass
            
            new_alert = {
                "computer": computer,
                "process_key": process_key,
                "window_start": window_start,
                "timestamp": window_start,
                "label": vec.label,
                "technique_id": vec.technique_id,
                "scenario": vec.scenario,
                "source": vec.source,
                "risk_score": lstm_score
            }
            alerts.append(new_alert)
            alerts_path.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
            
    db.session.commit()
    
    return jsonify({
        "status": "success",
        "risk_score": lstm_score,
        "containment_triggered": triggered
    })
