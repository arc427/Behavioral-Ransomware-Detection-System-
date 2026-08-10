"""Read-only telemetry endpoints for the SOC dashboard."""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
from flask import Blueprint, current_app, jsonify, request
from sqlalchemy.exc import OperationalError

from backend.auth import require_api_key
from backend.models.feature_vectors import FeatureVector

telemetry_bp = Blueprint("telemetry", __name__)


def _page_args() -> tuple[int, int]:
    try:
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return 100, 0
    return max(1, min(limit, current_app.config["MAX_PAGE_SIZE"])), max(0, offset)


def _safe_like(value: str) -> str:
    """Escape % and _ wildcards in SQL LIKE query filters to prevent pattern injection."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@telemetry_bp.get("/api/telemetry")
def telemetry():
    use_offline = (os.environ.get("BRDS_USE_OFFLINE_BENCHMARK") == "1")
    
    db_available = False
    total = 0
    try:
        query = FeatureVector.query
        total = query.count()
        db_available = True
    except OperationalError:
        pass
    
    if use_offline or (not db_available):
        # OFFLINE MODE: Read from historical CSV benchmark file
        path = Path(current_app.config["TELEMETRY_PATH"])
        if not path.exists():
            limit, offset = _page_args()
            return jsonify({"items": [], "total": 0, "limit": limit, "offset": offset})
        frame = pd.read_csv(path)
        for query_name, column in (("host", "computer"), ("technique", "technique_id"), ("source", "source")):
            value = request.args.get(query_name)
            if value and column in frame:
                frame = frame[frame[column].astype(str).str.contains(value, case=False, na=False)]
        limit, offset = _page_args()
        total = len(frame)
        page = frame.iloc[offset : offset + limit].where(pd.notna(frame), None)
        items = page.to_dict(orient="records")
    else:
        # LIVE MODE: Query strictly from SQL database (returns [] when empty)
        for query_name, field in (("host", FeatureVector.computer), 
                                   ("technique", FeatureVector.technique_id), 
                                   ("source", FeatureVector.source)):
            value = request.args.get(query_name)
            if value:
                query = query.filter(field.ilike(f"%{_safe_like(value)}%", escape="\\"))
                
        total = query.count()
        query = query.order_by(FeatureVector.window_start.desc())
        limit, offset = _page_args()
        vectors = query.offset(offset).limit(limit).all()
        items = [v.to_dict() for v in vectors]
        
    return jsonify({"items": items, "total": total, "limit": limit, "offset": offset})


@telemetry_bp.post("/api/score/live")
@require_api_key
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
    
    # Ping Telemetry Watchdog to register active telemetry heartbeat
    watchdog = current_app.config.get("WATCHDOG")
    if watchdog:
        watchdog.ping(count=1)
    
    # 2. Calculate dynamic LSTM sequence score
    lstm_score = 0.0
    lstm_infer = current_app.config.get("LSTM_INFER")
    technique = str(data.get("technique_id", "unknown"))
    is_benign_source = (technique.lower() in ("benign", "unknown", "monitoring", "live-monitoring"))
    
    # Gate check: Skip LSTM scoring for low-activity/idle windows to prevent false positives.
    # Due to training data limitations (where benign traces always had exactly 10 events),
    # the standardized features for low-activity/idle processes become massive outliers
    # that confuse the model, causing false 1.00 risk scores.
    event_count = features.get("event_count", 0)
    file_act = features.get("file_activity_count", 0)
    reg_act = features.get("registry_activity_count", 0)
    is_low_activity = (event_count < 5 and file_act < 3 and reg_act < 3)
    
    if lstm_infer and not is_benign_source and not is_low_activity:
        # Fetch the last 30 windows for this host (chronologically sorted)
        history = FeatureVector.query.filter(FeatureVector.computer == computer)\
            .filter(FeatureVector.window_start <= window_start)\
            .order_by(FeatureVector.window_start.desc())\
            .limit(30).all()
        history.reverse() # Sort ascending
        
        # Require minimum 15 distinct windows before trusting LSTM scores.
        # With fewer windows, the mean-vector padding (to fill 30 steps)
        # creates repeated identical rows that the model misinterprets as
        # ransomware repetition patterns, producing false 1.00 scores.
        if len(history) >= 15:
            rows = [h.to_dict() for h in history]
            df = pd.DataFrame(rows)
            try:
                lstm_score = float(lstm_infer.score_sequence(df))
            except Exception as e:
                current_app.logger.error(f"LSTM inference error: {e}")
                
    # Update FeatureVector risk_score
    vec.risk_score = lstm_score
    
    # 3. Create a signed dry-run alert if score >= 0.85 AND not from benign monitoring
    alert_created = False
    if lstm_score >= 0.85 and not is_benign_source:
        existing = Incident.query.filter_by(timestamp=window_start, computer=computer).first()
        if not existing:
            alert_created = True
            inc = Incident(
                timestamp=window_start,
                computer=computer,
                ransomware_family=vec.technique_id,
                risk_score=lstm_score,
                process_id=int(process_key.split(":")[-1]) if ":" in process_key and process_key.split(":")[-1].isdigit() else 9999,
                status="ACTIVE"
            )
            db.session.add(inc)
            
            # Write signed alert to JSON file for trigger daemon intercept
            from containment.alert_integrity import verify_and_load, sign_alerts
            alerts_path = Path(current_app.config["ALERTS_PATH"])
            alerts = []
            if alerts_path.exists():
                try:
                    alerts = verify_and_load(alerts_path)
                except Exception:
                    alerts = []
            
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
            alerts_path.write_text(sign_alerts(alerts), encoding="utf-8")
            
    db.session.commit()
    
    return jsonify({
        "status": "success",
        "risk_score": lstm_score,
        "alert_created": alert_created,
        "containment_triggered": False,
        "mode": "dry_run",
    })
