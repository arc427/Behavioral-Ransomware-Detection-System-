"""Telemetry ingestion and live scoring endpoints for the SOC dashboard."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pandas as pd
from flask import Blueprint, current_app, jsonify, request
from sqlalchemy.exc import OperationalError

from backend.auth import require_api_key
from backend.models.feature_vectors import FeatureVector

telemetry_bp = Blueprint("telemetry", __name__)
logger = logging.getLogger(__name__)


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
        for query_name, field in (
            ("host", FeatureVector.computer),
            ("technique", FeatureVector.technique_id),
            ("source", FeatureVector.source),
        ):
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
    """Ingest a window, run Isolation Forest -> LSTM, persist an audit row, write an alert if warranted."""
    import json
    from backend.models import db
    from backend.models.incidents import Incident
    from backend.models.pipeline_decisions import PipelineDecision

    data = request.get_json() or {}
    computer = data.get("computer", "BRDS-WIN11-SEC")
    process_key = data.get("process_key", "unknown:9999")
    window_start = data.get("window_start")

    if not window_start:
        return jsonify({"error": "window_start is required"}), 400

    features = data.get("features", {})

    # 1. Persist the incoming FeatureVector
    vec = FeatureVector(
        computer=computer,
        process_key=process_key,
        window_start=window_start,
        label=int(data.get("label", 0)),
        technique_id=str(data.get("technique_id", "unknown")),
        scenario=str(data.get("scenario", "unknown")),
        source=str(data.get("source", "live-ingestion")),
        features_json=json.dumps(features),
    )
    db.session.add(vec)
    db.session.flush()  # assign vec.id without committing so we can reference it

    # Ping Telemetry Watchdog to register active telemetry heartbeat
    watchdog = current_app.config.get("WATCHDOG")
    if watchdog:
        watchdog.ping(count=1)

    # 2. Run two-stage inference
    pipeline = current_app.config.get("INFERENCE_PIPELINE")
    window_row = vec.to_dict()
    inference_result = None
    final_risk = 0.0
    inference_error: str | None = None

    def _load_history() -> list[dict]:
        records = (
            FeatureVector.query.filter(FeatureVector.computer == computer)
            .filter(FeatureVector.window_start <= window_start)
            .order_by(FeatureVector.window_start.desc())
            .limit(30)
            .all()
        )
        records.reverse()
        return [row.to_dict() for row in records]

    if pipeline is not None:
        try:
            inference_result = pipeline.evaluate_window(window_row, history_loader=_load_history)
            final_risk = inference_result.final_risk_score
            # Diagnostic: trace real events through the full pipeline
            logger.info(
                "PIPELINE_TRACE window_start=%s computer=%s process_key=%s "
                "source=%s if_score=%.6f if_threshold=%.6f if_anomalous=%s "
                "lstm_invoked=%s lstm_score=%s lstm_decision=%s "
                "final_risk=%.4f would_alert=%s skip_reason=%s",
                window_start, computer, process_key,
                vec.source,
                inference_result.anomaly_score,
                inference_result.if_screening_threshold,
                inference_result.isolation_forest_anomalous,
                inference_result.lstm_invoked,
                inference_result.lstm_score,
                inference_result.lstm_decision,
                inference_result.final_risk_score,
                inference_result.would_alert,
                inference_result.skip_reason,
            )
        except Exception as exc:
            inference_error = str(exc)
            current_app.logger.error("Two-stage inference error: %s", exc, exc_info=True)
    else:
        inference_error = "INFERENCE_PIPELINE not loaded"
        current_app.logger.warning("INFERENCE_PIPELINE is not loaded; window was stored but not scored")

    # Update FeatureVector with scored results
    vec.anomaly_score = inference_result.anomaly_score if inference_result else None
    vec.risk_score = final_risk

    # 3. Write per-window audit record
    if inference_result is not None:
        meta = inference_result.models
        try:
            threshold_val = float(meta.get("lstm_alert_threshold", 0.85))
        except (TypeError, ValueError):
            threshold_val = 0.85
        schema_ok = meta.get("schema_aligned", "True") == "True"

        decision_row = PipelineDecision(
            window_start=window_start,
            computer=computer,
            process_key=process_key,
            anomaly_score=inference_result.anomaly_score,
            isolation_forest_decision=inference_result.isolation_forest_decision,
            isolation_forest_anomalous=inference_result.isolation_forest_anomalous,
            if_screening_threshold=inference_result.if_screening_threshold,
            if_legacy_anomalous=inference_result.isolation_forest_legacy_anomalous,
            lstm_invoked=inference_result.lstm_invoked,
            lstm_score=inference_result.lstm_score,
            lstm_decision=inference_result.lstm_decision,
            lstm_sequence_windows=inference_result.lstm_sequence_windows,
            final_risk_score=inference_result.final_risk_score,
            would_alert=inference_result.would_alert,
            skip_reason=inference_result.skip_reason,
            if_model_artifact=meta.get("isolation_forest"),
            lstm_model_artifact=meta.get("lstm"),
            lstm_alert_threshold=threshold_val,
            schema_aligned=schema_ok,
            source=vec.source,
            technique_id=vec.technique_id,
        )
        db.session.add(decision_row)

    # 4. Create a signed dry-run alert when the pipeline would alert
    alert_created = False
    would_alert = inference_result.would_alert if inference_result else False
    if would_alert:
        existing = Incident.query.filter_by(timestamp=window_start, computer=computer).first()
        if not existing:
            alert_created = True
            inc = Incident(
                timestamp=window_start,
                computer=computer,
                ransomware_family=vec.technique_id,
                risk_score=final_risk,
                process_id=(
                    int(process_key.split(":")[-1])
                    if ":" in process_key and process_key.split(":")[-1].isdigit()
                    else 9999
                ),
                status="ACTIVE",
            )
            db.session.add(inc)

            from containment.alert_integrity import sign_alerts, verify_and_load

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
                "risk_score": final_risk,
                "anomaly_score": inference_result.anomaly_score if inference_result else None,
                "isolation_forest_decision": inference_result.isolation_forest_decision if inference_result else None,
                "lstm_invoked": inference_result.lstm_invoked if inference_result else False,
                "lstm_score": inference_result.lstm_score if inference_result else None,
            }
            alerts.append(new_alert)
            alerts_path.write_text(sign_alerts(alerts), encoding="utf-8")

    db.session.commit()

    response: dict = {
        "status": "success",
        "risk_score": final_risk,
        "alert_created": alert_created,
        "containment_triggered": False,
        "mode": "dry_run",
    }
    if inference_result is not None:
        response["pipeline"] = inference_result.to_api_dict()
    if inference_error is not None:
        response["inference_error"] = inference_error
    return jsonify(response)
