"""Flask application factory for the BRDS-PEC API."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

from backend import config
from backend.routes.containment_routes import containment_bp
from backend.routes.incident_routes import incident_bp
from backend.routes.telemetry_routes import telemetry_bp
from backend.routes.xai_routes import xai_bp

from backend.models import db


def create_app(overrides: dict | None = None) -> Flask:
    _project_root = Path(__file__).resolve().parents[1]
    _frontend_dir = _project_root / "frontend"

    app = Flask(__name__, static_folder=str(_frontend_dir), static_url_path="/static")
    app.config.from_mapping(
        ALERTS_PATH=config.ALERTS_PATH,
        TELEMETRY_PATH=config.TELEMETRY_PATH,
        MODEL_PATH=config.MODEL_PATH,
        REPORT_PATH=config.REPORT_PATH,
        MAX_PAGE_SIZE=config.MAX_PAGE_SIZE,
        DATABASE_PATH=config.DATABASE_PATH,
        SQLALCHEMY_DATABASE_URI=config.SQLALCHEMY_DATABASE_URI,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        LSTM_MODEL_PATH=config.LSTM_MODEL_PATH,
        IF_SCREENING_THRESHOLD=config.IF_SCREENING_THRESHOLD,
    )
    if overrides:
        app.config.update(overrides)

    if app.config.get("TESTING") and (not overrides or "SQLALCHEMY_DATABASE_URI" not in overrides):
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    # Initialize database — all tables including PipelineDecision audit table
    db.init_app(app)
    with app.app_context():
        # Import so SQLAlchemy registers the new model before create_all
        from backend.models import pipeline_decisions  # noqa: F401
        db.create_all()

    # ── Two-stage inference pipeline (Isolation Forest -> LSTM) ─────────────
    lstm_path = app.config.get("LSTM_MODEL_PATH")
    baseline_path = app.config.get("MODEL_PATH")

    # Track what actually loaded so health can report truthfully
    pipeline_status: dict = {
        "isolation_forest_loaded": False,
        "if_screening_threshold": None,
        "lstm_loaded": False,
        "schema_aligned": None,
        "feature_count": None,
        "load_error": None,
    }

    app.config["LSTM_INFER"] = None
    app.config["INFERENCE_PIPELINE"] = None

    try:
        from ml_engine.lstm.infer import LSTMInfer
        from ml_engine.two_stage_pipeline import TwoStageInferencePipeline

        lstm_infer = None
        if Path(lstm_path).exists():
            lstm_infer = LSTMInfer(lstm_path)
            app.config["LSTM_INFER"] = lstm_infer
            pipeline_status["lstm_loaded"] = True
            print(f"LSTM model loaded from {lstm_path}")
        else:
            print(f"Warning: LSTM model not found at {lstm_path}")

        if Path(baseline_path).exists():
            if_threshold = app.config.get("IF_SCREENING_THRESHOLD")
            pipeline = TwoStageInferencePipeline(
                baseline_path,
                lstm_infer=lstm_infer,
                lstm_model_path=lstm_path,
                if_screening_threshold=if_threshold,
            )
            app.config["INFERENCE_PIPELINE"] = pipeline
            pipeline_status["isolation_forest_loaded"] = True
            pipeline_status["if_screening_threshold"] = pipeline.if_screening_threshold
            pipeline_status["schema_aligned"] = pipeline.models_meta.get("schema_aligned")
            pipeline_status["feature_count"] = pipeline.models_meta.get("feature_count")
            print(f"Two-stage inference pipeline loaded from {baseline_path} (screening threshold: {pipeline.if_screening_threshold})")
        else:
            print(f"Warning: Isolation Forest artifact not found at {baseline_path}")

    except Exception as exc:
        pipeline_status["load_error"] = str(exc)
        app.config["INFERENCE_PIPELINE"] = None
        print(f"Warning: Failed to load inference pipeline: {exc}")

    app.config["PIPELINE_STATUS"] = pipeline_status

    # ── Telemetry watchdog ───────────────────────────────────────────────────
    from pipeline.watchdog import TelemetryWatchdog
    watchdog = TelemetryWatchdog(silence_threshold_seconds=30.0)
    app.config["WATCHDOG"] = watchdog

    # ── CORS ─────────────────────────────────────────────────────────────────
    import os
    raw_origins = os.environ.get("BRDS_CORS_ORIGINS") or app.config.get("BRDS_CORS_ORIGINS")
    if raw_origins:
        if isinstance(raw_origins, list):
            allowed_origins = raw_origins
        else:
            allowed_origins = [o.strip() for o in str(raw_origins).split(",") if o.strip()]
    else:
        allowed_origins = [
            "http://localhost:5000",
            "http://127.0.0.1:5000",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]

    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})
    app.register_blueprint(containment_bp)
    app.register_blueprint(telemetry_bp)
    app.register_blueprint(incident_bp)
    app.register_blueprint(xai_bp)

    @app.get("/api/health")
    def health():
        import os as _os
        paths = {
            key: Path(app.config[key])
            for key in ("ALERTS_PATH", "TELEMETRY_PATH", "MODEL_PATH", "REPORT_PATH")
        }
        sensor_status = watchdog.get_status()
        ps = app.config.get("PIPELINE_STATUS", {})

        # Containment mode comes from the environment — not hardcoded
        live_containment_env = _os.environ.get("BRDS_LIVE_CONTAINMENT", "0")
        containment_mode = "lab_armed" if live_containment_env == "1" else "dry_run"

        overall_status = "ok" if sensor_status["sensor_healthy"] else "SENSOR_SILENCED"
        if ps.get("load_error"):
            overall_status = "PIPELINE_ERROR"

        return jsonify({
            "status": overall_status,
            "mode": containment_mode,
            "telemetry_sensor": sensor_status,
            "pipeline": {
                "isolation_forest_loaded": ps.get("isolation_forest_loaded", False),
                "if_screening_threshold": ps.get("if_screening_threshold"),
                "if_screening_threshold_status": "provisional_calibration_candidate",
                "lstm_loaded": ps.get("lstm_loaded", False),
                "schema_aligned": ps.get("schema_aligned"),
                "feature_count": ps.get("feature_count"),
                "load_error": ps.get("load_error"),
            },
            "containment_enabled": containment_mode == "lab_armed",
            "artifacts": {
                key.lower().replace("_path", ""): path.exists()
                for key, path in paths.items()
            },
        })

    @app.get("/")
    def serve_dashboard():
        """Serve the SOC dashboard at the root URL."""
        return send_from_directory(str(_frontend_dir), "index.html")

    @app.get("/<path:filename>")
    def serve_frontend_files(filename):
        """Serve CSS, JS, and other frontend assets."""
        return send_from_directory(str(_frontend_dir), filename)

    return app


if __name__ == "__main__":
    import os
    create_app().run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG", "0") == "1")
