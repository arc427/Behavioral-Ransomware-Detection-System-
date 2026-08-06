"""Read-only Flask API for BRDS-PEC dry-run dashboard data."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS

from backend import config
from backend.routes.incident_routes import incident_bp
from backend.routes.telemetry_routes import telemetry_bp
from backend.routes.xai_routes import xai_bp


from backend.models import db


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
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
    )
    if overrides:
        app.config.update(overrides)
        
    if app.config.get("TESTING") and (not overrides or "SQLALCHEMY_DATABASE_URI" not in overrides):
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    
    # Initialize database
    db.init_app(app)
    
    # Load LSTM sequence model
    lstm_path = app.config.get("LSTM_MODEL_PATH")
    try:
        from ml_engine.lstm.infer import LSTMInfer
        if Path(lstm_path).exists():
            app.config["LSTM_INFER"] = LSTMInfer(lstm_path)
            print(f"LSTM model loaded successfully from {lstm_path}")
        else:
            app.config["LSTM_INFER"] = None
            print(f"Warning: LSTM model not found at {lstm_path}")
    except Exception as e:
        app.config["LSTM_INFER"] = None
        print(f"Warning: Failed to load LSTM model: {e}")
    
    # Initialize Telemetry Watchdog
    from pipeline.watchdog import TelemetryWatchdog
    watchdog = TelemetryWatchdog(silence_threshold_seconds=30.0)
    app.config["WATCHDOG"] = watchdog

    import os
    raw_origins = os.environ.get("BRDS_CORS_ORIGINS") or app.config.get("BRDS_CORS_ORIGINS")
    if raw_origins:
        if isinstance(raw_origins, list):
            allowed_origins = raw_origins
        else:
            allowed_origins = [o.strip() for o in str(raw_origins).split(",") if o.strip()]
    else:
        allowed_origins = ["http://localhost:5000", "http://127.0.0.1:5000", "http://localhost:3000", "http://127.0.0.1:3000"]

    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})
    app.register_blueprint(telemetry_bp)
    app.register_blueprint(incident_bp)
    app.register_blueprint(xai_bp)

    @app.get("/api/health")
    def health():
        paths = {key: Path(app.config[key]) for key in ("ALERTS_PATH", "TELEMETRY_PATH", "MODEL_PATH", "REPORT_PATH")}
        sensor_status = watchdog.get_status()
        overall_status = "ok" if sensor_status["sensor_healthy"] else "SENSOR_SILENCED"
        return jsonify({
            "status": overall_status,
            "mode": "dry_run",
            "telemetry_sensor": sensor_status,
            "artifacts": {key.lower().replace("_path", ""): path.exists() for key, path in paths.items()},
            "containment_enabled": False
        })

    return app


if __name__ == "__main__":
    import os
    create_app().run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG", "0") == "1")
