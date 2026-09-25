import json

import pandas as pd

from backend.app import create_app


def test_read_only_dashboard_endpoints(tmp_path):
    import os
    alerts = tmp_path / "alerts.json"
    telemetry = tmp_path / "windows.csv"
    alerts.write_text(json.dumps([{"computer": "host-a", "technique_id": "T1486", "risk_score": 0.91, "mode": "dry_run"}]), encoding="utf-8")
    pd.DataFrame([{"computer": "host-a", "technique_id": "T1486", "event_count": 4}]).to_csv(telemetry, index=False)
    # Enable offline benchmark mode so the API reads from CSV/JSON files instead of empty SQL DB
    os.environ["BRDS_USE_OFFLINE_BENCHMARK"] = "1"
    try:
        app = create_app({"TESTING": True, "ALERTS_PATH": alerts, "TELEMETRY_PATH": telemetry, "MODEL_PATH": tmp_path / "missing.joblib", "REPORT_PATH": tmp_path / "missing.json"})
        client = app.test_client()
        assert client.get("/api/health").get_json()["containment_enabled"] is False
        assert client.get("/api/alerts?technique=T1486").get_json()["total"] == 1
        assert client.get("/api/telemetry?host=host-a").get_json()["items"][0]["event_count"] == 4
    finally:
        os.environ.pop("BRDS_USE_OFFLINE_BENCHMARK", None)

def test_telemetry_watchdog():
    from pipeline.watchdog import TelemetryWatchdog
    watchdog = TelemetryWatchdog(silence_threshold_seconds=0.1)
    
    # Initial state
    status = watchdog.get_status()
    assert status["sensor_healthy"] is True
    assert status["status"] == "HEALTHY"
    
    # Ping updates count
    watchdog.ping(count=5)
    assert watchdog.get_status()["total_events_ingested"] == 5
    
    # Wait for silence threshold to elapse
    import time
    time.sleep(0.15)
    
    silenced_status = watchdog.get_status()
    assert silenced_status["sensor_healthy"] is False
    assert silenced_status["status"] == "SENSOR_SILENCED"

def test_cors_origin_restrictions(tmp_path):
    alerts = tmp_path / "alerts.json"
    telemetry = tmp_path / "windows.csv"
    alerts.write_text("[]", encoding="utf-8")
    pd.DataFrame([]).to_csv(telemetry, index=False)
    
    app = create_app({
        "TESTING": True,
        "ALERTS_PATH": alerts,
        "TELEMETRY_PATH": telemetry,
        "MODEL_PATH": tmp_path / "m.joblib",
        "REPORT_PATH": tmp_path / "r.json",
        "BRDS_CORS_ORIGINS": ["http://trusted-soc-dashboard.local"]
    })
    client = app.test_client()
    
    # Allowed origin -> returns Access-Control-Allow-Origin header
    res_allowed = client.get("/api/health", headers={"Origin": "http://trusted-soc-dashboard.local"})
    assert res_allowed.headers.get("Access-Control-Allow-Origin") == "http://trusted-soc-dashboard.local"
    
    # Unauthorized origin -> Access-Control-Allow-Origin is omitted/blocked
    res_disallowed = client.get("/api/health", headers={"Origin": "http://malicious-attacker.com"})
    assert res_disallowed.headers.get("Access-Control-Allow-Origin") is None


def test_auth_missing_key_fails_closed(tmp_path, monkeypatch):
    """Missing BRDS_API_KEY environment variable MUST fail closed with 401."""
    monkeypatch.delenv("BRDS_API_KEY", raising=False)
    app = create_app({"TESTING": True, "BRDS_API_KEY": None})
    client = app.test_client()
    
    # Missing API key in environment + no header
    res = client.post("/api/containment/status", json={"window_start": "ts", "computer": "host", "status": "CONTAINED"})
    assert res.status_code == 401
    assert "no API key is configured" in res.get_json()["message"]


def test_auth_wrong_key_fails(tmp_path, monkeypatch):
    """Wrong API key header must fail with 401."""
    monkeypatch.setenv("BRDS_API_KEY", "correct-key")
    app = create_app({"TESTING": True})
    client = app.test_client()
    
    res = client.post("/api/containment/status", 
                      headers={"X-BRDS-API-Key": "wrong-key"},
                      json={"window_start": "ts", "computer": "host", "status": "CONTAINED"})
    assert res.status_code == 401
    assert "Invalid or missing" in res.get_json()["message"]


def test_auth_correct_key_authorized(tmp_path, monkeypatch):
    """Correct API key allows access to containment status."""
    monkeypatch.setenv("BRDS_API_KEY", "correct-key")
    app = create_app({"TESTING": True})
    client = app.test_client()
    
    res = client.post("/api/containment/status", 
                      headers={"X-BRDS-API-Key": "correct-key"},
                      json={"window_start": "ts", "computer": "host", "status": "CONTAINED"})
    # It might return 404 because DB is empty or 503, but not 401
    assert res.status_code != 401
