import json

import pandas as pd

from backend.app import create_app


def test_read_only_dashboard_endpoints(tmp_path):
    alerts = tmp_path / "alerts.json"
    telemetry = tmp_path / "windows.csv"
    alerts.write_text(json.dumps([{"computer": "host-a", "technique_id": "T1486", "risk_score": 0.91, "mode": "dry_run"}]), encoding="utf-8")
    pd.DataFrame([{"computer": "host-a", "technique_id": "T1486", "event_count": 4}]).to_csv(telemetry, index=False)
    app = create_app({"TESTING": True, "ALERTS_PATH": alerts, "TELEMETRY_PATH": telemetry, "MODEL_PATH": tmp_path / "missing.joblib", "REPORT_PATH": tmp_path / "missing.json"})
    client = app.test_client()
    assert client.get("/api/health").get_json()["containment_enabled"] is False
    assert client.get("/api/alerts?technique=T1486").get_json()["total"] == 1
    assert client.get("/api/telemetry?host=host-a").get_json()["items"][0]["event_count"] == 4
