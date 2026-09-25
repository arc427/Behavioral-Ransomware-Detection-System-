"""Stage B tests: decision/audit layer.

Covers:
  - PipelineDecision row written for every evaluated window
  - Row fields match inference result (IF score, LSTM score, skip_reason, etc.)
  - inference_error surfaces in API response when pipeline fails
  - /api/health reports actual IF/LSTM load state
  - /api/health reflects BRDS_LIVE_CONTAINMENT env var
  - /api/pipeline_decisions returns audit rows with filters
"""

from __future__ import annotations

import os
import joblib
import numpy as np
import pandas as pd
import pytest

from ml_engine.two_stage_pipeline import TwoStageInferencePipeline
from scripts.train_baseline import train


# ── Fixtures ─────────────────────────────────────────────────────────────────

FEATURE_NAMES = ["event_count", "file_activity_count", "registry_activity_count"]


class RecordingLSTM:
    def __init__(self, feature_names=FEATURE_NAMES, return_score=0.92):
        self.feature_names = feature_names
        self.return_score = return_score
        self.calls = 0

    def score_sequence(self, sequence_df):
        self.calls += 1
        return self.return_score


def _build_baseline(tmp_path):
    rows = []
    for label, prefix, offset in ((0, "benign", 0), (1, "attack", 10)):
        for si in range(3):
            for ri in range(4):
                rows.append({
                    "source": f"{prefix}-{si}", "label": label,
                    "computer": "host-a", "process_key": f"p-{ri}",
                    "window_start": f"2026-01-01T00:00:{ri:02d}Z",
                    "event_count": offset + ri,
                    "file_activity_count": offset + ri,
                    "registry_activity_count": ri,
                })
    artifacts, _ = train(pd.DataFrame(rows))
    path = tmp_path / "baseline_models.joblib"
    joblib.dump(artifacts, path)
    return path


@pytest.fixture
def app_with_pipeline(tmp_path):
    """Flask test app with a real (tiny) two-stage pipeline injected."""
    from backend.app import create_app

    baseline_path = _build_baseline(tmp_path)
    lstm = RecordingLSTM()
    pipeline = TwoStageInferencePipeline(baseline_path, lstm_infer=lstm, if_screening_threshold=-999.0)

    app = create_app({
        "TESTING": True,
        "MODEL_PATH": baseline_path,
        "LSTM_MODEL_PATH": tmp_path / "missing.pth",
        "ALERTS_PATH": tmp_path / "alerts.json",
        "TELEMETRY_PATH": tmp_path / "telemetry.csv",
        "REPORT_PATH": tmp_path / "report.json",
    })
    app.config["INFERENCE_PIPELINE"] = pipeline
    app.config["LSTM_INFER"] = lstm

    os.environ["BRDS_API_KEY"] = "test-key"
    yield app, lstm
    os.environ.pop("BRDS_API_KEY", None)


def _post_window(client, computer="host-a", window_start="2026-01-01T00:00:00Z", technique="T1486"):
    return client.post(
        "/api/score/live",
        json={
            "computer": computer,
            "process_key": "evil.exe:1234",
            "window_start": window_start,
            "technique_id": technique,
            "features": {
                "event_count": 19,
                "file_activity_count": 19,
                "registry_activity_count": 5,
            },
        },
        headers={"X-BRDS-API-Key": "test-key"},
    )


# ── Stage B Test: audit row written ──────────────────────────────────────────

def test_b1_audit_row_written_for_every_window(app_with_pipeline):
    """A PipelineDecision row must be persisted for every scored window."""
    from backend.models.pipeline_decisions import PipelineDecision

    app, lstm = app_with_pipeline
    with app.test_client() as client:
        _post_window(client, window_start="2026-01-01T00:00:01Z")
        _post_window(client, window_start="2026-01-01T00:00:02Z")

    with app.app_context():
        count = PipelineDecision.query.count()
        assert count == 2, f"Expected 2 audit rows, got {count}"


def test_b2_audit_row_fields_match_inference(app_with_pipeline):
    """Audit row fields must exactly match the WindowInferenceResult for that window."""
    from backend.models.pipeline_decisions import PipelineDecision

    app, lstm = app_with_pipeline
    with app.test_client() as client:
        res = _post_window(client, window_start="2026-01-01T00:01:00Z")
        body = res.get_json()

    with app.app_context():
        row = PipelineDecision.query.filter_by(window_start="2026-01-01T00:01:00Z").one()
        assert row.isolation_forest_decision == "anomalous"
        assert row.isolation_forest_anomalous is True
        assert row.lstm_invoked is True
        assert row.lstm_score == pytest.approx(0.92)
        assert row.lstm_decision == "malicious"
        assert row.final_risk_score == pytest.approx(0.92)
        assert row.would_alert is True
        assert row.skip_reason is None
        assert row.anomaly_score is not None
        assert row.lstm_alert_threshold == pytest.approx(0.85)
        assert row.if_screening_threshold is not None


def test_b3_audit_row_skip_reason_when_if_normal(tmp_path):
    """When IF says normal, skip_reason must be 'isolation_forest_normal' in the audit row."""
    from backend.app import create_app
    from backend.models.pipeline_decisions import PipelineDecision

    baseline_path = _build_baseline(tmp_path)
    lstm = RecordingLSTM()
    pipeline = TwoStageInferencePipeline(baseline_path, lstm_infer=lstm, if_screening_threshold=999.0)

    app = create_app({
        "TESTING": True,
        "MODEL_PATH": baseline_path,
        "LSTM_MODEL_PATH": tmp_path / "missing.pth",
        "ALERTS_PATH": tmp_path / "alerts.json",
        "TELEMETRY_PATH": tmp_path / "telemetry.csv",
        "REPORT_PATH": tmp_path / "report.json",
    })
    app.config["INFERENCE_PIPELINE"] = pipeline

    os.environ["BRDS_API_KEY"] = "test-key"
    try:
        with app.test_client() as client:
            _post_window(client, window_start="2026-01-01T00:02:00Z")

        with app.app_context():
            row = PipelineDecision.query.filter_by(window_start="2026-01-01T00:02:00Z").one()
            assert row.isolation_forest_decision == "normal"
            assert row.lstm_invoked is False
            assert row.skip_reason == "isolation_forest_normal"
            assert row.final_risk_score == pytest.approx(0.0)
            assert row.would_alert is False
    finally:
        os.environ.pop("BRDS_API_KEY", None)


def test_b4_inference_error_surfaces_in_response(tmp_path):
    """When the pipeline raises, the API must return HTTP 200 with inference_error key."""
    from backend.app import create_app

    baseline_path = _build_baseline(tmp_path)

    class BrokenPipeline:
        def evaluate_window(self, *a, **kw):
            raise RuntimeError("synthetic pipeline failure")

    app = create_app({
        "TESTING": True,
        "MODEL_PATH": baseline_path,
        "LSTM_MODEL_PATH": tmp_path / "missing.pth",
        "ALERTS_PATH": tmp_path / "alerts.json",
        "TELEMETRY_PATH": tmp_path / "telemetry.csv",
        "REPORT_PATH": tmp_path / "report.json",
    })
    app.config["INFERENCE_PIPELINE"] = BrokenPipeline()

    os.environ["BRDS_API_KEY"] = "test-key"
    try:
        with app.test_client() as client:
            res = _post_window(client, window_start="2026-01-01T00:03:00Z")
        assert res.status_code == 200
        body = res.get_json()
        assert "inference_error" in body
        assert "synthetic pipeline failure" in body["inference_error"]
        assert body["risk_score"] == pytest.approx(0.0)
    finally:
        os.environ.pop("BRDS_API_KEY", None)


def test_b5_health_reports_pipeline_load_state(app_with_pipeline):
    """/api/health must report actual IF/LSTM load state, not hardcoded values."""
    app, _ = app_with_pipeline
    with app.test_client() as client:
        res = client.get("/api/health")
    assert res.status_code == 200
    body = res.get_json()
    assert "pipeline" in body
    pl = body["pipeline"]
    assert "isolation_forest_loaded" in pl
    assert "lstm_loaded" in pl
    assert "schema_aligned" in pl
    # The injected pipeline has IF loaded
    assert pl["isolation_forest_loaded"] is True


def test_b6_health_containment_mode_from_env(app_with_pipeline):
    """/api/health containment_enabled must reflect BRDS_LIVE_CONTAINMENT env var."""
    app, _ = app_with_pipeline

    # Default: dry_run
    os.environ.pop("BRDS_LIVE_CONTAINMENT", None)
    with app.test_client() as client:
        res = client.get("/api/health")
    body = res.get_json()
    assert body["mode"] == "dry_run"
    assert body["containment_enabled"] is False

    # Lab-armed
    os.environ["BRDS_LIVE_CONTAINMENT"] = "1"
    try:
        with app.test_client() as client:
            res = client.get("/api/health")
        body = res.get_json()
        assert body["mode"] == "lab_armed"
        assert body["containment_enabled"] is True
    finally:
        os.environ.pop("BRDS_LIVE_CONTAINMENT", None)


def test_b7_pipeline_decisions_endpoint_returns_audit_rows(app_with_pipeline):
    """/api/pipeline_decisions must return persisted audit rows with pagination."""
    app, lstm = app_with_pipeline
    with app.test_client() as client:
        _post_window(client, window_start="2026-01-01T00:04:01Z")
        _post_window(client, window_start="2026-01-01T00:04:02Z")
        res = client.get("/api/pipeline_decisions")

    assert res.status_code == 200
    body = res.get_json()
    assert "items" in body
    assert "total" in body
    assert body["total"] >= 2
    first = body["items"][0]
    for key in ("window_start", "computer", "isolation_forest_decision",
                 "lstm_invoked", "lstm_score", "final_risk_score", "would_alert"):
        assert key in first, f"Missing key in audit row: {key}"


def test_b8_pipeline_decisions_filter_would_alert(app_with_pipeline):
    """/api/pipeline_decisions?would_alert=1 returns only alerting windows."""
    app, lstm = app_with_pipeline
    with app.test_client() as client:
        _post_window(client, window_start="2026-01-01T00:05:01Z")
        res = client.get("/api/pipeline_decisions?would_alert=1")

    body = res.get_json()
    for item in body["items"]:
        assert item["would_alert"] is True
