"""Tests for canonical Isolation Forest -> LSTM inference pipeline."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from ml_engine.two_stage_pipeline import TwoStageInferencePipeline
from pipeline.vectorizer import CANONICAL_FEATURE_NAMES, validate_feature_schema
from scripts.train_baseline import train


class RecordingLSTM:
    """Minimal LSTM stand-in that records invocations and feature schema."""

    def __init__(self, feature_names: list[str], return_score: float = 0.92):
        self.feature_names = feature_names
        self.return_score = return_score
        self.calls = 0
        self.last_sequence: pd.DataFrame | None = None

    def score_sequence(self, sequence_df: pd.DataFrame) -> float:
        self.calls += 1
        self.last_sequence = sequence_df.copy()
        missing = set(self.feature_names) - set(sequence_df.columns)
        assert not missing, f"Missing LSTM features: {missing}"
        return self.return_score


def _train_tiny_baseline(tmp_path: Path) -> Path:
    rows = []
    for label, prefix, offset in ((0, "benign", 0), (1, "attack", 10)):
        for source_index in range(3):
            for row_index in range(4):
                rows.append(
                    {
                        "source": f"{prefix}-{source_index}",
                        "label": label,
                        "computer": "host-a",
                        "process_key": f"p-{row_index}",
                        "window_start": f"2026-01-01T00:00:{row_index:02d}Z",
                        "event_count": offset + row_index,
                        "file_activity_count": offset + row_index,
                        "registry_activity_count": row_index,
                    }
                )
    artifacts, _ = train(pd.DataFrame(rows))
    model_path = tmp_path / "baseline_models.joblib"
    joblib.dump(artifacts, model_path)
    return model_path


def _lstm_names() -> list[str]:
    return ["event_count", "file_activity_count", "registry_activity_count"]


def _benign_window() -> dict:
    return {
        "computer": "host-a",
        "process_key": "p-0",
        "window_start": "2026-01-01T00:00:00Z",
        "technique_id": "benign",
        "event_count": 0,
        "file_activity_count": 0,
        "registry_activity_count": 0,
    }


def _attack_window() -> dict:
    return {
        "computer": "host-a",
        "process_key": "p-9",
        "window_start": "2026-01-01T00:00:09Z",
        "technique_id": "T1486",
        "event_count": 19,
        "file_activity_count": 19,
        "registry_activity_count": 5,
    }


def test_a_normal_benign_window_reaches_isolation_forest(tmp_path):
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm)
    result = pipeline.evaluate_window(_benign_window())

    assert result.anomaly_score is not None
    assert result.isolation_forest_decision in ("normal", "anomalous")
    assert result.models["isolation_forest"] == "baseline_models.joblib"


def test_b_anomalous_window_invokes_lstm(tmp_path):
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm, if_screening_threshold=-999.0)

    load_calls = {"n": 0}

    def history_loader():
        load_calls["n"] += 1
        return [_attack_window()]

    result = pipeline.evaluate_window(_attack_window(), history_loader=history_loader)

    assert result.isolation_forest_anomalous is True
    assert result.lstm_invoked is True
    assert result.lstm_score == pytest.approx(0.92)
    assert result.lstm_decision == "malicious"
    assert result.final_risk_score == pytest.approx(0.92)
    assert result.would_alert is True
    assert lstm.calls == 1
    assert load_calls["n"] == 1


def test_c_lstm_not_invoked_when_isolation_forest_normal(tmp_path):
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm, if_screening_threshold=999.0)

    load_calls = {"n": 0}

    def history_loader():
        load_calls["n"] += 1
        return [_attack_window()]

    result = pipeline.evaluate_window(_attack_window(), history_loader=history_loader)

    assert result.isolation_forest_decision == "normal"
    assert result.isolation_forest_anomalous is False
    assert result.lstm_invoked is False
    assert result.lstm_score is None
    assert result.lstm_decision == "skipped"
    assert result.skip_reason == "isolation_forest_normal"
    assert result.final_risk_score == 0.0
    assert result.would_alert is False
    assert lstm.calls == 0
    assert load_calls["n"] == 0


def test_d_lstm_sequence_has_expected_feature_schema(tmp_path):
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm, if_screening_threshold=-999.0)

    nested = {
        "computer": "host-a",
        "process_key": "p-9",
        "window_start": "2026-01-01T00:00:09Z",
        "features": {
            "event_count": 19,
            "file_activity_count": 19,
            "registry_activity_count": 5,
        },
    }
    pipeline.evaluate_window(nested)

    assert lstm.last_sequence is not None
    for name in lstm.feature_names:
        assert name in lstm.last_sequence.columns
    assert lstm.last_sequence[lstm.feature_names].shape[1] == len(lstm.feature_names)


def test_e_pipeline_returns_if_and_lstm_fields(tmp_path):
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm, if_screening_threshold=-999.0)
    result = pipeline.evaluate_window(_attack_window())
    payload = result.to_api_dict()
    logged = result.to_log_dict()

    for key in (
        "anomaly_score",
        "if_screening_threshold",
        "isolation_forest_anomalous",
        "isolation_forest_decision",
        "isolation_forest_legacy_anomalous",
        "lstm_invoked",
        "lstm_score",
        "lstm_decision",
        "final_risk_score",
        "would_alert",
    ):
        assert key in payload
        assert key in logged
    assert payload["lstm_invoked"] is True
    assert payload["isolation_forest_decision"] == "anomalous"


def test_f_score_live_uses_pipeline_not_lstm_only(tmp_path):
    import os

    from backend.app import create_app
    from backend.models.feature_vectors import FeatureVector

    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm, if_screening_threshold=-999.0)

    app = create_app(
        {
            "TESTING": True,
            "MODEL_PATH": model_path,
            "LSTM_MODEL_PATH": tmp_path / "missing.pth",
            "ALERTS_PATH": tmp_path / "alerts.json",
            "TELEMETRY_PATH": tmp_path / "telemetry.csv",
            "REPORT_PATH": tmp_path / "report.json",
        }
    )
    app.config["INFERENCE_PIPELINE"] = pipeline
    app.config["LSTM_INFER"] = lstm

    os.environ["BRDS_API_KEY"] = "test-key"
    try:
        client = app.test_client()
        payload = {
            "computer": "host-a",
            "process_key": "evil.exe:1234",
            "window_start": "2026-01-01T00:00:09Z",
            "technique_id": "T1486",
            "features": {
                "event_count": 19,
                "file_activity_count": 19,
                "registry_activity_count": 5,
            },
        }
        res = client.post(
            "/api/score/live",
            json=payload,
            headers={"X-BRDS-API-Key": "test-key"},
        )
        assert res.status_code == 200
        body = res.get_json()
        assert "pipeline" in body
        assert body["pipeline"]["isolation_forest_decision"] == "anomalous"
        assert body["pipeline"]["lstm_invoked"] is True
        assert lstm.calls == 1
        with app.app_context():
            saved = FeatureVector.query.filter_by(window_start=payload["window_start"]).one()
            assert saved.anomaly_score is not None
            assert saved.risk_score == pytest.approx(0.92)
    finally:
        os.environ.pop("BRDS_API_KEY", None)


def test_score_dataframe_preserves_two_stage_columns(tmp_path):
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm)
    frame = pd.DataFrame([_benign_window(), _attack_window()])
    scored = pipeline.score_dataframe(frame)

    assert "isolation_forest_anomalous" in scored.columns
    assert "lstm_invoked" in scored.columns
    assert "lstm_decision" in scored.columns
    assert "risk_score" in scored.columns
    assert "pipeline_skip_reason" in scored.columns


# ── Stage A: Feature contract tests ──────────────────────────────────────────

def test_canonical_feature_schema_has_17_features():
    """CANONICAL_FEATURE_NAMES must contain exactly the 17 behavioural features
    produced by temporal_aggregator.py."""
    assert len(CANONICAL_FEATURE_NAMES) == 17
    # Spot-check key features
    for expected in (
        "event_count", "file_activity_count", "registry_activity_count",
        "network_activity_count", "event_1_count", "event_26_count",
        "suspicious_path_count", "unique_destination_ips",
    ):
        assert expected in CANONICAL_FEATURE_NAMES, f"Missing expected feature: {expected}"


def test_validate_feature_schema_returns_missing_names():
    partial = ["event_count", "file_activity_count"]
    missing = validate_feature_schema(partial, strict=False)
    assert "registry_activity_count" in missing
    assert "event_count" not in missing
    assert "file_activity_count" not in missing


def test_validate_feature_schema_strict_raises():
    with pytest.raises(ValueError, match="missing canonical features"):
        validate_feature_schema(["event_count"], strict=True)


def test_validate_feature_schema_full_schema_no_missing():
    missing = validate_feature_schema(CANONICAL_FEATURE_NAMES, strict=True)
    assert missing == []


def test_pipeline_schema_aligned_meta_reported(tmp_path):
    """When IF and LSTM use the same feature list, models_meta must reflect alignment."""
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm)
    # Tiny baseline only has 3 features; mismatch is expected but must be reported
    assert "schema_aligned" in pipeline.models_meta
    assert "feature_count" in pipeline.models_meta
    assert pipeline.models_meta["feature_count"] == str(len(pipeline.feature_names))


def test_pipeline_strict_schema_raises_on_missing_window_feature(tmp_path):
    """With strict_schema=True the pipeline must raise when a required feature
    is absent from a window, rather than silently filling with 0."""
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm, strict_schema=True, if_screening_threshold=-999.0)

    # Window is completely empty — all IF features are missing
    empty_window = {"computer": "host-a", "process_key": "p-0", "window_start": "2026-01-01T00:00:00Z"}
    with pytest.raises(ValueError, match="missing required features"):
        pipeline.evaluate_window(empty_window)


def test_pipeline_default_fills_missing_features_without_raising(tmp_path):
    """Without strict_schema the pipeline must fill missing features with 0 and not raise."""
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(model_path, lstm_infer=lstm, strict_schema=False)

    empty_window = {"computer": "host-a", "process_key": "p-0", "window_start": "2026-01-01T00:00:00Z"}
    result = pipeline.evaluate_window(empty_window)
    # Result should be returned without error; IF score exists
    assert result.anomaly_score is not None


def test_pipeline_mismatched_if_lstm_schemas_logged_not_raised(tmp_path):
    """If IF and LSTM feature lists differ, a warning is issued but no exception
    is raised (strict_schema defaults to False)."""
    model_path = _train_tiny_baseline(tmp_path)
    # LSTM uses a *different* feature set from the IF
    lstm_different = RecordingLSTM(feature_names=["event_count", "unique_images"])
    # Should not raise
    pipeline = TwoStageInferencePipeline(
        model_path, lstm_infer=lstm_different, strict_schema=False
    )
    assert pipeline.models_meta["schema_aligned"] == "False"


def test_pipeline_strict_schema_raises_on_if_lstm_mismatch(tmp_path):
    """With strict_schema=True, an IF/LSTM feature mismatch at load time raises ValueError."""
    model_path = _train_tiny_baseline(tmp_path)
    lstm_different = RecordingLSTM(feature_names=["event_count", "unique_images"])
    with pytest.raises(ValueError, match="Feature mismatch"):
        TwoStageInferencePipeline(
            model_path, lstm_infer=lstm_different, strict_schema=True
        )


# ── Continuous IF Screening Tests (Phase Verification) ────────────────────────

def test_if_continuous_score_used_for_screening(tmp_path):
    """Test 1: Proves the continuous anomaly score governs screening."""
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())

    # Pipeline with high threshold: window score will fall below it
    pipeline_strict = TwoStageInferencePipeline(
        model_path, lstm_infer=lstm, if_screening_threshold=100.0
    )
    res_normal = pipeline_strict.evaluate_window(_attack_window())
    assert res_normal.isolation_forest_anomalous is False
    assert res_normal.isolation_forest_decision == "normal"
    assert res_normal.lstm_invoked is False

    # Pipeline with low threshold: same window score will exceed it
    pipeline_permissive = TwoStageInferencePipeline(
        model_path, lstm_infer=lstm, if_screening_threshold=-100.0
    )
    res_anomalous = pipeline_permissive.evaluate_window(_attack_window())
    assert res_anomalous.isolation_forest_anomalous is True
    assert res_anomalous.isolation_forest_decision == "anomalous"
    assert res_anomalous.lstm_invoked is True


def test_predict_is_no_longer_the_live_tier1_gate(tmp_path):
    """Test 2: Explicitly proves predict() does NOT decide the live Tier-1 gate.

    Case A: predict() returns 1 (normal), but anomaly_score >= threshold -> ANOMALOUS.
    Case B: predict() returns -1 (anomalous), but anomaly_score < threshold -> NORMAL.
    """
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())

    # Case A: predict says normal (+1), but threshold is permissive (-999.0)
    pipeline_a = TwoStageInferencePipeline(
        model_path, lstm_infer=lstm, if_screening_threshold=-999.0
    )
    pipeline_a.isolation_forest.predict = lambda X: np.ones(len(X), dtype=int)
    res_a = pipeline_a.evaluate_window(_benign_window())
    assert res_a.isolation_forest_legacy_prediction == 1
    assert res_a.isolation_forest_legacy_anomalous is False
    # Despite predict() == 1, continuous score exceeds threshold:
    assert res_a.isolation_forest_anomalous is True
    assert res_a.isolation_forest_decision == "anomalous"
    assert res_a.lstm_invoked is True
    assert lstm.calls == 1

    # Case B: predict says anomalous (-1), but threshold is strict (+999.0)
    pipeline_b = TwoStageInferencePipeline(
        model_path, lstm_infer=lstm, if_screening_threshold=999.0
    )
    pipeline_b.isolation_forest.predict = lambda X: np.full(len(X), -1, dtype=int)
    res_b = pipeline_b.evaluate_window(_attack_window())
    assert res_b.isolation_forest_legacy_prediction == -1
    assert res_b.isolation_forest_legacy_anomalous is True
    # Despite predict() == -1, continuous score is below threshold:
    assert res_b.isolation_forest_anomalous is False
    assert res_b.isolation_forest_decision == "normal"
    assert res_b.lstm_invoked is False
    assert res_b.skip_reason == "isolation_forest_normal"


def test_threshold_read_from_configuration_and_environment(tmp_path, monkeypatch):
    """Test 3: Threshold is read from BRDS_IF_SCREENING_THRESHOLD or fallback."""
    import os
    from ml_engine.two_stage_pipeline import DEFAULT_IF_SCREENING_THRESHOLD

    model_path = _train_tiny_baseline(tmp_path)

    # 1. Default fallback
    monkeypatch.delenv("BRDS_IF_SCREENING_THRESHOLD", raising=False)
    monkeypatch.delenv("IF_SCREENING_THRESHOLD", raising=False)
    pipeline_def = TwoStageInferencePipeline(model_path)
    assert pipeline_def.if_screening_threshold == pytest.approx(DEFAULT_IF_SCREENING_THRESHOLD)

    # 2. Read from BRDS_IF_SCREENING_THRESHOLD
    monkeypatch.setenv("BRDS_IF_SCREENING_THRESHOLD", "-0.188196")
    pipeline_env = TwoStageInferencePipeline(model_path)
    assert pipeline_env.if_screening_threshold == pytest.approx(-0.188196)

    # 3. Explicit argument overrides environment
    pipeline_arg = TwoStageInferencePipeline(model_path, if_screening_threshold=-0.109568)
    assert pipeline_arg.if_screening_threshold == pytest.approx(-0.109568)


def test_below_threshold_skips_lstm(tmp_path):
    """Test 4: Below threshold -> LSTM is skipped and audit reason recorded."""
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())
    pipeline = TwoStageInferencePipeline(
        model_path, lstm_infer=lstm, if_screening_threshold=999.0
    )
    result = pipeline.evaluate_window(_attack_window())

    assert result.isolation_forest_anomalous is False
    assert result.lstm_invoked is False
    assert result.lstm_score is None
    assert result.lstm_decision == "skipped"
    assert result.skip_reason == "isolation_forest_normal"
    assert result.final_risk_score == 0.0
    assert result.would_alert is False
    assert lstm.calls == 0


def test_at_or_above_threshold_invokes_lstm(tmp_path):
    """Test 5: At or above threshold -> LSTM is invoked with existing decision logic."""
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names(), return_score=0.91)
    pipeline = TwoStageInferencePipeline(
        model_path, lstm_infer=lstm, if_screening_threshold=-999.0
    )
    result = pipeline.evaluate_window(_attack_window())

    assert result.isolation_forest_anomalous is True
    assert result.lstm_invoked is True
    assert result.lstm_score == pytest.approx(0.91)
    assert result.lstm_decision == "malicious"
    assert result.final_risk_score == pytest.approx(0.91)
    assert result.would_alert is True
    assert lstm.calls == 1


def test_if_score_and_threshold_appear_in_decision_and_audit(tmp_path):
    """Test 6: Score and threshold appear in WindowInferenceResult and API payload."""
    model_path = _train_tiny_baseline(tmp_path)
    pipeline = TwoStageInferencePipeline(
        model_path, if_screening_threshold=-0.167461
    )
    result = pipeline.evaluate_window(_attack_window())

    assert result.anomaly_score is not None
    assert result.if_screening_threshold == pytest.approx(-0.167461)
    assert result.models["if_screening_threshold"] == "-0.167461"
    assert result.models["if_screening_mode"] == "continuous_score"

    api_dict = result.to_api_dict()
    assert "anomaly_score" in api_dict
    assert "if_screening_threshold" in api_dict
    assert api_dict["if_screening_threshold"] == pytest.approx(-0.167461)
    assert "isolation_forest_legacy_anomalous" in api_dict


def test_legacy_predict_gate_mode_preserves_comparison(tmp_path):
    """Test 7: use_legacy_predict_gate allows exact comparison with old predict() gate."""
    model_path = _train_tiny_baseline(tmp_path)
    lstm = RecordingLSTM(feature_names=_lstm_names())

    # In legacy mode, predict() governs regardless of anomaly score
    pipeline = TwoStageInferencePipeline(
        model_path, lstm_infer=lstm, use_legacy_predict_gate=True
    )
    assert pipeline.models_meta["if_screening_mode"] == "legacy_predict"

    pipeline.isolation_forest.predict = lambda X: np.ones(len(X), dtype=int)
    res_normal = pipeline.evaluate_window(_attack_window())
    assert res_normal.isolation_forest_anomalous is False
    assert res_normal.lstm_invoked is False

    pipeline.isolation_forest.predict = lambda X: np.full(len(X), -1, dtype=int)
    res_anom = pipeline.evaluate_window(_attack_window())
    assert res_anom.isolation_forest_anomalous is True
    assert res_anom.lstm_invoked is True
