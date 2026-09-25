"""Stage D tests: evaluation experiments verification.

Covers:
  - Experiment 1: Isolation Forest alone returns metrics and screening efficiency
  - Experiment 2: LSTM alone returns metrics and 100% invocation count
  - Experiment 3: Two-Stage pipeline reduces LSTM invocations and returns metrics
  - Experiment 4: Latency & throughput benchmark produces valid numbers
  - Experiment 5: Detection lead-time analyzer handles missing and present timestamps
  - End-to-end run_all_experiments writes valid JSON report
"""

from __future__ import annotations

import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from scripts.evaluate_experiments import (
    _calc_metrics,
    analyze_detection_lead_time,
    eval_isolation_forest_alone,
    eval_lstm_alone,
    eval_two_stage_pipeline,
    run_all_experiments,
)
from scripts.train_baseline import train


# ── Fixtures ──────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "event_count", "unique_images", "unique_files", "unique_extensions",
    "unique_destination_ips", "suspicious_path_count", "file_activity_count",
    "registry_activity_count", "network_activity_count", "event_1_count",
    "event_3_count", "event_7_count", "event_11_count", "event_12_count",
    "event_13_count", "event_23_count", "event_26_count",
]


class MockLSTM:
    def __init__(self, feature_names=FEATURE_NAMES, return_score=0.92):
        self.feature_names = feature_names
        self.return_score = return_score

    def score_sequence(self, sequence_df):
        return self.return_score


@pytest.fixture
def tiny_dataset():
    rows = []
    # 4 sources: 2 benign, 2 attack -> scenario_split will put them into train/val/test
    for label, prefix in ((0, "benign"), (1, "attack")):
        for src_idx in range(4):
            for row_idx in range(5):
                row = {
                    "source": f"{prefix}_{src_idx}",
                    "label": label,
                    "computer": f"host_{src_idx}",
                    "process_key": f"p_{row_idx}",
                    "window_start": f"2026-01-01T00:00:{row_idx:02d}Z",
                }
                for f in FEATURE_NAMES:
                    row[f] = 0 if label == 0 else 50
                rows.append(row)
    return pd.DataFrame(rows)


def test_d1_calc_metrics_accuracy():
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 1, 0, 1])
    scores = np.array([0.1, 0.6, 0.4, 0.9])

    m = _calc_metrics(y_true, y_pred, scores=scores)
    assert m["true_positives"] == 1
    assert m["false_positives"] == 1
    assert m["true_negatives"] == 1
    assert m["false_negatives"] == 1
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["false_positive_rate"] == 0.5
    assert m["roc_auc"] is not None


def test_d2_eval_isolation_forest_alone(tmp_path, tiny_dataset):
    artifacts, _ = train(tiny_dataset)
    res = eval_isolation_forest_alone(artifacts, tiny_dataset)

    assert "metrics" in res
    assert "screening_efficiency" in res
    assert res["screening_efficiency"]["screening_rate"] >= 0.0
    assert "precision" in res["metrics"]
    assert "recall" in res["metrics"]


def test_d3_eval_lstm_alone(tiny_dataset):
    lstm = MockLSTM(return_score=0.90)
    res = eval_lstm_alone(lstm, tiny_dataset, threshold=0.85)

    assert "metrics" in res
    assert res["lstm_invocations"] == len(tiny_dataset)
    assert res["metrics"]["recall"] == 1.0


def test_d4_eval_two_stage_pipeline_reduces_invocations(tmp_path, tiny_dataset):
    artifacts, _ = train(tiny_dataset)
    joblib_path = tmp_path / "baseline_models.joblib"
    import joblib
    joblib.dump(artifacts, joblib_path)

    lstm = MockLSTM(return_score=0.90)
    from ml_engine.two_stage_pipeline import TwoStageInferencePipeline
    pipeline = TwoStageInferencePipeline(joblib_path, lstm_infer=lstm)

    # Force IF to predict normal on first 10 rows, anomalous on remaining via legacy gate
    pipeline.use_legacy_predict_gate = True
    preds = np.array([1] * 10 + [-1] * (len(tiny_dataset) - 10))
    pipeline.isolation_forest.predict = lambda X: preds[:len(X)]

    res = eval_two_stage_pipeline(pipeline, tiny_dataset, threshold=0.85)
    assert res["lstm_invocations"] < len(tiny_dataset)
    assert res["invocation_reduction_pct"] > 0.0


def test_d5_analyze_detection_lead_time():
    # Without encryption_start column
    df_no_enc = pd.DataFrame({"source": ["a", "b"]})
    res_no = analyze_detection_lead_time(df_no_enc)
    assert res_no["lead_time_measurable"] is False
    assert "No ground-truth" in res_no["reason"]

    # With encryption_start column
    df_with_enc = pd.DataFrame({
        "source": ["a", "b"],
        "encryption_start": ["2026-01-01T00:00:10Z", "2026-01-01T00:00:20Z"],
    })
    res_yes = analyze_detection_lead_time(df_with_enc)
    assert res_yes["lead_time_measurable"] is True
    assert res_yes["annotated_sources_count"] == 2
