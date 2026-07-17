import pandas as pd
import joblib
from pathlib import Path

from scripts.train_baseline import detection_lead_times, scenario_split, train
from ml_engine.risk_engine import RiskEngine


def test_scenario_split_has_no_source_leakage():
    rows = []
    for label, prefix in ((0, "benign"), (1, "attack")):
        for index in range(3):
            rows.append({"source": f"{prefix}-{index}", "label": label, "event_count": index})
    splits = scenario_split(pd.DataFrame(rows))
    source_sets = [set(frame.source) for frame in splits.values()]
    assert not source_sets[0] & source_sets[1]
    assert not source_sets[0] & source_sets[2]
    assert not source_sets[1] & source_sets[2]


def test_train_baseline_with_source_separated_data():
    rows = []
    for label, prefix, offset in ((0, "benign", 0), (1, "attack", 10)):
        for source_index in range(3):
            for row_index in range(3):
                rows.append({
                    "source": f"{prefix}-{source_index}", "label": label,
                    "computer": "host", "process_key": str(row_index),
                    "window_start": "2026-01-01", "event_count": offset + row_index,
                    "file_activity_count": offset + row_index,
                })
    artifacts, report = train(pd.DataFrame(rows))
    assert artifacts["feature_names"] == ["event_count", "file_activity_count"]
    assert report["test"]["roc_auc"] is not None


def test_detection_lead_time_uses_encryption_annotation():
    frame = pd.DataFrame({"source": ["attack-a"], "label": [1], "window_start": ["2026-01-01T00:00:00Z"]})
    lead = detection_lead_times(frame, scores=[0.9], encryption_times={"attack-a": "2026-01-01T00:01:00Z"}, threshold=0.85)
    assert lead == {"attack-a": 60.0}


def test_risk_engine_is_dry_run(tmp_path=None):
    rows = []
    for label, prefix, offset in ((0, "benign", 0), (1, "attack", 10)):
        for source_index in range(3):
            rows.append({"source": f"{prefix}-{source_index}", "label": label, "computer": "host", "process_key": "p", "window_start": "2026-01-01", "event_count": offset + source_index})
    artifacts, _ = train(pd.DataFrame(rows))
    path = Path("data/processed/test_baseline_models.joblib")
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifacts, path)
    result = RiskEngine(path).score(pd.DataFrame(rows[:1]))
    assert result.loc[0, "mode"] == "dry_run"
