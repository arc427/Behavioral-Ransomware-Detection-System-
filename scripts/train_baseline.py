"""Train scenario-separated Isolation Forest and Logistic Regression baselines."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.vectorizer import vectorize


def _split_groups(groups: list[str], rng: np.random.Generator) -> tuple[set[str], set[str], set[str]]:
    """Assign entire sources to train/validation/test, requiring three sources/class."""
    if len(groups) < 3:
        raise ValueError("At least three distinct source logs are required for each class.")
    shuffled = list(rng.permutation(groups))
    test_count = max(1, round(len(shuffled) * 0.2))
    validation_count = max(1, round(len(shuffled) * 0.2))
    if test_count + validation_count >= len(shuffled):
        test_count = validation_count = 1
    return set(shuffled[test_count + validation_count :]), set(shuffled[test_count : test_count + validation_count]), set(shuffled[:test_count])


def scenario_split(frame: pd.DataFrame, seed: int = 42) -> dict[str, pd.DataFrame]:
    """Create class-balanced source-level splits with no source leakage."""
    if "source" not in frame or "label" not in frame:
        raise ValueError("Dataset must include source and label columns.")
    rng = np.random.default_rng(seed)
    assignments: dict[str, str] = {}
    for label in (0, 1):
        groups = sorted(frame.loc[frame["label"] == label, "source"].unique())
        train, validation, test = _split_groups(groups, rng)
        assignments.update({group: "train" for group in train})
        assignments.update({group: "validation" for group in validation})
        assignments.update({group: "test" for group in test})
    return {name: frame[frame["source"].map(assignments) == name].copy() for name in ("train", "validation", "test")}


def detection_lead_times(test_frame: pd.DataFrame, scores: np.ndarray, encryption_times: dict[str, str], threshold: float = 0.5) -> dict[str, float | None]:
    """Return encryption-start minus first alert time for annotated attack sources."""
    result: dict[str, float | None] = {}
    if not encryption_times:
        return result
    frame = test_frame.copy()
    frame["score"] = np.asarray(scores)
    frame["window_start"] = pd.to_datetime(frame["window_start"], utc=True, errors="coerce")
    for source, encryption_start in encryption_times.items():
        rows = frame[(frame["source"] == source) & (frame["label"] == 1) & (frame["score"] >= threshold)]
        encryption_at = pd.to_datetime(encryption_start, utc=True, errors="coerce")
        if rows.empty or pd.isna(encryption_at):
            result[source] = None
        else:
            result[source] = float((encryption_at - rows["window_start"].min()).total_seconds())
    return result


def metrics_for(y_true: pd.Series, scores: np.ndarray, threshold: float = 0.5) -> dict[str, float | None]:
    predicted = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    return {
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, scores)) if y_true.nunique() == 2 else None,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "true_positives": int(tp), "false_positives": int(fp), "true_negatives": int(tn), "false_negatives": int(fn),
        "detection_lead_time_seconds": None,
    }


def train(dataset: pd.DataFrame, seed: int = 42, encryption_times: dict[str, str] | None = None) -> tuple[dict[str, object], dict[str, object]]:
    labels = set(dataset.get("label", pd.Series(dtype=int)).dropna().astype(int).unique())
    if labels != {0, 1}:
        raise ValueError(
            "Training requires labelled benign (0) and attack (1) Sysmon windows. "
            "Rebuild the dataset with --benign-input <path-to-benign-sysmon-logs>."
        )
    splits = scenario_split(dataset, seed)
    x_train, feature_names = vectorize(splits["train"])
    x_validation, _ = vectorize(splits["validation"].reindex(columns=dataset.columns, fill_value=0))
    x_test, _ = vectorize(splits["test"].reindex(columns=dataset.columns, fill_value=0))
    y_train = splits["train"]["label"].astype(int)
    y_validation = splits["validation"]["label"].astype(int)
    y_test = splits["test"]["label"].astype(int)
    benign_train = x_train.loc[y_train == 0]
    if benign_train.empty:
        raise ValueError("Isolation Forest requires benign training windows.")
    anomaly = Pipeline([("scale", StandardScaler()), ("model", IsolationForest(contamination=0.05, random_state=seed))])
    anomaly.fit(benign_train)
    supervised = Pipeline([("scale", StandardScaler()), ("model", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=seed))])
    supervised.fit(x_train, y_train)
    validation_scores = supervised.predict_proba(x_validation)[:, 1]
    test_scores = supervised.predict_proba(x_test)[:, 1]
    artifacts: dict[str, object] = {"feature_names": feature_names, "isolation_forest": anomaly, "supervised_model": supervised}
    report: dict[str, object] = {
        "split_windows": {name: int(len(split)) for name, split in splits.items()},
        "split_sources": {name: int(split["source"].nunique()) for name, split in splits.items()},
        "validation": metrics_for(y_validation, validation_scores),
        "test": metrics_for(y_test, test_scores),
        "detection_lead_times_seconds": detection_lead_times(splits["test"], test_scores, encryption_times or {}),
        "note": "Detection lead time is null until each scenario includes a verified encryption-start timestamp; source-level splits prevent scenario leakage.",
    }
    return artifacts, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/processed/sysmon_attack_windows.csv")
    parser.add_argument("--model-output", type=Path, default=ROOT / "data/models/baseline_models.joblib")
    parser.add_argument("--report-output", type=Path, default=ROOT / "data/models/baseline_report.json")
    parser.add_argument("--encryption-times", type=Path, help="JSON object mapping attack source path to encryption-start ISO timestamp")
    args = parser.parse_args()
    dataset = pd.read_csv(args.input)
    encryption_times = json.loads(args.encryption_times.read_text(encoding="utf-8")) if args.encryption_times else None
    artifacts, report = train(dataset, encryption_times=encryption_times)
    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifacts, args.model_output)
    args.report_output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
