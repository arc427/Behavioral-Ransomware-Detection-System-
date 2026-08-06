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


def _validate_representation(dataset: pd.DataFrame, allow_proxy_representations: bool) -> None:
    """Prevent invalid benchmark claims from mixed raw-log and embedding data."""
    if "representation" not in dataset.columns:
        return
    values = set(dataset["representation"].dropna().astype(str).unique())
    proxy_values = {value for value in values if value != "raw_sysmon"}
    if proxy_values and not allow_proxy_representations:
        raise ValueError(
            "Dataset contains proxy/embedded representations "
            f"({', '.join(sorted(proxy_values))}). Train SILRAD-native models separately "
            "or pass --allow-proxy-representations only for a clearly labelled demo."
        )
    if "raw_sysmon" in values and proxy_values:
        raise ValueError("Refusing to mix raw Sysmon windows with embedded proxy representations.")


def train(dataset: pd.DataFrame, seed: int = 42, encryption_times: dict[str, str] | None = None,
          allow_proxy_representations: bool = False) -> tuple[dict[str, object], dict[str, object]]:
    _validate_representation(dataset, allow_proxy_representations)
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
        "dataset_sources": sorted(dataset.get("dataset_source", pd.Series(["unspecified"])).dropna().astype(str).unique().tolist()),
        "representations": sorted(dataset.get("representation", pd.Series(["raw_sysmon"])).dropna().astype(str).unique().tolist()),
        "validation": metrics_for(y_validation, validation_scores),
        "test": metrics_for(y_test, test_scores),
        "detection_lead_times_seconds": detection_lead_times(splits["test"], test_scores, encryption_times or {}),
        "note": "Detection lead time is null until each scenario includes a verified encryption-start timestamp; source-level splits prevent scenario leakage.",
    }
    return artifacts, report


def scenario_holdout_eval(dataset: pd.DataFrame, seed: int = 42) -> dict[str, object]:
    """Leave-one-scenario-out cross-validation for attack generalization testing.

    For each unique attack scenario, holds it out entirely from training,
    trains on the remaining scenarios + all benign data, and evaluates
    on the held-out attack scenario + a proportional benign sample.
    """
    from pipeline.vectorizer import vectorize as _vectorize

    attack_scenarios = sorted(
        dataset.loc[(dataset["label"] == 1) & (dataset["scenario"].notna()), "scenario"]
        .unique()
        .tolist()
    )
    if len(attack_scenarios) < 2:
        return {"error": "Need at least 2 attack scenarios for held-out evaluation."}

    results: dict[str, object] = {"scenarios": {}}
    all_benign = dataset[dataset["label"] == 0]

    for held_out in attack_scenarios:
        # Test set: held-out attack scenario + proportional benign sample
        test_attack = dataset[(dataset["label"] == 1) & (dataset["scenario"] == held_out)]
        n_test_benign = min(len(all_benign), max(len(test_attack), 500))
        rng = np.random.default_rng(seed)
        test_benign = all_benign.sample(n=n_test_benign, random_state=rng.integers(2**31))
        test_set = pd.concat([test_attack, test_benign], ignore_index=True)

        # Train set: all other attack scenarios + remaining benign
        train_attack = dataset[(dataset["label"] == 1) & (dataset["scenario"] != held_out)]
        train_benign = all_benign.drop(test_benign.index)
        train_set = pd.concat([train_attack, train_benign], ignore_index=True)

        if train_set["label"].nunique() < 2 or test_set["label"].nunique() < 2:
            results["scenarios"][held_out] = {"error": "Insufficient class diversity"}
            continue

        x_train, _ = _vectorize(train_set)
        x_test, _ = _vectorize(test_set.reindex(columns=dataset.columns, fill_value=0))
        y_train = train_set["label"].astype(int)
        y_test = test_set["label"].astype(int)

        model = Pipeline([
            ("scale", StandardScaler()),
            ("model", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=seed))
        ])
        model.fit(x_train, y_train)
        scores = model.predict_proba(x_test)[:, 1]

        results["scenarios"][held_out] = {
            "train_attack_windows": int(len(train_attack)),
            "test_attack_windows": int(len(test_attack)),
            "test_benign_windows": int(n_test_benign),
            **metrics_for(y_test, scores),
        }

    # Compute averages
    scenario_metrics = [v for v in results["scenarios"].values() if isinstance(v, dict) and "f1" in v]
    if scenario_metrics:
        results["average"] = {
            "precision": float(np.mean([m["precision"] for m in scenario_metrics])),
            "recall": float(np.mean([m["recall"] for m in scenario_metrics])),
            "f1": float(np.mean([m["f1"] for m in scenario_metrics])),
            "false_positive_rate": float(np.mean([m["false_positive_rate"] for m in scenario_metrics if m["false_positive_rate"] is not None])),
        }
    results["note"] = (
        "Each scenario was held out entirely from training. "
        "The model was trained on remaining attack scenarios + all benign data, "
        "then tested on the held-out attack scenario. "
        "This measures generalization to unseen attack patterns."
    )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/processed/sysmon_attack_windows.csv")
    parser.add_argument("--model-output", type=Path, default=ROOT / "data/models/baseline_models.joblib")
    parser.add_argument("--report-output", type=Path, default=ROOT / "data/models/baseline_report.json")
    parser.add_argument("--encryption-times", type=Path, help="JSON object mapping attack source path to encryption-start ISO timestamp")
    parser.add_argument("--allow-proxy-representations", action="store_true", help="Permit a single non-raw representation for an explicitly labelled exploratory run")
    parser.add_argument("--scenario-holdout", action="store_true", help="Run leave-one-scenario-out cross-validation")
    parser.add_argument("--holdout-report-output", type=Path, default=ROOT / "data/models/scenario_holdout_report.json")
    args = parser.parse_args()
    dataset = pd.read_csv(args.input)
    encryption_times = json.loads(args.encryption_times.read_text(encoding="utf-8")) if args.encryption_times else None
    artifacts, report = train(dataset, encryption_times=encryption_times,
                              allow_proxy_representations=args.allow_proxy_representations)
    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifacts, args.model_output)
    args.report_output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

    if args.scenario_holdout:
        print("\n--- Scenario Held-Out Cross-Validation ---")
        holdout_report = scenario_holdout_eval(dataset)
        args.holdout_report_output.write_text(json.dumps(holdout_report, indent=2), encoding="utf-8")
        print(json.dumps(holdout_report, indent=2))
        print(f"\nScenario holdout report saved to {args.holdout_report_output}")


if __name__ == "__main__":
    main()

