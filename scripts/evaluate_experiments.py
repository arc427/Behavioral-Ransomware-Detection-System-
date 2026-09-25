"""Stage D Evaluation Experiments: Model 1 vs Model 2 vs Two-Stage Pipeline.

Compares:
  Experiment 1: Model 1 (Isolation Forest) screening alone
  Experiment 2: Model 2 (LSTM sequence classifier) alone
  Experiment 3: Two-Stage Sequential Pipeline (IF -> LSTM)
  Experiment 4: Computational latency, throughput, and invocation reduction
  Experiment 5: Detection lead-time analysis and ground-truth validation
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml_engine.lstm.infer import LSTMInfer
from ml_engine.two_stage_pipeline import TwoStageInferencePipeline
from pipeline.vectorizer import CANONICAL_FEATURE_NAMES, vectorize
from scripts.train_baseline import scenario_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("eval_experiments")
logging.getLogger("ml_engine.two_stage_pipeline").setLevel(logging.WARNING)

DEFAULT_DATASET = ROOT / "data" / "processed" / "sysmon_combined_windows.csv"
DEFAULT_BASELINE = ROOT / "data" / "models" / "baseline_models.joblib"
DEFAULT_LSTM = ROOT / "data" / "models" / "lstm_model.pth"
DEFAULT_OUTPUT = ROOT / "data" / "models" / "two_stage_evaluation_report.json"


def _calc_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None = None) -> dict[str, Any]:
    """Compute standard classification performance metrics."""
    labels = [0, 1]
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=labels).ravel()
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    auc = None
    if scores is not None and len(np.unique(y_true)) == 2:
        try:
            auc = float(roc_auc_score(y_true, scores))
        except Exception:
            auc = None

    return {
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "false_positive_rate": fpr,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "total_windows": int(len(y_true)),
    }


def eval_isolation_forest_alone(
    baseline_artifacts: dict[str, Any],
    test_df: pd.DataFrame,
) -> dict[str, Any]:
    """Experiment 1: Evaluate Tier-1 Isolation Forest anomaly screening alone."""
    model = baseline_artifacts["isolation_forest"]
    x_test, _ = vectorize(test_df[list(baseline_artifacts["feature_names"])])
    y_true = test_df["label"].to_numpy().astype(int)

    # In sklearn IsolationForest: -1 is anomaly (attack candidate), 1 is normal (benign)
    preds_raw = model.predict(x_test)
    y_pred = (preds_raw == -1).astype(int)
    anomaly_scores = -model.decision_function(x_test)  # higher = more anomalous

    metrics = _calc_metrics(y_true, y_pred, scores=anomaly_scores)
    normal_screened = int(np.sum(y_pred == 0))
    screen_rate = float(normal_screened / len(y_pred)) if len(y_pred) > 0 else 0.0

    return {
        "metrics": metrics,
        "screening_efficiency": {
            "normal_windows_screened": normal_screened,
            "anomalous_windows_passed": int(np.sum(y_pred == 1)),
            "screening_rate": screen_rate,
        },
    }


def eval_lstm_alone(
    lstm_infer: LSTMInfer,
    test_df: pd.DataFrame,
    threshold: float = 0.85,
) -> dict[str, Any]:
    """Experiment 2: Evaluate Tier-2 LSTM sequence classifier on all windows without screening."""
    frame = test_df.copy()
    if "window_start" in frame.columns:
        frame["_sort_time"] = pd.to_datetime(frame["window_start"], utc=True, errors="coerce")
    else:
        frame["_sort_time"] = pd.RangeIndex(len(frame))

    scores = []
    y_true_list = []

    for _, group in frame.groupby("computer", sort=False):
        ordered = group.sort_values("_sort_time")
        history: list[dict[str, Any]] = []
        for _, row in ordered.iterrows():
            window = row.to_dict()
            history.append(window)
            seq_df = pd.DataFrame(history[-30:])
            # Expose canonical features
            for name in lstm_infer.feature_names:
                if name not in seq_df.columns:
                    seq_df[name] = 0.0
            prob = lstm_infer.score_sequence(seq_df)
            scores.append(prob)
            y_true_list.append(int(window["label"]))

    scores_arr = np.array(scores)
    y_true_arr = np.array(y_true_list)
    y_pred_arr = (scores_arr >= threshold).astype(int)

    metrics = _calc_metrics(y_true_arr, y_pred_arr, scores=scores_arr)
    return {
        "metrics": metrics,
        "threshold": threshold,
        "lstm_invocations": len(scores_arr),
    }


def eval_two_stage_pipeline(
    pipeline: TwoStageInferencePipeline,
    test_df: pd.DataFrame,
    threshold: float = 0.85,
    if_screening_threshold: float | None = None,
    use_legacy_predict_gate: bool | None = None,
) -> dict[str, Any]:
    """Experiment 3: Evaluate integrated sequential Two-Stage Pipeline (IF -> LSTM)."""
    scored = pipeline.score_dataframe(
        test_df,
        if_screening_threshold=if_screening_threshold,
        use_legacy_predict_gate=use_legacy_predict_gate,
    )
    y_true = scored["label"].to_numpy().astype(int)
    y_pred = scored["would_alert"].to_numpy().astype(int)
    scores = scored["risk_score"].to_numpy()

    metrics = _calc_metrics(y_true, y_pred, scores=scores)
    total_windows = len(scored)
    lstm_invocations = int(scored["lstm_invoked"].sum())
    lstm_skipped = total_windows - lstm_invocations
    reduction_pct = float(lstm_skipped / total_windows * 100.0) if total_windows > 0 else 0.0

    total_attack = int((y_true == 1).sum())
    total_benign = int((y_true == 0).sum())
    attack_passed = int(((y_true == 1) & scored["isolation_forest_anomalous"]).sum())
    benign_passed = int(((y_true == 0) & scored["isolation_forest_anomalous"]).sum())
    if_screening_recall = float(attack_passed / total_attack) if total_attack > 0 else 0.0
    benign_pass_rate = float(benign_passed / total_benign) if total_benign > 0 else 0.0
    effective_if_threshold = (
        if_screening_threshold
        if if_screening_threshold is not None
        else pipeline.if_screening_threshold
    )
    screening_mode = (
        "legacy_predict"
        if (use_legacy_predict_gate if use_legacy_predict_gate is not None else pipeline.use_legacy_predict_gate)
        else "continuous_score"
    )

    return {
        "metrics": metrics,
        "threshold": threshold,
        "if_screening_threshold": effective_if_threshold,
        "if_screening_mode": screening_mode,
        "if_screening_recall": if_screening_recall,
        "attack_windows_passed": attack_passed,
        "total_attack_windows": total_attack,
        "benign_windows_passed": benign_passed,
        "benign_pass_rate": benign_pass_rate,
        "total_windows": total_windows,
        "lstm_invocations": lstm_invocations,
        "lstm_skipped": lstm_skipped,
        "invocation_reduction_pct": reduction_pct,
    }


def compare_screening_thresholds(
    pipeline: TwoStageInferencePipeline,
    test_df: pd.DataFrame,
    thresholds: list[float] | None = None,
    lstm_alert_threshold: float = 0.85,
) -> dict[str, Any]:
    """Sensitivity analysis comparing legacy binary predict() gate against candidate IF continuous thresholds."""
    if thresholds is None:
        thresholds = [-0.188196, -0.167461, -0.109568, 0.0]

    # Pre-score all windows once with threshold=-999.0 so each window receives its full LSTM sequential score
    all_scored = pipeline.score_dataframe(test_df, if_screening_threshold=-999.0)
    y_true = all_scored["label"].to_numpy().astype(int)
    total_windows = len(all_scored)
    total_attack = int((y_true == 1).sum())
    total_benign = int((y_true == 0).sum())

    scores_all = all_scored["risk_score"].to_numpy()
    if_scores = all_scored["anomaly_score"].to_numpy()
    legacy_anom = all_scored["isolation_forest_legacy_anomalous"].to_numpy()

    def _eval_gate(is_anomalous_mask: np.ndarray, mode: str, if_thr: float) -> dict[str, Any]:
        # When screened out, LSTM is not invoked, risk score is 0.0, would_alert is False
        y_pred = np.where(is_anomalous_mask, (scores_all >= lstm_alert_threshold).astype(int), 0)
        final_scores = np.where(is_anomalous_mask, scores_all, 0.0)

        metrics = _calc_metrics(y_true, y_pred, scores=final_scores)
        lstm_invocations = int(is_anomalous_mask.sum())
        lstm_skipped = total_windows - lstm_invocations
        reduction_pct = float(lstm_skipped / total_windows * 100.0) if total_windows > 0 else 0.0

        attack_passed = int(((y_true == 1) & is_anomalous_mask).sum())
        benign_passed = int(((y_true == 0) & is_anomalous_mask).sum())
        if_screening_recall = float(attack_passed / total_attack) if total_attack > 0 else 0.0
        benign_pass_rate = float(benign_passed / total_benign) if total_benign > 0 else 0.0

        return {
            "metrics": metrics,
            "threshold": lstm_alert_threshold,
            "if_screening_threshold": if_thr,
            "if_screening_mode": mode,
            "if_screening_recall": if_screening_recall,
            "attack_windows_passed": attack_passed,
            "total_attack_windows": total_attack,
            "benign_windows_passed": benign_passed,
            "benign_pass_rate": benign_pass_rate,
            "total_windows": total_windows,
            "lstm_invocations": lstm_invocations,
            "lstm_skipped": lstm_skipped,
            "invocation_reduction_pct": reduction_pct,
        }

    baseline = _eval_gate(legacy_anom, "legacy_predict", 0.0)
    baseline["gate_description"] = "Baseline: binary predict() == -1 hard gate"

    candidate_results = []
    for thr in thresholds:
        mask = if_scores >= thr
        res = _eval_gate(mask, "continuous_score", thr)
        res["gate_description"] = f"Candidate continuous threshold: score >= {thr}"
        candidate_results.append(res)

    return {
        "baseline_legacy_gate": baseline,
        "candidate_thresholds": candidate_results,
        "methodology_disclaimer": (
            "Threshold sensitivity analysis on test split. "
            "These are sensitivity points, NOT final production performance claims."
        ),
    }


def benchmark_latencies(
    baseline_artifacts: dict[str, Any],
    lstm_infer: LSTMInfer,
    pipeline: TwoStageInferencePipeline,
    test_df: pd.DataFrame,
    n_samples: int = 300,
) -> dict[str, Any]:
    """Experiment 4: Measure inference latency and throughput across configurations."""
    sample = test_df.head(n_samples).copy()
    x_test, _ = vectorize(sample[list(baseline_artifacts["feature_names"])])
    model = baseline_artifacts["isolation_forest"]

    # 1. Isolation Forest latency
    t0 = time.perf_counter()
    model.predict(x_test)
    t1 = time.perf_counter()
    if_total_sec = t1 - t0
    if_per_window_ms = (if_total_sec / len(sample)) * 1000.0
    if_throughput = len(sample) / if_total_sec if if_total_sec > 0 else 0.0

    # 2. LSTM latency (scoring 30-step windows)
    t0 = time.perf_counter()
    for _, group in sample.groupby("computer", sort=False):
        history = []
        for _, row in group.iterrows():
            history.append(row.to_dict())
            seq_df = pd.DataFrame(history[-30:])
            for name in lstm_infer.feature_names:
                if name not in seq_df.columns:
                    seq_df[name] = 0.0
            lstm_infer.score_sequence(seq_df)
    t1 = time.perf_counter()
    lstm_total_sec = t1 - t0
    lstm_per_window_ms = (lstm_total_sec / len(sample)) * 1000.0
    lstm_throughput = len(sample) / lstm_total_sec if lstm_total_sec > 0 else 0.0

    # 3. Two-Stage Pipeline latency
    t0 = time.perf_counter()
    pipeline.score_dataframe(sample)
    t1 = time.perf_counter()
    two_stage_total_sec = t1 - t0
    two_stage_per_window_ms = (two_stage_total_sec / len(sample)) * 1000.0
    two_stage_throughput = len(sample) / two_stage_total_sec if two_stage_total_sec > 0 else 0.0

    speedup_vs_lstm = (lstm_total_sec / two_stage_total_sec) if two_stage_total_sec > 0 else 0.0

    return {
        "sample_windows_benchmarked": len(sample),
        "isolation_forest_alone": {
            "latency_ms_per_window": round(if_per_window_ms, 3),
            "throughput_windows_per_sec": round(if_throughput, 1),
        },
        "lstm_alone": {
            "latency_ms_per_window": round(lstm_per_window_ms, 3),
            "throughput_windows_per_sec": round(lstm_throughput, 1),
        },
        "two_stage_pipeline": {
            "latency_ms_per_window": round(two_stage_per_window_ms, 3),
            "throughput_windows_per_sec": round(two_stage_throughput, 1),
            "speedup_factor_vs_lstm_alone": round(speedup_vs_lstm, 2),
        },
    }


def analyze_detection_lead_time(test_df: pd.DataFrame) -> dict[str, Any]:
    """Experiment 5: Scientific audit of detection lead time vs encryption timestamps."""
    annotated_sources = {}
    if "encryption_start" in test_df.columns:
        valid = test_df.dropna(subset=["encryption_start"])
        if not valid.empty:
            for source, grp in valid.groupby("source"):
                annotated_sources[source] = str(grp["encryption_start"].iloc[0])

    if annotated_sources:
        return {
            "lead_time_measurable": True,
            "annotated_sources_count": len(annotated_sources),
            "sources": annotated_sources,
        }

    return {
        "lead_time_measurable": False,
        "reason": (
            "No ground-truth encryption start timestamps are annotated in the benchmark dataset. "
            "Detection lead time cannot be scientifically claimed without verified per-scenario "
            "key-exchange or file-rename start markers."
        ),
        "recommendation": (
            "Deploy Sysmon with FileCreate/FileDelete monitoring on canary directories during live VM "
            "detonations to capture verifiable pre-encryption lead time deltas."
        ),
    }


def run_all_experiments(
    dataset_path: Path = DEFAULT_DATASET,
    baseline_path: Path = DEFAULT_BASELINE,
    lstm_path: Path = DEFAULT_LSTM,
    output_report_path: Path = DEFAULT_OUTPUT,
    threshold: float = 0.85,
    sample_eval: int | None = None,
) -> dict[str, Any]:
    """Run all 5 evaluation experiments and write a comprehensive JSON report."""
    logger.info("Loading dataset from %s", dataset_path)
    df = pd.read_csv(dataset_path)

    logger.info("Splitting dataset by scenario (source-level split)...")
    splits = scenario_split(df, seed=42)
    test_df = splits["test"]
    logger.info(
        "Dataset split: train=%d, validation=%d, test=%d",
        len(splits["train"]), len(splits["validation"]), len(test_df),
    )

    if sample_eval and sample_eval < len(test_df):
        logger.info("Sampling %d windows from test set for quick evaluation...", sample_eval)
        test_df = test_df.head(sample_eval).copy()

    logger.info("Loading model artifacts...")
    baseline_artifacts = joblib.load(baseline_path)
    lstm_infer = LSTMInfer(lstm_path)
    pipeline = TwoStageInferencePipeline(
        baseline_path,
        lstm_infer=lstm_infer,
        lstm_alert_threshold=threshold,
    )

    logger.info("Running Experiment 1: Model 1 (Isolation Forest) Alone...")
    exp1 = eval_isolation_forest_alone(baseline_artifacts, test_df)

    logger.info("Running Experiment 2: Model 2 (LSTM) Alone...")
    exp2 = eval_lstm_alone(lstm_infer, test_df, threshold=threshold)

    logger.info("Running Experiment 3: Two-Stage Pipeline (IF -> LSTM)...")
    exp3 = eval_two_stage_pipeline(pipeline, test_df, threshold=threshold)

    logger.info("Running Experiment 4: Latency & Throughput Benchmark...")
    exp4 = benchmark_latencies(baseline_artifacts, lstm_infer, pipeline, test_df, n_samples=min(200, len(test_df)))

    logger.info("Running Experiment 5: Detection Lead-Time Analysis...")
    logger.info("Running Screening Threshold Sensitivity Analysis (Baseline vs Candidates)...")
    exp3_sensitivity = compare_screening_thresholds(pipeline, test_df, lstm_alert_threshold=threshold)

    report = {
        "metadata": {
            "dataset": str(dataset_path.name),
            "test_windows_evaluated": len(test_df),
            "attack_windows": int(test_df["label"].sum()),
            "benign_windows": int(len(test_df) - test_df["label"].sum()),
            "threshold": threshold,
            "if_screening_threshold": pipeline.if_screening_threshold,
            "canonical_feature_count": len(CANONICAL_FEATURE_NAMES),
        },
        "experiment_1_isolation_forest_alone": exp1,
        "experiment_2_lstm_alone": exp2,
        "experiment_3_two_stage_pipeline": exp3,
        "threshold_sensitivity_analysis": exp3_sensitivity,
        "experiment_4_computational_efficiency": exp4,
        "experiment_5_detection_lead_time": exp5,
    }

    output_report_path.parent.mkdir(parents=True, exist_ok=True)
    with output_report_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    logger.info("Evaluation report saved to %s", output_report_path)
    return report


def print_comparison_table(report: dict[str, Any]) -> None:
    """Print an academic markdown table comparing the three architectures."""
    m1 = report["experiment_1_isolation_forest_alone"]["metrics"]
    m2 = report["experiment_2_lstm_alone"]["metrics"]
    m3 = report["experiment_3_two_stage_pipeline"]["metrics"]
    eff = report["experiment_4_computational_efficiency"]
    meta = report["metadata"]

    print("\n" + "=" * 80)
    print("           BRDS-PEC TWO-STAGE PIPELINE EVALUATION REPORT")
    print("=" * 80)
    print(f"Evaluated on {meta['test_windows_evaluated']} test windows ({meta['attack_windows']} attack, {meta['benign_windows']} benign)\n")

    table = [
        ("| Metric", "| Model 1: IF Alone", "| Model 2: LSTM Alone", "| Two-Stage (IF -> LSTM) |"),
        ("|" + "-" * 25, "|" + "-" * 22, "|" + "-" * 22, "|" + "-" * 25 + "|"),
        (f"| Precision", f"| {m1['precision']:.4f}", f"| {m2['precision']:.4f}", f"| {m3['precision']:.4f} |"),
        (f"| Recall (Sensitivity)", f"| {m1['recall']:.4f}", f"| {m2['recall']:.4f}", f"| {m3['recall']:.4f} |"),
        (f"| F1-Score", f"| {m1['f1']:.4f}", f"| {m2['f1']:.4f}", f"| {m3['f1']:.4f} |"),
        (f"| False Positive Rate", f"| {m1['false_positive_rate']:.4f}", f"| {m2['false_positive_rate']:.4f}", f"| {m3['false_positive_rate']:.4f} |"),
        (f"| ROC-AUC", f"| {m1['roc_auc'] or 0.0:.4f}", f"| {m2['roc_auc'] or 0.0:.4f}", f"| {m3['roc_auc'] or 0.0:.4f} |"),
        (f"| True Positives", f"| {m1['true_positives']}", f"| {m2['true_positives']}", f"| {m3['true_positives']} |"),
        (f"| False Positives", f"| {m1['false_positives']}", f"| {m2['false_positives']}", f"| {m3['false_positives']} |"),
        (f"| False Negatives", f"| {m1['false_negatives']}", f"| {m2['false_negatives']}", f"| {m3['false_negatives']} |"),
        (f"| LSTM Invocations", f"| 0 (N/A)", f"| {meta['test_windows_evaluated']} (100%)", f"| {report['experiment_3_two_stage_pipeline']['lstm_invocations']} (-{report['experiment_3_two_stage_pipeline']['invocation_reduction_pct']:.1f}%) |"),
        (f"| Latency (ms/win)", f"| {eff['isolation_forest_alone']['latency_ms_per_window']:.2f} ms", f"| {eff['lstm_alone']['latency_ms_per_window']:.2f} ms", f"| {eff['two_stage_pipeline']['latency_ms_per_window']:.2f} ms |"),
        (f"| Throughput (win/s)", f"| {eff['isolation_forest_alone']['throughput_windows_per_sec']:.1f}", f"| {eff['lstm_alone']['throughput_windows_per_sec']:.1f}", f"| {eff['two_stage_pipeline']['throughput_windows_per_sec']:.1f} |"),
    ]

    for row in table:
        print(f"{row[0]:<26} {row[1]:<23} {row[2]:<23} {row[3]}")

    print("\n[Detection Lead Time Analysis]")
    lt = report["experiment_5_detection_lead_time"]
    print(f"Measurable: {lt['lead_time_measurable']}")
    print(f"Reason: {lt['reason']}")
    print("=" * 80 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate BRDS-PEC Experiments 1-5")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--lstm", type=Path, default=DEFAULT_LSTM)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--threshold", type=float, default=0.85)
    parser.add_argument("--sample", type=int, default=None, help="Sample N windows for fast test")
    args = parser.parse_args()

    report = run_all_experiments(
        dataset_path=args.dataset,
        baseline_path=args.baseline,
        lstm_path=args.lstm,
        output_report_path=args.output,
        threshold=args.threshold,
        sample_eval=args.sample,
    )
    print_comparison_table(report)


if __name__ == "__main__":
    main()
