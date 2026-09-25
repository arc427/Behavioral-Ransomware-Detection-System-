"""Canonical Isolation Forest -> LSTM sequential inference for live and replay paths."""

from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

import joblib
import pandas as pd

from ml_engine.isolation_forest.infer import anomaly_scores
from ml_engine.lstm.infer import LSTMInfer
from pipeline.vectorizer import CANONICAL_FEATURE_NAMES, validate_feature_schema

# LSTM alert threshold used by the previous live scorer and scripts/score_windows.py.
DEFAULT_LSTM_ALERT_THRESHOLD = 0.85

# Tier-1 Isolation Forest continuous screening threshold.
# PROVISIONAL CALIBRATION CANDIDATE — NOT a validated production threshold.
# Derived from sensitivity analysis on the held-out test split.
# Calibrate on target environment data before production deployment.
DEFAULT_IF_SCREENING_THRESHOLD = -0.167461

logger = logging.getLogger(__name__)

HistoryLoader = Callable[[], list[dict[str, Any]]]


@dataclass
class WindowInferenceResult:
    """Structured two-stage decision for one behavioural window."""

    window_start: str
    computer: str
    process_key: str
    anomaly_score: float
    isolation_forest_anomalous: bool
    isolation_forest_decision: str
    lstm_invoked: bool
    lstm_score: float | None
    lstm_decision: str
    lstm_sequence_windows: int | None
    final_risk_score: float
    would_alert: bool
    skip_reason: str | None
    models: dict[str, str | None]
    if_screening_threshold: float = DEFAULT_IF_SCREENING_THRESHOLD
    isolation_forest_legacy_anomalous: bool = False
    isolation_forest_legacy_prediction: int = 1

    def to_log_dict(self) -> dict[str, Any]:
        """Safe fields for application logging (no secrets)."""
        return asdict(self)

    def to_api_dict(self) -> dict[str, Any]:
        return {
            "anomaly_score": self.anomaly_score,
            "if_screening_threshold": self.if_screening_threshold,
            "isolation_forest_anomalous": self.isolation_forest_anomalous,
            "isolation_forest_decision": self.isolation_forest_decision,
            "isolation_forest_legacy_anomalous": self.isolation_forest_legacy_anomalous,
            "lstm_invoked": self.lstm_invoked,
            "lstm_score": self.lstm_score,
            "lstm_decision": self.lstm_decision,
            "lstm_sequence_windows": self.lstm_sequence_windows,
            "final_risk_score": self.final_risk_score,
            "would_alert": self.would_alert,
            "skip_reason": self.skip_reason,
            "models": self.models,
        }


def _flatten_window(window: dict[str, Any]) -> dict[str, Any]:
    """Merge nested ``features`` into a flat window dict without dropping identifiers."""
    flat = dict(window)
    nested = flat.get("features")
    if isinstance(nested, dict):
        for key, value in nested.items():
            if key not in flat or flat[key] is None:
                flat[key] = value
    return flat


def _isolation_forest_contamination(estimator: Any) -> str | None:
    """Read contamination from the fitted sklearn IsolationForest if present."""
    model = estimator
    named_steps = getattr(estimator, "named_steps", None)
    if named_steps and "model" in named_steps:
        model = named_steps["model"]
    contamination = getattr(model, "contamination", None)
    return None if contamination is None else str(contamination)


class TwoStageInferencePipeline:
    """
    Tier 1: Isolation Forest screens the current behavioural window.
    Tier 2: LSTM sequence classifier runs only when Tier 1 labels the window anomalous.

    Isolation Forest screening gate (live)
    ---------------------------------------
    The live Tier-1 gate uses the **continuous anomaly score** (higher = more
    suspicious, computed as ``-decision_function()``) compared against a
    configurable screening threshold (``BRDS_IF_SCREENING_THRESHOLD``).

    The sklearn binary ``predict()`` call (``-1`` = anomalous, ``+1`` = normal)
    is **retained for audit comparison only** and does NOT control the live
    screening decision.  Set ``use_legacy_predict_gate=True`` to restore the
    old binary gate for controlled baseline comparisons.

    The provisional default threshold is a **calibration candidate** derived
    from sensitivity analysis on the held-out test split.  It is NOT a
    validated production threshold.  Calibrate on target environment data.

    LSTM alerting uses ``DEFAULT_LSTM_ALERT_THRESHOLD`` (0.85).

    Feature schema
    --------------
    Both models must share the same 17 canonical features defined in
    ``pipeline.vectorizer.CANONICAL_FEATURE_NAMES``.  On load, the pipeline:
      - Warns if either model's stored feature list diverges from the canonical schema.
      - Warns (or raises, if ``strict_schema=True``) if the IF and LSTM feature lists
        differ from each other.
    During inference, missing features are filled with 0 and logged at DEBUG level.
    Set ``strict_schema=True`` to raise instead of filling, e.g. in tests.
    """

    def __init__(
        self,
        baseline_model_path: str | Path,
        lstm_infer: LSTMInfer | None = None,
        lstm_model_path: str | Path | None = None,
        lstm_alert_threshold: float = DEFAULT_LSTM_ALERT_THRESHOLD,
        if_screening_threshold: float | None = None,
        use_legacy_predict_gate: bool = False,
        strict_schema: bool = False,
    ):
        path = Path(baseline_model_path)
        self.baseline_model_path = path
        self.artifacts = joblib.load(path)
        self.feature_names: list[str] = list(self.artifacts["feature_names"])
        self.isolation_forest = self.artifacts["isolation_forest"]
        self.lstm_alert_threshold = lstm_alert_threshold
        self.use_legacy_predict_gate = use_legacy_predict_gate
        self.strict_schema = strict_schema

        if if_screening_threshold is not None:
            self.if_screening_threshold = float(if_screening_threshold)
        else:
            env_val = os.environ.get("BRDS_IF_SCREENING_THRESHOLD") or os.environ.get("IF_SCREENING_THRESHOLD")
            if env_val is not None:
                try:
                    self.if_screening_threshold = float(env_val)
                except ValueError:
                    logger.warning(
                        "Invalid IF_SCREENING_THRESHOLD env var '%s'; using default %s",
                        env_val,
                        DEFAULT_IF_SCREENING_THRESHOLD,
                    )
                    self.if_screening_threshold = DEFAULT_IF_SCREENING_THRESHOLD
            else:
                self.if_screening_threshold = DEFAULT_IF_SCREENING_THRESHOLD

        lstm_path = Path(lstm_model_path) if lstm_model_path else None
        if lstm_infer is not None:
            self.lstm_infer = lstm_infer
        elif lstm_path is not None and lstm_path.exists():
            self.lstm_infer = LSTMInfer(lstm_path)
        else:
            self.lstm_infer = None

        # ── Schema validation ─────────────────────────────────────────────────
        # 1. Each model's stored feature list vs the canonical 17-feature schema.
        if_missing = validate_feature_schema(self.feature_names, strict=False)
        if if_missing:
            logger.warning(
                "Isolation Forest artifact is missing canonical features: %s", if_missing
            )

        schema_aligned = True
        if self.lstm_infer is not None:
            lstm_missing = validate_feature_schema(
                self.lstm_infer.feature_names, strict=False
            )
            if lstm_missing:
                logger.warning(
                    "LSTM checkpoint is missing canonical features: %s", lstm_missing
                )
            # 2. IF feature list vs LSTM feature list must match exactly.
            if list(self.feature_names) != list(self.lstm_infer.feature_names):
                schema_aligned = False
                msg = (
                    f"Feature mismatch between Isolation Forest "
                    f"({self.feature_names}) and LSTM ({self.lstm_infer.feature_names})"
                )
                if strict_schema:
                    raise ValueError(msg)
                logger.warning(msg)

        self.models_meta: dict[str, str | None] = {
            "isolation_forest": path.name,
            "isolation_forest_contamination": _isolation_forest_contamination(
                self.isolation_forest
            ),
            "if_screening_threshold": str(self.if_screening_threshold),
            "if_screening_mode": "legacy_predict" if use_legacy_predict_gate else "continuous_score",
            "lstm": lstm_path.name if lstm_path else None,
            "lstm_alert_threshold": str(lstm_alert_threshold),
            "schema_aligned": str(schema_aligned),
            "feature_count": str(len(self.feature_names)),
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _feature_row(self, window: dict[str, Any]) -> pd.DataFrame:
        """Build a single-row DataFrame for the Isolation Forest stage.

        Any feature in the IF contract that is absent or None in ``window`` is
        filled with 0.  Missing features are logged at DEBUG; with
        ``strict_schema=True`` a ValueError is raised instead.
        """
        missing = [
            name
            for name in self.feature_names
            if name not in window or window.get(name) is None
        ]
        if missing:
            if self.strict_schema:
                raise ValueError(f"Window missing required features: {missing}")
            logger.debug("Window missing IF features (filled with 0): %s", missing)
        row = {name: float(window.get(name, 0) or 0) for name in self.feature_names}
        return pd.DataFrame([row], columns=self.feature_names)

    def _isolation_forest_stage(
        self,
        window: dict[str, Any],
        threshold_override: float | None = None,
        legacy_gate_override: bool | None = None,
    ) -> tuple[float, bool, str, float, bool, int]:
        features = self._feature_row(window)
        score = float(anomaly_scores(self.isolation_forest, features).iloc[0])
        legacy_prediction = int(self.isolation_forest.predict(features)[0])
        legacy_anomalous = legacy_prediction == -1

        threshold = (
            threshold_override
            if threshold_override is not None
            else self.if_screening_threshold
        )
        use_legacy = (
            legacy_gate_override
            if legacy_gate_override is not None
            else self.use_legacy_predict_gate
        )

        if use_legacy:
            anomalous = legacy_anomalous
        else:
            anomalous = score >= threshold

        decision = "anomalous" if anomalous else "normal"
        return score, anomalous, decision, threshold, legacy_anomalous, legacy_prediction

    def _lstm_sequence_frame(self, rows: list[dict[str, Any]]) -> pd.DataFrame:
        """Build the multi-row DataFrame for LSTM scoring.

        Columns required by the LSTM that are absent from the history rows are
        added as 0.  Missing columns are logged at DEBUG; with
        ``strict_schema=True`` a ValueError is raised instead.
        """
        frame = pd.DataFrame(rows)
        if self.lstm_infer is None:
            return frame
        missing_cols = [
            name
            for name in self.lstm_infer.feature_names
            if name not in frame.columns
        ]
        if missing_cols:
            if self.strict_schema:
                raise ValueError(
                    f"LSTM sequence frame missing features: {missing_cols}"
                )
            logger.debug(
                "LSTM sequence frame missing columns (filled with 0): %s", missing_cols
            )
            for name in missing_cols:
                frame[name] = 0.0
        return frame

    # ── Public inference API ──────────────────────────────────────────────────

    def evaluate_window(
        self,
        window: dict[str, Any],
        history: list[dict[str, Any]] | None = None,
        history_loader: HistoryLoader | None = None,
        if_screening_threshold: float | None = None,
        use_legacy_predict_gate: bool | None = None,
    ) -> WindowInferenceResult:
        """Run Isolation Forest first; invoke LSTM only if that stage is anomalous."""
        window = _flatten_window(window)
        window_start = str(window.get("window_start", ""))
        computer = str(window.get("computer", ""))
        process_key = str(window.get("process_key", ""))

        (
            anomaly_score,
            if_anomalous,
            if_decision,
            effective_threshold,
            legacy_anomalous,
            legacy_prediction,
        ) = self._isolation_forest_stage(
            window,
            threshold_override=if_screening_threshold,
            legacy_gate_override=use_legacy_predict_gate,
        )

        lstm_invoked = False
        lstm_score: float | None = None
        lstm_decision = "skipped"
        lstm_sequence_windows: int | None = None
        skip_reason: str | None = None
        final_risk = 0.0
        would_alert = False

        if not if_anomalous:
            skip_reason = "isolation_forest_normal"
        elif self.lstm_infer is None:
            skip_reason = "lstm_unavailable"
        else:
            sequence_rows: list[dict[str, Any]] = []
            if history is not None:
                recent = history[-29:] if len(history) > 29 else history
                sequence_rows = [_flatten_window(row) for row in recent]
            elif history_loader is not None:
                loaded = history_loader() or []
                recent = loaded[-29:] if len(loaded) > 29 else loaded
                sequence_rows = [_flatten_window(row) for row in recent]
            if not sequence_rows:
                sequence_rows = [window]
            elif sequence_rows[-1].get("window_start") != window_start:
                sequence_rows = sequence_rows + [window]

            sequence_df = self._lstm_sequence_frame(sequence_rows)
            lstm_sequence_windows = len(sequence_df)
            lstm_invoked = True
            lstm_score = float(self.lstm_infer.score_sequence(sequence_df))
            lstm_decision = (
                "malicious" if lstm_score >= self.lstm_alert_threshold else "benign"
            )
            final_risk = lstm_score
            would_alert = lstm_score >= self.lstm_alert_threshold

        models = dict(self.models_meta)
        models["if_screening_threshold"] = str(effective_threshold)
        if self.lstm_infer is not None and models.get("lstm") is None:
            models["lstm"] = "lstm_infer"

        result = WindowInferenceResult(
            window_start=window_start,
            computer=computer,
            process_key=process_key,
            anomaly_score=anomaly_score,
            isolation_forest_anomalous=if_anomalous,
            isolation_forest_decision=if_decision,
            lstm_invoked=lstm_invoked,
            lstm_score=lstm_score,
            lstm_decision=lstm_decision,
            lstm_sequence_windows=lstm_sequence_windows,
            final_risk_score=final_risk,
            would_alert=would_alert,
            skip_reason=skip_reason,
            models=models,
            if_screening_threshold=effective_threshold,
            isolation_forest_legacy_anomalous=legacy_anomalous,
            isolation_forest_legacy_prediction=legacy_prediction,
        )
        logger.info("two_stage_inference %s", result.to_log_dict())
        return result

    def score_dataframe(
        self,
        windows: pd.DataFrame,
        if_screening_threshold: float | None = None,
        use_legacy_predict_gate: bool | None = None,
    ) -> pd.DataFrame:
        """Score all windows in chronological order per host (replay / batch)."""
        if windows.empty:
            return windows.copy()

        frame = windows.copy()
        if "window_start" in frame.columns:
            frame["_sort_time"] = pd.to_datetime(
                frame["window_start"], utc=True, errors="coerce"
            )
        else:
            frame["_sort_time"] = pd.RangeIndex(len(frame))

        results: list[dict[str, Any]] = []
        for _, group in frame.groupby("computer", sort=False):
            ordered = group.sort_values("_sort_time")
            history: list[dict[str, Any]] = []
            for _, row in ordered.iterrows():
                window = row.to_dict()
                inference = self.evaluate_window(
                    window,
                    history=history,
                    if_screening_threshold=if_screening_threshold,
                    use_legacy_predict_gate=use_legacy_predict_gate,
                )
                history.append(window)
                enriched = window.copy()
                enriched["anomaly_score"] = inference.anomaly_score
                enriched["if_screening_threshold"] = inference.if_screening_threshold
                enriched["isolation_forest_anomalous"] = inference.isolation_forest_anomalous
                enriched["isolation_forest_decision"] = inference.isolation_forest_decision
                enriched["isolation_forest_legacy_anomalous"] = inference.isolation_forest_legacy_anomalous
                enriched["lstm_invoked"] = inference.lstm_invoked
                enriched["lstm_score"] = inference.lstm_score
                enriched["lstm_decision"] = inference.lstm_decision
                enriched["lstm_sequence_windows"] = inference.lstm_sequence_windows
                enriched["risk_score"] = inference.final_risk_score
                enriched["would_alert"] = inference.would_alert
                enriched["pipeline_skip_reason"] = inference.skip_reason
                enriched["mode"] = "dry_run"
                results.append(enriched)

        scored = pd.DataFrame(results)
        if "_sort_time" in scored.columns:
            scored = scored.drop(columns=["_sort_time"])
        return scored
