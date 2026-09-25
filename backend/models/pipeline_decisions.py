"""Durable audit log for two-stage pipeline decisions.

One row is written for every window evaluated by TwoStageInferencePipeline,
whether or not it triggers an alert.  This table is the research ground truth
for Experiments 1-5 (Stage D).
"""

from __future__ import annotations

from backend.models import db


class PipelineDecision(db.Model):
    """Per-window two-stage inference audit record."""

    __tablename__ = "pipeline_decisions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Window identity
    window_start = db.Column(db.String(100), nullable=False, index=True)
    computer = db.Column(db.String(100), nullable=False, index=True)
    process_key = db.Column(db.String(200), nullable=False)

    # Tier-1: Isolation Forest
    anomaly_score = db.Column(db.Float, nullable=False)
    isolation_forest_decision = db.Column(db.String(20), nullable=False)  # "normal" | "anomalous"
    isolation_forest_anomalous = db.Column(db.Boolean, nullable=False)
    if_screening_threshold = db.Column(db.Float, nullable=True)
    if_legacy_anomalous = db.Column(db.Boolean, nullable=True)

    # Tier-2: LSTM (nullable — not run when IF says normal)
    lstm_invoked = db.Column(db.Boolean, nullable=False, default=False)
    lstm_score = db.Column(db.Float, nullable=True)
    lstm_decision = db.Column(db.String(20), nullable=True)   # "malicious" | "benign" | "skipped"
    lstm_sequence_windows = db.Column(db.Integer, nullable=True)

    # Final decision
    final_risk_score = db.Column(db.Float, nullable=False, default=0.0)
    would_alert = db.Column(db.Boolean, nullable=False, default=False)
    skip_reason = db.Column(db.String(50), nullable=True)  # "isolation_forest_normal" | "lstm_unavailable"

    # Model provenance (no secret values stored here)
    if_model_artifact = db.Column(db.String(200), nullable=True)
    lstm_model_artifact = db.Column(db.String(200), nullable=True)
    lstm_alert_threshold = db.Column(db.Float, nullable=True)
    schema_aligned = db.Column(db.Boolean, nullable=True)

    # Source metadata
    source = db.Column(db.String(255), nullable=True)
    technique_id = db.Column(db.String(100), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "window_start": self.window_start,
            "computer": self.computer,
            "process_key": self.process_key,
            "anomaly_score": self.anomaly_score,
            "isolation_forest_decision": self.isolation_forest_decision,
            "isolation_forest_anomalous": self.isolation_forest_anomalous,
            "if_screening_threshold": self.if_screening_threshold,
            "if_legacy_anomalous": self.if_legacy_anomalous,
            "lstm_invoked": self.lstm_invoked,
            "lstm_score": self.lstm_score,
            "lstm_decision": self.lstm_decision,
            "lstm_sequence_windows": self.lstm_sequence_windows,
            "final_risk_score": self.final_risk_score,
            "would_alert": self.would_alert,
            "skip_reason": self.skip_reason,
            "if_model_artifact": self.if_model_artifact,
            "lstm_model_artifact": self.lstm_model_artifact,
            "lstm_alert_threshold": self.lstm_alert_threshold,
            "schema_aligned": self.schema_aligned,
            "source": self.source,
            "technique_id": self.technique_id,
        }
