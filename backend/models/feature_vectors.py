import json
from backend.models import db

class FeatureVector(db.Model):
    """SQLAlchemy model for Aggregated Telemetry Feature Vectors."""
    __tablename__ = 'feature_vectors'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    computer = db.Column(db.String(100), nullable=False)
    process_key = db.Column(db.String(100), nullable=False)
    window_start = db.Column(db.String(100), nullable=False)
    label = db.Column(db.Integer, nullable=False)
    technique_id = db.Column(db.String(100), nullable=False)
    scenario = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(255), nullable=False)
    risk_score = db.Column(db.Float, nullable=True)
    anomaly_score = db.Column(db.Float, nullable=True)
    features_json = db.Column(db.Text, nullable=False) # Stores all vector counts flexibly

    def get_features(self) -> dict:
        try:
            return json.loads(self.features_json)
        except Exception:
            return {}

    def to_dict(self) -> dict:
        # Re-assemble metadata and vector counts
        res = {
            'computer': self.computer,
            'process_key': self.process_key,
            'window_start': self.window_start,
            'label': self.label,
            'technique_id': self.technique_id,
            'scenario': self.scenario,
            'source': self.source,
            'risk_score': self.risk_score,
            'anomaly_score': self.anomaly_score
        }
        res.update(self.get_features())
        return res
