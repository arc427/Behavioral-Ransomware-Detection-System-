from backend.models import db

class ExplainabilityLog(db.Model):
    """SQLAlchemy model for SHAP Feature Importance Explanations."""
    __tablename__ = 'explainability_logs'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_id = db.Column(db.String(100), nullable=False)
    feature_name = db.Column(db.String(100), nullable=False)
    importance_value = db.Column(db.Float, nullable=False)

    def to_dict(self) -> dict:
        return {
            'alert_id': self.alert_id,
            'feature_name': self.feature_name,
            'importance_value': self.importance_value
        }
