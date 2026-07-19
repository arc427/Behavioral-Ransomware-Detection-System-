from backend.models import db

class Incident(db.Model):
    """SQLAlchemy model for Security Incident Alerts."""
    __tablename__ = 'incidents'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.String(100), nullable=False)
    computer = db.Column(db.String(100), nullable=False)
    ransomware_family = db.Column(db.String(100), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    process_id = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='ACTIVE')

    def to_dict(self) -> dict:
        return {
            'id': f"INC-{self.id}",
            'timestamp': self.timestamp,
            'computer': self.computer,
            'ransomware_family': self.ransomware_family,
            'risk_score': self.risk_score,
            'process_id': self.process_id,
            'status': self.status
        }
