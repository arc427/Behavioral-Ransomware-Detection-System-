from backend.models import db

class RawTelemetry(db.Model):
    """SQLAlchemy model for Raw Event Log Metadata."""
    __tablename__ = 'raw_telemetry'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    computer = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.String(100), nullable=False)
    event_id = db.Column(db.Integer, nullable=False)
    payload = db.Column(db.Text, nullable=False) # JSON-serialized raw event fields

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'computer': self.computer,
            'timestamp': self.timestamp,
            'event_id': self.event_id,
            'payload': self.payload
        }
