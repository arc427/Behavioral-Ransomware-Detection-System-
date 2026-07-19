import sys
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app import create_app
from backend.models import db
# Import models to ensure they are registered with SQLAlchemy metadata
from backend.models.incidents import Incident
from backend.models.feature_vectors import FeatureVector
from backend.models.explainability_logs import ExplainabilityLog
from backend.models.raw_telemetry import RawTelemetry

def init_database() -> None:
    """Initialize SQLite database and create all tables."""
    app = create_app()
    with app.app_context():
        db_path = Path(app.config.get("DATABASE_PATH", ROOT / "data/brds.db"))
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"Initializing SQLite database at: {db_path}")
        db.create_all()
        print("All database tables created successfully.")

if __name__ == "__main__":
    init_database()
