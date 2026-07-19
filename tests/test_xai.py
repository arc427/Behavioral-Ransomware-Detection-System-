import tempfile
from pathlib import Path
import json
import pytest
import os
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from backend.app import create_app
from backend.models import db
from backend.models.incidents import Incident
from backend.models.feature_vectors import FeatureVector
from ml_engine.xai.shap_explainer import SHAPExplainer

@pytest.fixture
def app_client():
    # Setup temporary SQLite database and fake model for testing
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    
    model_fd, model_path = tempfile.mkstemp(suffix=".joblib")
    os.close(model_fd)
    
    # Create a simple trained model to avoid missing file errors
    scaler = StandardScaler()
    lr = LogisticRegression()
    # 2 features: event_count, file_activity_count
    import numpy as np
    x_fake = np.array([[1.0, 2.0], [5.0, 10.0], [0.5, 1.0], [10.0, 20.0]])
    y_fake = np.array([0, 1, 0, 1])
    scaler.fit(x_fake)
    lr.fit(scaler.transform(x_fake), y_fake)
    pipeline = Pipeline([("scale", scaler), ("model", lr)])
    
    artifacts = {
        "feature_names": ["event_count", "file_activity_count"],
        "isolation_forest": None,
        "supervised_model": pipeline
    }
    joblib.dump(artifacts, model_path)
    
    app = create_app({
        'SQLALCHEMY_DATABASE_URI': f"sqlite:///{db_path}",
        'TESTING': True,
        'DATABASE_PATH': Path(db_path),
        'MODEL_PATH': Path(model_path)
    })
    
    with app.app_context():
        db.create_all()
        
        # Seed test data
        v = FeatureVector(
            computer="TEST-WIN-XAI",
            process_key="ryuk.exe:3333",
            window_start="2026-07-19T04:10:00Z",
            label=1,
            technique_id="T1486",
            scenario="ryuk",
            source="C:\\Malware\\ryuk-logs",
            risk_score=0.95,
            anomaly_score=0.75,
            features_json='{"event_count": 55, "file_activity_count": 42}'
        )
        db.session.add(v)
        
        inc = Incident(
            timestamp="2026-07-19T04:10:00Z",
            computer="TEST-WIN-XAI",
            ransomware_family="T1486",
            risk_score=0.95,
            process_id=3333,
            status="ACTIVE"
        )
        db.session.add(inc)
        db.session.commit()
        
    with app.test_client() as client:
        yield client
        
    # Cleanup session and close database connections
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
        
    try:
        os.remove(db_path)
        os.remove(model_path)
    except OSError:
        pass

def test_shap_explainer_directly(app_client):
    model_path = app_client.application.config.get("MODEL_PATH")
    explainer = SHAPExplainer(model_path)
    
    feat_dict = {"event_count": 55, "file_activity_count": 42}
    attributions = explainer.explain(feat_dict)
    
    assert len(attributions) == 2
    assert attributions[0]["feature_name"] in ["event_count", "file_activity_count"]
    assert isinstance(attributions[0]["importance_value"], float)

def test_api_explanation_db_query(app_client):
    # Query `/api/explanations/<alert_id>`
    # The alert_id can be the Incident timestamp
    alert_id = "2026-07-19T04:10:00Z"
    res = app_client.get(f'/api/explanations/{alert_id}')
    assert res.status_code == 200
    data = json.loads(res.data)
    
    assert data["alert_id"] == alert_id
    assert data["available"] is True
    assert len(data["attributions"]) == 2
    assert data["attributions"][0]["feature_name"] in ["event_count", "file_activity_count"]
