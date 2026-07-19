import tempfile
from pathlib import Path
import json
import pytest
from backend.app import create_app
from backend.models import db
from backend.models.incidents import Incident
from backend.models.feature_vectors import FeatureVector

import os

@pytest.fixture
def app_client():
    # Setup temporary SQLite database for testing
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    
    app = create_app({
        'SQLALCHEMY_DATABASE_URI': f"sqlite:///{db_path}",
        'TESTING': True,
        'DATABASE_PATH': Path(db_path)
    })
    
    with app.app_context():
        db.create_all()
        
        # Seed test data
        v1 = FeatureVector(
            computer="TEST-WIN-1",
            process_key="svchost.exe:1010",
            window_start="2026-07-19T04:00:00Z",
            label=0,
            technique_id="benign",
            scenario="benign",
            source="C:\\Windows\\System32\\benign-logs-1",
            risk_score=0.05,
            anomaly_score=0.10,
            features_json='{"event_count": 5, "file_activity_count": 2}'
        )
        v2 = FeatureVector(
            computer="TEST-WIN-1",
            process_key="wannacry.exe:2020",
            window_start="2026-07-19T04:00:05Z",
            label=1,
            technique_id="T1486",
            scenario="wannacry",
            source="C:\\Malware\\wannacry-logs",
            risk_score=0.98,
            anomaly_score=0.88,
            features_json='{"event_count": 120, "file_activity_count": 85}'
        )
        db.session.add(v1)
        db.session.add(v2)
        
        inc1 = Incident(
            timestamp="2026-07-19T04:00:05Z",
            computer="TEST-WIN-1",
            ransomware_family="T1486",
            risk_score=0.98,
            process_id=2020,
            status="ACTIVE"
        )
        db.session.add(inc1)
        db.session.commit()
        
    with app.test_client() as client:
        yield client
        
    # Cleanup session and close database connections
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
        
    try:
        os.remove(db_path)
    except OSError:
        pass

def test_database_insert_retrieve(app_client):
    # Retrieve using raw queries inside app context
    with app_client.application.app_context():
        vectors = FeatureVector.query.all()
        assert len(vectors) == 2
        assert vectors[0].computer == "TEST-WIN-1"
        assert vectors[1].process_key == "wannacry.exe:2020"
        assert vectors[1].get_features()["file_activity_count"] == 85
        
        incidents = Incident.query.all()
        assert len(incidents) == 1
        assert incidents[0].ransomware_family == "T1486"
        assert incidents[0].to_dict()["id"] == "INC-1"

def test_api_telemetry_db_query(app_client):
    # Query /api/telemetry via REST API
    res = app_client.get('/api/telemetry?limit=5')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["total"] == 2
    assert len(data["items"]) == 2
    assert data["items"][0]["process_key"] == "svchost.exe:1010"
    assert data["items"][0]["event_count"] == 5
    assert data["items"][1]["file_activity_count"] == 85

def test_api_alerts_db_query(app_client):
    # Query /api/alerts via REST API
    res = app_client.get('/api/alerts')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["total"] == 1
    assert data["items"][0]["id"] == "INC-1"
    assert data["items"][0]["ransomware_family"] == "T1486"
    assert data["items"][0]["risk_score"] == 0.98
