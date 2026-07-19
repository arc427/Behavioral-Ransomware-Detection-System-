import tempfile
from pathlib import Path
import json
import pytest
import os
import joblib
import torch
import numpy as np
from backend.app import create_app
from backend.models import db
from backend.models.incidents import Incident
from backend.models.feature_vectors import FeatureVector

@pytest.fixture
def app_client():
    # Setup temporary SQLite database and fake model/scaler pth file for testing
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    
    lstm_fd, lstm_path = tempfile.mkstemp(suffix=".pth")
    os.close(lstm_fd)
    
    # Save a fake PyTorch checkpoint for LSTMInfer to load
    # To keep it extremely light and fast, we can save mock scaler parameters and model weights
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    # 17 features
    x_fake = np.zeros((10, 17))
    scaler.fit(x_fake)
    
    # We serialize the state dictionary for our LSTM model
    from ml_engine.lstm.model import LSTMClassifier
    model = LSTMClassifier(input_dim=17, hidden_dim=8, num_layers=1, dropout=0.0)
    
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "scaler": scaler,
        "feature_names": [
            'event_count', 'unique_images', 'unique_files', 'unique_extensions',
            'unique_destination_ips', 'suspicious_path_count', 'file_activity_count',
            'registry_activity_count', 'network_activity_count', 'event_1_count',
            'event_3_count', 'event_7_count', 'event_11_count', 'event_12_count',
            'event_13_count', 'event_23_count', 'event_26_count'
        ],
        "input_dim": 17,
        "hidden_dim": 8,
        "num_layers": 1,
        "dropout": 0.0
    }
    torch.save(checkpoint, lstm_path)
    
    alerts_fd, alerts_path = tempfile.mkstemp(suffix=".json")
    os.close(alerts_fd)
    Path(alerts_path).write_text("[]", encoding="utf-8")
    
    app = create_app({
        'SQLALCHEMY_DATABASE_URI': f"sqlite:///{db_path}",
        'TESTING': True,
        'DATABASE_PATH': Path(db_path),
        'LSTM_MODEL_PATH': Path(lstm_path),
        'ALERTS_PATH': Path(alerts_path)
    })
    
    with app.app_context():
        db.create_all()
        
    with app.test_client() as client:
        yield client
        
    # Cleanup session and close database connections
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
        
    try:
        os.remove(db_path)
        os.remove(lstm_path)
        os.remove(alerts_path)
    except OSError:
        pass

def test_lstm_live_scoring_low_risk(app_client):
    # Ingest benign telemetry window (all zero features)
    features = {
        'event_count': 0, 'unique_images': 0, 'unique_files': 0, 'unique_extensions': 0,
        'unique_destination_ips': 0, 'suspicious_path_count': 0, 'file_activity_count': 0,
        'registry_activity_count': 0, 'network_activity_count': 0, 'event_1_count': 0,
        'event_3_count': 0, 'event_7_count': 0, 'event_11_count': 0, 'event_12_count': 0,
        'event_13_count': 0, 'event_23_count': 0, 'event_26_count': 0
    }
    
    # Force low risk output by setting bias negative
    lstm_infer = app_client.application.config.get("LSTM_INFER")
    if lstm_infer:
        lstm_infer.model.fc.bias.data.fill_(-5.0)
        lstm_infer.model.fc.weight.data.fill_(0.0)

    payload = {
        "computer": "TEST-HOST-BENIGN",
        "process_key": "svchost.exe:1010",
        "window_start": "2026-07-19T04:20:00Z",
        "label": 0,
        "technique_id": "benign",
        "scenario": "benign",
        "source": "live-logs",
        "features": features
    }
    
    res = app_client.post('/api/score/live', json=payload)
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["status"] == "success"
    assert data["risk_score"] < 0.85
    assert data["containment_triggered"] is False

def test_lstm_live_scoring_high_risk(app_client):
    # Seed 29 steps in FeatureVector database to fill the sequence
    with app_client.application.app_context():
        import json
        for i in range(29):
            v = FeatureVector(
                computer="TEST-HOST-ATTACK",
                process_key="wannacry.exe:2020",
                window_start=f"2026-07-19T04:20:{i:02d}Z",
                label=1,
                technique_id="T1486",
                scenario="wannacry",
                source="live-logs",
                features_json='{"event_count": 500, "file_activity_count": 450}'
            )
            db.session.add(v)
        db.session.commit()

    # Post step 30 (high risk ransomware indicators)
    features = {
        'event_count': 600, 'unique_images': 2, 'unique_files': 500, 'unique_extensions': 5,
        'unique_destination_ips': 1, 'suspicious_path_count': 2, 'file_activity_count': 550,
        'registry_activity_count': 10, 'network_activity_count': 5, 'event_1_count': 2,
        'event_3_count': 5, 'event_7_count': 0, 'event_11_count': 500, 'event_12_count': 5,
        'event_13_count': 5, 'event_23_count': 10, 'event_26_count': 0
    }
    
    # Force high risk output by setting bias positive
    lstm_infer = app_client.application.config.get("LSTM_INFER")
    if lstm_infer:
        lstm_infer.model.fc.bias.data.fill_(5.0)
        lstm_infer.model.fc.weight.data.fill_(0.5)

    payload = {
        "computer": "TEST-HOST-ATTACK",
        "process_key": "wannacry.exe:2020",
        "window_start": "2026-07-19T04:20:30Z",
        "label": 1,
        "technique_id": "T1486",
        "scenario": "wannacry",
        "source": "live-logs",
        "features": features
    }
    
    # Send post request
    res = app_client.post('/api/score/live', json=payload)
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["status"] == "success"
    
    # Query incidents to make sure it triggered a database alert
    with app_client.application.app_context():
        incidents = Incident.query.filter_by(computer="TEST-HOST-ATTACK").all()
        assert len(incidents) == 1
        assert incidents[0].computer == "TEST-HOST-ATTACK"
        assert incidents[0].ransomware_family == "T1486"
        assert incidents[0].status == "ACTIVE"
        
        # Verify it appended alert to JSON path
        alerts_path = Path(app_client.application.config["ALERTS_PATH"])
        alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
        assert len(alerts) == 1
        assert alerts[0]["computer"] == "TEST-HOST-ATTACK"
        assert alerts[0]["technique_id"] == "T1486"
