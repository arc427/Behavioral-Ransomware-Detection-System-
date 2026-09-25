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

import torch
from backend.app import create_app

def test_api_explanation_db_query(app_client):
    # Query `/api/explanations/<alert_id>`
    # The alert_id can be the Incident timestamp
    alert_id = "2026-07-19T04:10:00Z"
    res = app_client.get(f'/api/explanations/{alert_id}')
    assert res.status_code == 200
    data = json.loads(res.data)
    
    assert data["alert_id"] == alert_id
    assert data["available"] is True
    assert len(data["attributions"]) > 0
    assert "feature_name" in data["attributions"][0]

def test_xai_error_sanitization(app_client):
    # Clear LSTM_INFER and set invalid MODEL_PATH to trigger exception fallback on dynamic explanation computation
    original_model_path = app_client.application.config.get("MODEL_PATH")
    original_lstm_infer = app_client.application.config.get("LSTM_INFER")
    app_client.application.config["LSTM_INFER"] = None
    app_client.application.config["MODEL_PATH"] = Path("/invalid/path/missing_model.joblib")
    
    alert_id = "2026-07-19T04:10:00Z"
    res = app_client.get(f'/api/explanations/{alert_id}')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["fallback"] is True
    assert "Explanation computation failed" in data["error"]
    # Ensure no absolute paths or tracebacks are leaked
    assert "C:\\" not in data["error"]
    assert "Traceback" not in data["error"]
    
    # Restore model configs
    app_client.application.config["MODEL_PATH"] = original_model_path
    app_client.application.config["LSTM_INFER"] = original_lstm_infer

def test_lstm_shap_explainer_directly():
    from ml_engine.lstm.model import LSTMClassifier
    from ml_engine.lstm.infer import LSTMInfer
    from ml_engine.xai.shap_explainer import LSTMSHAPExplainer
    
    with tempfile.TemporaryDirectory() as tmpdir:
        pth_path = Path(tmpdir) / "m.pth"
        model = LSTMClassifier(input_dim=2, hidden_dim=8, num_layers=1)
        checkpoint = {
            'model_state_dict': model.state_dict(),
            'feature_names': ['feat1', 'feat2'],
            'input_dim': 2,
            'hidden_dim': 8,
            'num_layers': 1,
            'dropout': 0.0
        }
        torch.save(checkpoint, pth_path)
        infer = LSTMInfer(pth_path)
        
        explainer = LSTMSHAPExplainer(infer)
        attrs = explainer.explain({"feat1": 1.0, "feat2": 2.0})
        
        assert len(attrs) == 2
        assert attrs[0]["feature_name"] in ["feat1", "feat2"]
        assert isinstance(attrs[0]["importance_value"], float)

def test_api_explanation_pdf_download(app_client):
    alert_id = "2026-07-19T04:10:00Z"
    res = app_client.get(f'/api/explanations/{alert_id}/pdf')
    assert res.status_code == 200
    assert res.content_type == "application/pdf"
    assert "attachment" in res.headers.get("Content-Disposition", "")
    assert len(res.data) > 100


def test_xai_attribution_sign_preservation(tmp_path):
    """Verify that positive and negative feature attributions preserve their signs after normalization."""
    # Create model with 1 positive coefficient and 1 negative coefficient
    import numpy as np
    scaler = StandardScaler()
    lr = LogisticRegression()
    # 2 features: feat_pos, feat_neg
    x_fake = np.array([[1.0, 10.0], [5.0, 2.0], [0.5, 8.0], [10.0, 1.0]])
    y_fake = np.array([0, 1, 0, 1])
    scaler.fit(x_fake)
    lr.fit(scaler.transform(x_fake), y_fake)
    
    # Explicitly set weights: +1.0 on feat1, -1.0 on feat2
    lr.coef_ = np.array([[1.5, -1.5]])
    lr.intercept_ = np.array([0.0])
    
    pipeline = Pipeline([("scale", scaler), ("model", lr)])
    model_path = tmp_path / "signed_model.joblib"
    joblib.dump({
        "feature_names": ["feat_pos", "feat_neg"],
        "isolation_forest": None,
        "supervised_model": pipeline
    }, model_path)
    
    explainer = SHAPExplainer(model_path)
    # Give high value to feat_pos (scaled > 0, coef > 0 => positive)
    # Give high value to feat_neg (scaled > 0, coef < 0 => negative)
    mean_vals = scaler.mean_
    feat_dict = {"feat_pos": mean_vals[0] + 5.0, "feat_neg": mean_vals[1] + 5.0}
    attributions = explainer.explain(feat_dict)
    
    attr_dict = {a["feature_name"]: a["importance_value"] for a in attributions}
    assert attr_dict["feat_pos"] > 0, "Positive risk-contributing feature must have positive attribution"
    assert attr_dict["feat_neg"] < 0, "Negative risk-reducing feature must have negative attribution"
    # Sum of absolute values should be 1.0
    total_abs = sum(abs(v) for v in attr_dict.values())
    assert pytest.approx(total_abs, rel=1e-3) == 1.0


def test_xai_provenance_flags_distinction(app_client):
    """Verify model-derived vs fallback explanations are clearly distinguishable."""
    alert_id = "2026-07-19T04:10:00Z"
    
    # 1. Model-derived success path
    res = app_client.get(f'/api/explanations/{alert_id}')
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("model_derived") is True
    assert data.get("fallback") in (False, None)
    
    # 2. Failure fallback path (clear cached DB logs so it forces dynamic computation with broken model path)
    from backend.models.explainability_logs import ExplainabilityLog
    with app_client.application.app_context():
        ExplainabilityLog.query.delete()
        db.session.commit()

    orig_path = app_client.application.config.get("MODEL_PATH")
    orig_infer = app_client.application.config.get("LSTM_INFER")
    app_client.application.config["LSTM_INFER"] = None
    app_client.application.config["MODEL_PATH"] = Path("/nonexistent/m.joblib")
    
    # Test error fallback specifically with missing model
    res_err = app_client.get(f'/api/explanations/{alert_id}')
    data_err = res_err.get_json()
    assert data_err.get("fallback") is True
    assert data_err.get("model_derived") is False
    assert data_err.get("provenance") == "heuristic_fallback_not_model_derived"
    assert "NOT MODEL-DERIVED" in data_err.get("warning", "")
    
    app_client.application.config["MODEL_PATH"] = orig_path
    app_client.application.config["LSTM_INFER"] = orig_infer


