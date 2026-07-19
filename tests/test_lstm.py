import tempfile
import torch
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from ml_engine.lstm.model import LSTMClassifier
from ml_engine.lstm.dataset import SequenceDataset
from ml_engine.lstm.infer import LSTMInfer

def test_lstm_model():
    batch_size = 4
    seq_len = 30
    input_dim = 15
    
    # Create random batch input
    x = torch.randn(batch_size, seq_len, input_dim)
    
    model = LSTMClassifier(input_dim=input_dim, hidden_dim=32, num_layers=2)
    out = model(x)
    
    assert out.shape == (batch_size, 1)
    assert torch.all(out >= 0.0)
    assert torch.all(out <= 1.0)

def test_sequence_dataset():
    # Build a dummy dataframe
    n_rows = 50
    df = pd.DataFrame({
        'computer': ['BRDS-WIN11-SEC'] * n_rows,
        'process_key': [f'cmd.exe:{i}' for i in range(n_rows)],
        'window_start': pd.date_range(start='2026-07-19T00:00:00', periods=n_rows, freq='5s').to_series().dt.strftime('%Y-%m-%dT%H:%M:%SZ').values,
        'label': np.random.randint(0, 2, size=n_rows),
        'technique_id': ['benign'] * n_rows,
        'scenario': ['benign'] * n_rows,
        'source': ['C:\\Windows\\System32\\benign-logs-1'] * n_rows,
        'feat1': np.random.randn(n_rows),
        'feat2': np.random.randn(n_rows)
    })
    
    features = ['feat1', 'feat2']
    dataset = SequenceDataset(df, features, seq_len=30, is_training=True)
    
    assert len(dataset) == n_rows
    
    # Check item types and shapes
    seq, label = dataset[0]
    assert seq.shape == (30, len(features))
    assert label.shape == (1,)
    assert isinstance(seq, torch.Tensor)
    assert isinstance(label, torch.Tensor)

def test_lstm_infer():
    # Setup dummy trained checkpoint
    scaler = StandardScaler()
    dummy_feats = np.random.randn(10, 2)
    scaler.fit(dummy_feats)
    
    model = LSTMClassifier(input_dim=2, hidden_dim=8, num_layers=1)
    
    checkpoint = {
        'model_state_dict': model.state_dict(),
        'scaler': scaler,
        'feature_names': ['feat1', 'feat2'],
        'input_dim': 2,
        'hidden_dim': 8,
        'num_layers': 1,
        'dropout': 0.2
    }
    
    # Save checkpoint to temporary file
    with tempfile.TemporaryDirectory() as tmpdir:
        checkpoint_path = Path(tmpdir) / "test_lstm_model.pth"
        torch.save(checkpoint, checkpoint_path)
        
        # Initialize inference engine
        infer = LSTMInfer(checkpoint_path)
        
        # Score a dummy sequence DataFrame
        df = pd.DataFrame({
            'window_start': ['2026-07-19T00:00:01Z', '2026-07-19T00:00:02Z'],
            'feat1': [1.0, -1.0],
            'feat2': [0.5, 1.5]
        })
        
        score = infer.score_sequence(df)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
