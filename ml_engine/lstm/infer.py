import torch
import pandas as pd
import numpy as np
from pathlib import Path
from ml_engine.lstm.model import LSTMClassifier

import hashlib
import joblib

class LSTMInfer:
    """Wrapper class to load trained LSTM model securely and run real-time inference."""
    
    def __init__(self, model_path: str | Path):
        path = Path(model_path)
        
        # Verify SHA-256 checksum if hash manifest exists
        hash_path = path.with_suffix('.sha256')
        if hash_path.exists():
            expected_hash = hash_path.read_text(encoding="utf-8").strip()
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise RuntimeError(
                    f"Model checkpoint integrity check failed! File: {path}\n"
                    f"Expected SHA-256: {expected_hash}\nActual SHA-256: {actual_hash}"
                )
                
        # Secure deserialization: load tensors only to prevent RCE
        checkpoint = torch.load(path, map_location=torch.device('cpu'), weights_only=True)
        self.feature_names = checkpoint['feature_names']
        
        # Load scaler from sidecar file or fallback
        scaler_path = path.with_suffix('.scaler.joblib')
        if scaler_path.exists():
            self.scaler = joblib.load(scaler_path)
        else:
            self.scaler = checkpoint.get('scaler', None)
            
        self.input_dim = checkpoint['input_dim']
        self.hidden_dim = checkpoint.get('hidden_dim', 64)
        self.num_layers = checkpoint.get('num_layers', 2)
        self.dropout = checkpoint.get('dropout', 0.2)
        
        self.model = LSTMClassifier(
            input_dim=self.input_dim,
            hidden_dim=self.hidden_dim,
            num_layers=self.num_layers,
            dropout=self.dropout
        )
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.eval()

    def score_sequence(self, sequence_df: pd.DataFrame) -> float:
        """
        Compute risk score for a chronological sequence of windowed logs.
        Args:
            sequence_df: pandas DataFrame containing window telemetry.
        Returns:
            Risk score as a float probability in range [0, 1]
        """
        df = sequence_df.copy()
        
        # Sort chronologically if window_start is present
        if 'window_start' in df.columns:
            df = df.sort_values('window_start')
            
        # Expose only features the model was trained on
        features_raw = df[self.feature_names].fillna(0.0).values
        
        # Standardize using the fitted training scaler
        if self.scaler is not None:
            features_scaled = self.scaler.transform(features_raw)
        else:
            features_scaled = features_raw
            
        # Target length is 30 steps
        seq_len = 30
        if len(features_scaled) > seq_len:
            # Take the latest 30 steps
            features_scaled = features_scaled[-seq_len:]
        elif len(features_scaled) < seq_len:
            # Front-pad short sequences with feature mean vector to prevent artificially depressing risk scores
            missing_steps = seq_len - len(features_scaled)
            if len(features_scaled) > 0:
                mean_vec = np.mean(features_scaled, axis=0)
            else:
                mean_vec = np.zeros(self.input_dim)
            padding = np.tile(mean_vec, (missing_steps, 1))
            features_scaled = np.vstack((padding, features_scaled))
            
        # Convert to tensor and insert batch dimension: shape (1, 30, input_dim)
        tensor_in = torch.tensor(features_scaled, dtype=torch.float32).unsqueeze(0)
        
        # Disable gradient computation for faster inference
        with torch.no_grad():
            probability = self.model(tensor_in).item()
            
        return probability
