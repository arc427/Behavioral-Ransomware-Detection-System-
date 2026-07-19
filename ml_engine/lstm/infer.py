import torch
import pandas as pd
import numpy as np
from pathlib import Path
from ml_engine.lstm.model import LSTMClassifier

class LSTMInfer:
    """Wrapper class to load trained LSTM model and run real-time inference."""
    
    def __init__(self, model_path: str | Path):
        checkpoint = torch.load(model_path, map_location=torch.device('cpu'), weights_only=False)
        self.feature_names = checkpoint['feature_names']
        self.scaler = checkpoint['scaler']
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
            # Pad front with zeros if sequence is short
            padding = np.zeros((seq_len - len(features_scaled), self.input_dim))
            features_scaled = np.vstack((padding, features_scaled))
            
        # Convert to tensor and insert batch dimension: shape (1, 30, input_dim)
        tensor_in = torch.tensor(features_scaled, dtype=torch.float32).unsqueeze(0)
        
        # Disable gradient computation for faster inference
        with torch.no_grad():
            probability = self.model(tensor_in).item()
            
        return probability
