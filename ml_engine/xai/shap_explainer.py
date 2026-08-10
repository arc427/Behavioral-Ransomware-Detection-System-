import sys
from pathlib import Path
import joblib
import numpy as np

# Add project root to path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

class SHAPExplainer:
    """Computes SHAP/feature contribution values for baseline Logistic Regression predictions."""
    def __init__(self, model_path: Path | str | None = None):
        if model_path is None:
            model_path = ROOT / "data/models/baseline_models.joblib"
        self.model_path = Path(model_path)
        self.artifacts = None
        self.feature_names = None
        self.supervised_model = None
        self.scaler = None
        self.model = None

    def _load_model(self) -> None:
        if self.artifacts is not None:
            return
        if not self.model_path.exists():
            raise FileNotFoundError(f"Baseline model not found at {self.model_path}")
        
        self.artifacts = joblib.load(self.model_path)
        self.feature_names = list(self.artifacts["feature_names"])
        self.supervised_model = self.artifacts["supervised_model"]
        self.scaler = self.supervised_model.named_steps["scale"]
        self.model = self.supervised_model.named_steps["model"]

    def explain(self, feature_dict: dict) -> list[dict]:
        """Compute feature contribution values for a single telemetry feature vector.
        
        Returns:
            list[dict]: Sorted list of feature attributions (feature_name, importance_value).
        """
        self._load_model()
        
        # Assemble raw feature vector ordered by feature names
        x_raw = np.array([float(feature_dict.get(col) or 0.0) for col in self.feature_names]).reshape(1, -1)
        
        try:
            # 1. Try to compute using the actual SHAP library
            import shap
            background = np.zeros((1, len(self.feature_names)))
            explainer = shap.LinearExplainer(self.model, background)
            x_scaled = self.scaler.transform(x_raw)
            shap_values = explainer.shap_values(x_scaled)
            # Handle both list and array outputs from SHAP shape variations
            if isinstance(shap_values, list):
                shap_values = shap_values[0]
            if len(shap_values.shape) > 1:
                shap_values = shap_values[0]
                
            attributions = []
            for name, val in zip(self.feature_names, shap_values):
                attributions.append({
                    "feature_name": name,
                    "importance_value": float(val)
                })
        except Exception:
            # 2. Mathematical fallback for linear models: beta * (x - mean) / std
            x_scaled = self.scaler.transform(x_raw)[0]
            coefs = self.model.coef_[0]
            
            attributions = []
            for name, scaled_val, coef in zip(self.feature_names, x_scaled, coefs):
                val = float(scaled_val * coef)
                attributions.append({
                    "feature_name": name,
                    "importance_value": val
                })

        # Sort by absolute importance value descending
        attributions.sort(key=lambda x: abs(x["importance_value"]), reverse=True)
        return attributions


import torch

class LSTMSHAPExplainer:
    """Computes gradient-based feature attributions for PyTorch LSTM sequence classification."""
    
    def __init__(self, lstm_infer):
        self.lstm_infer = lstm_infer

    def explain(self, sequence_df) -> list[dict]:
        """Compute integrated gradient / feature attribution for an LSTM sequence.
        
        Args:
            sequence_df: pandas DataFrame or dict containing window telemetry.
        Returns:
            list[dict]: Sorted list of feature attributions (feature_name, importance_value).
        """
        import pandas as pd
        if isinstance(sequence_df, dict):
            df = pd.DataFrame([sequence_df])
        else:
            df = sequence_df.copy()
            
        # 1. Try SHAP GradientExplainer
        try:
            import shap
            features_raw = df.reindex(columns=self.lstm_infer.feature_names, fill_value=0.0).fillna(0.0).values
            if self.lstm_infer.scaler is not None:
                features_scaled = self.lstm_infer.scaler.transform(features_raw)
            else:
                features_scaled = features_raw
                
            # Target 30 steps sequence
            seq_len = 30
            if len(features_scaled) > seq_len:
                features_scaled = features_scaled[-seq_len:]
            elif len(features_scaled) < seq_len:
                missing_steps = seq_len - len(features_scaled)
                mean_vec = np.mean(features_scaled, axis=0) if len(features_scaled) > 0 else np.zeros(self.lstm_infer.input_dim)
                padding = np.tile(mean_vec, (missing_steps, 1))
                features_scaled = np.vstack((padding, features_scaled))
                
            input_tensor = torch.tensor(features_scaled, dtype=torch.float32).unsqueeze(0)
            background_tensor = torch.zeros((1, seq_len, self.lstm_infer.input_dim))
            
            explainer = shap.GradientExplainer(self.lstm_infer.model, background_tensor)
            shap_values = explainer.shap_values(input_tensor)
            if isinstance(shap_values, list):
                shap_values = shap_values[0]
            if len(shap_values.shape) == 3:
                shap_values = shap_values[0]
                
            # Average absolute feature importance across all sequence timesteps
            mean_importance = np.abs(shap_values).mean(axis=0)
            attributions = [
                {"feature_name": name, "importance_value": float(np.asarray(val).flatten()[0])}
                for name, val in zip(self.lstm_infer.feature_names, mean_importance)
            ]
        except Exception:
            # 2. PyTorch Gradient * Input attribution fallback
            self.lstm_infer.model.eval()
            features_raw = df.reindex(columns=self.lstm_infer.feature_names, fill_value=0.0).fillna(0.0).values
            if self.lstm_infer.scaler is not None:
                features_scaled = self.lstm_infer.scaler.transform(features_raw)
            else:
                features_scaled = features_raw
                
            seq_len = 30
            if len(features_scaled) > seq_len:
                features_scaled = features_scaled[-seq_len:]
            elif len(features_scaled) < seq_len:
                missing_steps = seq_len - len(features_scaled)
                mean_vec = np.mean(features_scaled, axis=0) if len(features_scaled) > 0 else np.zeros(self.lstm_infer.input_dim)
                padding = np.tile(mean_vec, (missing_steps, 1))
                features_scaled = np.vstack((padding, features_scaled))
                
            self.lstm_infer.model.zero_grad()
            input_tensor = torch.tensor(features_scaled, dtype=torch.float32).unsqueeze(0).requires_grad_(True)
            output = self.lstm_infer.model(input_tensor)
            output.backward()
            
            grads = input_tensor.grad.detach().numpy()[0] # (seq_len, input_dim)
            grad_x_input = np.abs(grads * features_scaled).mean(axis=0)
            
            attributions = [
                {"feature_name": name, "importance_value": float(np.asarray(val).flatten()[0])}
                for name, val in zip(self.lstm_infer.feature_names, grad_x_input)
            ]
            
        # Normalize importance values so they sum to 1.0 (relative percentage importance)
        # This prevents "all zeros" in the UI when the sigmoid gradient vanishes due to high confidence (0.999+ scores)
        total_importance = sum(abs(x["importance_value"]) for x in attributions)
        if total_importance > 0:
            for attr in attributions:
                # Scale up to a readable range, e.g. relative percentage (0.0 to 1.0)
                # We multiply by 10 so the raw values look like solid integers/decimals in the UI
                attr["importance_value"] = (abs(attr["importance_value"]) / total_importance) * 10.0

        attributions.sort(key=lambda x: abs(x["importance_value"]), reverse=True)
        return attributions
