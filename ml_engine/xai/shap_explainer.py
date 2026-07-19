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
        x_raw = np.array([float(feature_dict.get(col, 0.0)) for col in self.feature_names]).reshape(1, -1)
        
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
