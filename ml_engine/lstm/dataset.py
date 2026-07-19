import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset
from sklearn.preprocessing import StandardScaler

class SequenceDataset(Dataset):
    """Dataset for sequence model training, loading sliding windows of logs."""
    
    def __init__(self, df: pd.DataFrame, feature_names: list[str], seq_len: int = 30, scaler: StandardScaler = None, is_training: bool = True):
        self.seq_len = seq_len
        self.feature_names = feature_names
        
        df = df.copy()
        
        # Fit or apply scaler on feature columns
        features_raw = df[feature_names].fillna(0.0).values
        if is_training:
            self.scaler = StandardScaler()
            features_scaled = self.scaler.fit_transform(features_raw)
        else:
            self.scaler = scaler
            if self.scaler is not None:
                features_scaled = self.scaler.transform(features_raw)
            else:
                features_scaled = features_raw
                
        df[feature_names] = features_scaled
        
        # Build sequences group by source
        self.sequences = []
        self.labels = []
        
        for _, group in df.groupby('source'):
            # Ensure chronological order
            group_sorted = group.sort_values('window_start')
            group_features = group_sorted[feature_names].values
            group_labels = group_sorted['label'].values
            
            for end_idx in range(len(group_features)):
                start_idx = max(0, end_idx - seq_len + 1)
                seq = group_features[start_idx:end_idx + 1]
                
                # Zero padding if sequence is shorter than seq_len
                if len(seq) < seq_len:
                    padding = np.zeros((seq_len - len(seq), len(feature_names)))
                    seq = np.vstack((padding, seq))
                    
                self.sequences.append(seq)
                self.labels.append(group_labels[end_idx])

    def __len__(self) -> int:
        return len(self.sequences)

    def __getitem__(self, idx: int) -> tuple[torch.Tensor, torch.Tensor]:
        seq = torch.tensor(self.sequences[idx], dtype=torch.float32)
        lbl = torch.tensor([self.labels[idx]], dtype=torch.float32)
        return seq, lbl
