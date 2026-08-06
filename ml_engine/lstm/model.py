import torch
import torch.nn as nn

class LSTMClassifier(nn.Module):
    """LSTM-based sequence classifier for behavioral telemetry sequences."""
    
    def __init__(self, input_dim: int, hidden_dim: int = 64, num_layers: int = 2, dropout: float = 0.2):
        super().__init__()
        self.input_projection = nn.Linear(input_dim, hidden_dim)
        self.lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0
        )
        # Bidirectional LSTM outputs hidden_dim * 2; Mean + Max pooling outputs hidden_dim * 4
        self.fc = nn.Linear(hidden_dim * 4, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass for classification.
        Args:
            x: Input tensor of shape (batch_size, seq_len, input_dim)
        Returns:
            Probability tensor of shape (batch_size, 1) in range [0, 1]
        """
        # Shape: (batch_size, seq_len, hidden_dim)
        projected = self.input_projection(x)
        
        # Shape: (batch_size, seq_len, hidden_dim * 2)
        lstm_out, _ = self.lstm(projected)
        
        # Mean and Max pooling across all sequence timesteps
        # Mean pool captures average activity; Max pool captures peak threat intensity at any step
        mean_pool = lstm_out.mean(dim=1)
        max_pool = lstm_out.max(dim=1).values
        pooled = torch.cat([mean_pool, max_pool], dim=1) # Shape: (batch_size, hidden_dim * 4)
        
        # Class logits and Sigmoid activation
        logits = self.fc(pooled)
        probabilities = self.sigmoid(logits)
        
        return probabilities
