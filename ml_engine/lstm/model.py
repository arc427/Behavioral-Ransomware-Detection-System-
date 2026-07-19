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
        # Bidirectional LSTM outputs hidden_dim * 2
        self.fc = nn.Linear(hidden_dim * 2, 1)
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
        
        # Extract features from the final time-step of the sequence
        # Shape: (batch_size, hidden_dim * 2)
        final_state = lstm_out[:, -1, :]
        
        # Class logits and Sigmoid activation
        # Shape: (batch_size, 1)
        logits = self.fc(final_state)
        probabilities = self.sigmoid(logits)
        
        return probabilities
