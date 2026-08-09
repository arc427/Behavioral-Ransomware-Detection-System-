"""PyTorch layer-by-layer shape and parameter verification script for BRDS-PEC."""

import sys
from pathlib import Path
import torch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml_engine.lstm.model import LSTMClassifier

def verify_architecture():
    print("=" * 70)
    print("      BRDS-PEC PYTORCH LSTM LAYER-BY-LAYER ARCHITECTURE AUDIT      ")
    print("=" * 70)

    input_dim = 17
    hidden_dim = 64
    num_layers = 2
    seq_len = 30
    batch_size = 32

    model = LSTMClassifier(input_dim=input_dim, hidden_dim=hidden_dim, num_layers=num_layers)
    model.eval()

    # Create dummy batch (batch_size=32, seq_len=30, input_dim=17)
    dummy_input = torch.randn(batch_size, seq_len, input_dim)

    print(f"\n[INPUT TENSOR SHAPE]: {list(dummy_input.shape)} (Batch Size: {batch_size}, Sequence Length: {seq_len}, Features: {input_dim})")
    print("-" * 70)

    # 1. Input Linear Projection Layer
    projected = model.input_projection(dummy_input)
    proj_params = sum(p.numel() for p in model.input_projection.parameters())
    print(f"Layer 1: Input Projection  | Input: {list(dummy_input.shape)} -> Output: {list(projected.shape)} | Params: {proj_params:,}")

    # 2. 2-Layer Bidirectional LSTM
    lstm_out, (hn, cn) = model.lstm(projected)
    lstm_params = sum(p.numel() for p in model.lstm.parameters())
    print(f"Layer 2: 2-Layer BiLSTM    | Input: {list(projected.shape)} -> Output: {list(lstm_out.shape)} | Params: {lstm_params:,}")
    print(f"          Hidden States (hn): {list(hn.shape)} | Cell States (cn): {list(cn.shape)}")

    # 3. Mean + Max Concatenated Pooling
    mean_pool = lstm_out.mean(dim=1)
    max_pool = lstm_out.max(dim=1).values
    pooled = torch.cat([mean_pool, max_pool], dim=1)
    print(f"Layer 3: Mean + Max Pool   | Mean: {list(mean_pool.shape)} + Max: {list(max_pool.shape)} -> Pooled: {list(pooled.shape)}")

    # 4. FC Output Classification Layer
    logits = model.fc(pooled)
    probs = model.sigmoid(logits)
    fc_params = sum(p.numel() for p in model.fc.parameters())
    print(f"Layer 4: Fully Connected FC | Input: {list(pooled.shape)} -> Logits: {list(logits.shape)} -> Sigmoid: {list(probs.shape)} | Params: {fc_params:,}")

    total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

    print("-" * 70)
    print(f"[SUMMARY] TOTAL TRAINABLE MODEL PARAMETERS: {total_params:,}")
    print("=" * 70)

    print("\nDetailed Parameter Tensor Breakdown:")
    for name, param in model.named_parameters():
        shape_str = str(list(param.shape))
        print(f"  * {name:<35}: shape {shape_str:<22} | {param.numel():>6,} params")

if __name__ == "__main__":
    verify_architecture()
