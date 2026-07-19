import os
import sys
import argparse
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
import pandas as pd
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.vectorizer import feature_columns
from scripts.train_baseline import scenario_split
from ml_engine.lstm.model import LSTMClassifier
from ml_engine.lstm.dataset import SequenceDataset

def train_lstm(input_path: Path, model_output_path: Path, epochs: int = 10, batch_size: int = 64, lr: float = 0.001, seed: int = 42) -> None:
    print(f"Loading dataset from {input_path}...")
    df = pd.read_csv(input_path)
    
    # Extract features and split scenario
    features = feature_columns(df)
    print(f"Detected {len(features)} numeric behavioral features: {features}")
    
    splits = scenario_split(df, seed=seed)
    print(f"Dataset split size -> Train: {len(splits['train'])}, Val: {len(splits['validation'])}, Test: {len(splits['test'])}")
    
    # Create datasets
    train_dataset = SequenceDataset(splits["train"], features, is_training=True)
    val_dataset = SequenceDataset(splits["validation"], features, scaler=train_dataset.scaler, is_training=False)
    test_dataset = SequenceDataset(splits["test"], features, scaler=train_dataset.scaler, is_training=False)
    
    # Create dataloaders
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    
    # Initialize model, loss, and optimizer
    model = LSTMClassifier(input_dim=len(features))
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    
    best_val_loss = float('inf')
    best_model_state = None
    
    print("\nStarting training loop...")
    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        for X_batch, y_batch in train_loader:
            optimizer.zero_grad()
            pred = model(X_batch)
            loss = criterion(pred, y_batch)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * X_batch.size(0)
            
        train_loss /= len(train_loader.dataset)
        
        # Validation
        model.eval()
        val_loss = 0.0
        correct = 0
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                pred = model(X_batch)
                loss = criterion(pred, y_batch)
                val_loss += loss.item() * X_batch.size(0)
                
                # Accuracy metric
                preds_binary = (pred >= 0.5).float()
                correct += (preds_binary == y_batch).sum().item()
                
        val_loss /= len(val_loader.dataset)
        val_acc = correct / len(val_loader.dataset)
        
        print(f"Epoch {epoch}/{epochs} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}")
        
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_model_state = model.state_dict()
            
    # Save the trained model checkpoint
    model_output_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint = {
        'model_state_dict': best_model_state if best_model_state is not None else model.state_dict(),
        'scaler': train_dataset.scaler,
        'feature_names': features,
        'input_dim': len(features),
        'hidden_dim': 64,
        'num_layers': 2,
        'dropout': 0.2
    }
    torch.save(checkpoint, model_output_path)
    print(f"\nTraining finished! Saved model checkpoint to {model_output_path}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Train LSTM Sequence Classification Model.")
    parser.add_argument("--input", type=Path, default=ROOT / "data/processed/sysmon_combined_windows.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "data/models/lstm_model.pth")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=0.001)
    args = parser.parse_args()
    
    train_lstm(args.input, args.output, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr)

if __name__ == "__main__":
    main()
