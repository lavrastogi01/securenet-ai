# SecureNet AI - ResNet Training Script for NSL-KDD
# ===================================================
# Run this to train the ResNet model and save it as resnet_nslkdd.pth
#
# Usage:
#   cd backend
#   python train_resnet.py
#
# Requirements:
#   pip install torch numpy pandas scikit-learn

import os
import csv
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# Import model and helpers from app
from app import (
    ResNetClassifier, encode_row, ATTACK_CATEGORY,
    label_to_idx, idx_to_label,
)


def load_training_rows():
    """Load NSL-KDD training data — prefer KDDTrain+.txt, fall back to KDDTest+.txt."""
    base = os.path.join(os.path.dirname(__file__), "data")
    rows = []
    for candidate in ("KDDTrain+.txt", "KDDTrain.txt", "KDDTest+.txt", "KDDTest.txt"):
        p = os.path.join(base, candidate)
        if os.path.exists(p):
            with open(p, "r") as f:
                for r in csv.reader(f):
                    if len(r) >= 42:
                        rows.append(r)
            print(f"Loaded {len(rows)} rows from {candidate}")
            return rows
    return rows


def main():
    training_rows = load_training_rows()
    if not training_rows:
        print("ERROR: No dataset rows loaded. Place KDDTrain+.txt in backend/data/.")
        return

    print(f"Preparing {len(training_rows)} samples...")

    X, y = [], []
    for row in training_rows:
        features = encode_row(row)
        raw_label = row[41].strip().lower() if len(row) > 41 else "normal"
        category = ATTACK_CATEGORY.get(raw_label, "Normal")
        X.append(features)
        y.append(label_to_idx[category])

    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int64)

    # Normalize features
    mean = X.mean(axis=0)
    std = X.std(axis=0) + 1e-8
    X = (X - mean) / std

    # Save normalization params
    np.save("norm_mean.npy", mean)
    np.save("norm_std.npy", std)

    # Train/val split (80/20)
    indices = np.random.permutation(len(X))
    split = int(0.8 * len(X))
    train_idx, val_idx = indices[:split], indices[split:]

    train_ds = TensorDataset(torch.FloatTensor(X[train_idx]), torch.LongTensor(y[train_idx]))
    val_ds = TensorDataset(torch.FloatTensor(X[val_idx]), torch.LongTensor(y[val_idx]))

    train_loader = DataLoader(train_ds, batch_size=256, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=256)

    # Create model
    model = ResNetClassifier(input_dim=122, hidden_dim=128, num_classes=5, num_blocks=3)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=10, gamma=0.5)
    criterion = nn.CrossEntropyLoss()

    # Training loop
    epochs = 30
    best_acc = 0
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for xb, yb in train_loader:
            optimizer.zero_grad()
            out = model(xb)
            loss = criterion(out, yb)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        scheduler.step()

        # Validation
        model.eval()
        correct, total = 0, 0
        with torch.no_grad():
            for xb, yb in val_loader:
                preds = torch.argmax(model(xb), dim=1)
                correct += (preds == yb).sum().item()
                total += len(yb)
        acc = correct / total
        print(f"Epoch {epoch+1}/{epochs} — Loss: {total_loss/len(train_loader):.4f} — Val Acc: {acc:.4f}")

        if acc > best_acc:
            best_acc = acc
            torch.save(model.state_dict(), "resnet_nslkdd.pth")

    print(f"\nTraining complete! Best validation accuracy: {best_acc:.4f}")
    print("Model saved to backend/resnet_nslkdd.pth")

    # Print per-class accuracy
    model.load_state_dict(torch.load("resnet_nslkdd.pth"))
    model.eval()
    class_correct = {i: 0 for i in range(5)}
    class_total = {i: 0 for i in range(5)}
    with torch.no_grad():
        for xb, yb in val_loader:
            preds = torch.argmax(model(xb), dim=1)
            for p, t in zip(preds, yb):
                class_total[t.item()] += 1
                if p.item() == t.item():
                    class_correct[t.item()] += 1
    print("\nPer-class accuracy:")
    for i in range(5):
        if class_total[i] > 0:
            print(f"  {idx_to_label[i]}: {class_correct[i]/class_total[i]:.4f} ({class_correct[i]}/{class_total[i]})")


if __name__ == "__main__":
    main()
