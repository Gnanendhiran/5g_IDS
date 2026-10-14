import os
import sys
import random
import time
from collections import Counter

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)

# Set paths
ROOT_DIR = r"d:\5G_Wireless_IDS"
sys.path.insert(0, ROOT_DIR)

from models.htstcl_gnn_multiclass import HTSTCL_GNN_Multiclass

# Config
RANDOM_SEED = 42
BATCH_SIZE = 64
EPOCHS = 10
LEARNING_RATE = 2e-4
WEIGHT_DECAY = 1e-4
PATIENCE = 4

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

set_seed(RANDOM_SEED)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("=" * 70)
print("HTSTCL-GNN MULTICLASS ATTACK DETECTION TRAINING")
print("=" * 70)
print(f"Device: {DEVICE}")
print(f"Batch Size: {BATCH_SIZE} | Learning Rate: {LEARNING_RATE} | Epochs: {EPOCHS}")

# Load sequence dataset & labels
SEQ_PATH = os.path.join(ROOT_DIR, "outputs", "sequence_dataset", "graph_sequences.pt")
LABELS_PATH = os.path.join(ROOT_DIR, "outputs", "sequence_dataset", "multiclass_sequence_labels.npz")
SAVED_MODELS_DIR = os.path.join(ROOT_DIR, "saved_models")
REPORTS_DIR = os.path.join(ROOT_DIR, "reports")
os.makedirs(SAVED_MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

print("\n[1/6] Loading graph sequences and multiclass metadata...")
sequences = torch.load(SEQ_PATH, map_location="cpu", weights_only=False)
meta = np.load(LABELS_PATH)

attack_classes = list(meta["attack_classes"])
attack_indices = meta["attack_indices"]
binary_labels = meta["binary_labels"]
train_idx = meta["train_indices"]
val_idx = meta["val_indices"]
test_idx = meta["test_indices"]

num_classes = len(attack_classes)
print(f"Loaded {len(sequences):,} sequences across {num_classes} classes: {attack_classes}")
print(f"Train: {len(train_idx):,} | Val: {len(val_idx):,} | Test: {len(test_idx):,}")

# Dataset class
class SequenceDataset(Dataset):
    def __init__(self, sequences, multi_labels, bin_labels, indices):
        self.sequences = sequences
        self.multi_labels = multi_labels
        self.bin_labels = bin_labels
        self.indices = indices

    def __len__(self):
        return len(self.indices)

    def __getitem__(self, idx):
        real_idx = self.indices[idx]
        return {
            "graphs": self.sequences[real_idx]["graphs"],
            "multiclass_label": self.multi_labels[real_idx],
            "binary_label": self.bin_labels[real_idx],
            "seq_idx": real_idx
        }

def collate_fn(batch):
    batch_sequences = [item["graphs"] for item in batch]
    multi_labels = torch.tensor([item["multiclass_label"] for item in batch], dtype=torch.long)
    bin_labels = torch.tensor([item["binary_label"] for item in batch], dtype=torch.long)
    seq_indices = [item["seq_idx"] for item in batch]
    return {
        "batch_sequences": batch_sequences,
        "multiclass_labels": multi_labels,
        "binary_labels": bin_labels,
        "seq_indices": seq_indices
    }

train_ds = SequenceDataset(sequences, attack_indices, binary_labels, train_idx)
val_ds = SequenceDataset(sequences, attack_indices, binary_labels, val_idx)
test_ds = SequenceDataset(sequences, attack_indices, binary_labels, test_idx)

train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate_fn)
val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate_fn)
test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate_fn)

# Calculate class weights for imbalance handling
print("\n[2/6] Computing class weights...")
train_class_counts = Counter(attack_indices[train_idx])
total_train = len(train_idx)
class_weights = []
for c in range(num_classes):
    count = train_class_counts.get(c, 1)
    # Balanced smoothed inverse frequency
    weight = np.sqrt(total_train / (num_classes * count))
    class_weights.append(weight)

class_weights = torch.tensor(class_weights, dtype=torch.float32).to(DEVICE)
print("Class weights:")
for c, w in enumerate(class_weights.tolist()):
    print(f"  [{c}] {attack_classes[c]:<15}: {w:.3f}")

# Model initialization & transfer learning
print("\n[3/6] Initializing HTSTCL-GNN Multiclass model...")
model = HTSTCL_GNN_Multiclass(
    input_dim=91,
    hidden_dim=128,
    embedding_dim=128,
    num_classes=num_classes,
    gru_layers=2,
    dropout=0.3
).to(DEVICE)

# Transfer pre-trained backbone weights from baseline
BINARY_CKPT = os.path.join(SAVED_MODELS_DIR, "htstcl_gnn_best.pth")
if os.path.exists(BINARY_CKPT):
    print(f"Loading pre-trained spatio-temporal representation from: {BINARY_CKPT}")
    ckpt = torch.load(BINARY_CKPT, map_location=DEVICE, weights_only=False)
    state_dict = ckpt["model_state_dict"] if "model_state_dict" in ckpt else ckpt
    
    # Filter matching keys
    model_dict = model.state_dict()
    matched_keys = []
    for k, v in state_dict.items():
        if k in model_dict and model_dict[k].shape == v.shape:
            model_dict[k] = v
            matched_keys.append(k)
        elif k.startswith("classifier."):
            # Transfer first linear layer (embedding_dim -> 64)
            if k == "classifier.0.weight":
                model_dict["multiclass_classifier.0.weight"] = v
                model_dict["binary_classifier.0.weight"] = v
                matched_keys.append(k)
            elif k == "classifier.0.bias":
                model_dict["multiclass_classifier.0.bias"] = v
                model_dict["binary_classifier.0.bias"] = v
                matched_keys.append(k)
            elif k == "classifier.3.weight":
                model_dict["binary_classifier.3.weight"] = v
                matched_keys.append(k)
            elif k == "classifier.3.bias":
                model_dict["binary_classifier.3.bias"] = v
                matched_keys.append(k)

    model.load_state_dict(model_dict)
    print(f"Successfully transferred {len(matched_keys)} pre-trained parameter tensors!")

# Losses & Optimizer
multi_criterion = nn.CrossEntropyLoss(weight=class_weights)
binary_criterion = nn.CrossEntropyLoss()

optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="max", factor=0.5, patience=2)

# Training loop
print("\n[4/6] Commencing multiclass training & validation...")
best_val_f1 = 0.0
best_epoch = 0
history = {
    "epoch": [],
    "train_loss": [],
    "val_loss": [],
    "val_acc": [],
    "val_macro_f1": [],
    "val_weighted_f1": []
}

BEST_CKPT_PATH = os.path.join(SAVED_MODELS_DIR, "htstcl_gnn_multiclass_best.pth")
FINAL_CKPT_PATH = os.path.join(SAVED_MODELS_DIR, "htstcl_gnn_multiclass_final.pth")

patience_counter = 0

for epoch in range(1, EPOCHS + 1):
    epoch_start = time.time()
    model.train()
    total_train_loss = 0.0
    num_train_batches = 0

    for batch in train_loader:
        optimizer.zero_grad()
        out = model(batch["batch_sequences"])
        
        loss_multi = multi_criterion(out["multiclass_logits"], batch["multiclass_labels"].to(DEVICE))
        loss_bin = binary_criterion(out["binary_logits"], batch["binary_labels"].to(DEVICE))
        
        loss = loss_multi + 0.5 * loss_bin
        loss.backward()
        
        # Gradient clipping
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
        optimizer.step()
        
        total_train_loss += loss.item()
        num_train_batches += 1

    avg_train_loss = total_train_loss / max(1, num_train_batches)

    # Validation
    model.eval()
    total_val_loss = 0.0
    num_val_batches = 0
    all_val_preds = []
    all_val_targets = []

    with torch.no_grad():
        for batch in val_loader:
            out = model(batch["batch_sequences"])
            t_multi = batch["multiclass_labels"].to(DEVICE)
            t_bin = batch["binary_labels"].to(DEVICE)
            
            loss_multi = multi_criterion(out["multiclass_logits"], t_multi)
            loss_bin = binary_criterion(out["binary_logits"], t_bin)
            loss = loss_multi + 0.5 * loss_bin
            
            total_val_loss += loss.item()
            num_val_batches += 1
            
            preds = torch.argmax(out["multiclass_logits"], dim=1).cpu().numpy()
            all_val_preds.extend(preds)
            all_val_targets.extend(t_multi.cpu().numpy())

    avg_val_loss = total_val_loss / max(1, num_val_batches)
    val_acc = accuracy_score(all_val_targets, all_val_preds)
    val_macro_f1 = f1_score(all_val_targets, all_val_preds, average="macro", zero_division=0)
    val_weighted_f1 = f1_score(all_val_targets, all_val_preds, average="weighted", zero_division=0)

    scheduler.step(val_macro_f1)
    duration = time.time() - epoch_start

    history["epoch"].append(epoch)
    history["train_loss"].append(avg_train_loss)
    history["val_loss"].append(avg_val_loss)
    history["val_acc"].append(val_acc)
    history["val_macro_f1"].append(val_macro_f1)
    history["val_weighted_f1"].append(val_weighted_f1)

    print(f"Epoch {epoch:02d}/{EPOCHS:02d} [{duration:.1f}s] - "
          f"Train Loss: {avg_train_loss:.4f} | "
          f"Val Loss: {avg_val_loss:.4f} | "
          f"Val Acc: {val_acc*100:.2f}% | "
          f"Val Macro F1: {val_macro_f1*100:.2f}% | "
          f"Val W-F1: {val_weighted_f1*100:.2f}%")

    if val_macro_f1 > best_val_f1:
        best_val_f1 = val_macro_f1
        best_epoch = epoch
        patience_counter = 0
        
        # Save best checkpoint with comprehensive metadata
        torch.save({
            "epoch": epoch,
            "model_state_dict": model.state_dict(),
            "optimizer_state_dict": optimizer.state_dict(),
            "val_loss": avg_val_loss,
            "val_acc": val_acc,
            "val_macro_f1": val_macro_f1,
            "val_weighted_f1": val_weighted_f1,
            "attack_classes": attack_classes,
            "num_classes": num_classes,
            "input_dim": 91,
            "hidden_dim": 128,
            "embedding_dim": 128,
            "random_seed": RANDOM_SEED,
            "architecture": "HTSTCL_GNN_Multiclass"
        }, BEST_CKPT_PATH)
        print(f"  --> Saved BEST checkpoint: {BEST_CKPT_PATH} (Macro F1: {val_macro_f1*100:.2f}%)")
    else:
        patience_counter += 1
        if patience_counter >= PATIENCE:
            print(f"\nEarly stopping triggered after {PATIENCE} epochs without improvement.")
            break

# Save final checkpoint
torch.save({
    "epoch": epoch,
    "model_state_dict": model.state_dict(),
    "attack_classes": attack_classes,
    "num_classes": num_classes,
    "architecture": "HTSTCL_GNN_Multiclass"
}, FINAL_CKPT_PATH)
print(f"Saved FINAL checkpoint: {FINAL_CKPT_PATH}")

# 5. Final Evaluation on Held-Out Test Set
print("\n[5/6] Final Evaluation on Held-Out Test Set (7,296 sequences)...")
best_checkpoint = torch.load(BEST_CKPT_PATH, map_location=DEVICE, weights_only=False)
model.load_state_dict(best_checkpoint["model_state_dict"])
model.eval()

test_preds = []
test_targets = []
test_probs = []
test_bin_preds = []
test_bin_targets = []

with torch.no_grad():
    for batch in test_loader:
        out = model(batch["batch_sequences"])
        probs = torch.softmax(out["multiclass_logits"], dim=1).cpu().numpy()
        preds = np.argmax(probs, axis=1)
        targets = batch["multiclass_labels"].numpy()
        bin_targets = batch["binary_labels"].numpy()
        
        # Binary prediction derived from multiclass (0 = Benign, >0 = Malicious)
        bin_preds = (preds > 0).astype(np.int64)
        
        test_probs.extend(probs)
        test_preds.extend(preds)
        test_targets.extend(targets)
        test_bin_preds.extend(bin_preds)
        test_bin_targets.extend(bin_targets)

test_preds = np.array(test_preds)
test_targets = np.array(test_targets)
test_probs = np.array(test_probs)
test_bin_preds = np.array(test_bin_preds)
test_bin_targets = np.array(test_bin_targets)

# Compute Multiclass Metrics
acc = accuracy_score(test_targets, test_preds)
macro_p = precision_score(test_targets, test_preds, average="macro", zero_division=0)
macro_r = recall_score(test_targets, test_preds, average="macro", zero_division=0)
macro_f1 = f1_score(test_targets, test_preds, average="macro", zero_division=0)

weighted_p = precision_score(test_targets, test_preds, average="weighted", zero_division=0)
weighted_r = recall_score(test_targets, test_preds, average="weighted", zero_division=0)
weighted_f1 = f1_score(test_targets, test_preds, average="weighted", zero_division=0)

# Binary metrics
bin_acc = accuracy_score(test_bin_targets, test_bin_preds)
bin_p = precision_score(test_bin_targets, test_bin_preds, zero_division=0)
bin_r = recall_score(test_bin_targets, test_bin_preds, zero_division=0)
bin_f1 = f1_score(test_bin_targets, test_bin_preds, zero_division=0)

print("\n" + "=" * 70)
print("FINAL TEST RESULTS (HTSTCL-GNN MULTICLASS)")
print("=" * 70)
print(f"Overall Accuracy   : {acc*100:.2f}%")
print(f"Macro Precision    : {macro_p*100:.2f}%")
print(f"Macro Recall       : {macro_r*100:.2f}%")
print(f"Macro F1-Score     : {macro_f1*100:.2f}%")
print(f"Weighted Precision : {weighted_p*100:.2f}%")
print(f"Weighted Recall    : {weighted_r*100:.2f}%")
print(f"Weighted F1-Score  : {weighted_f1*100:.2f}%")
print("-" * 70)
print(f"Binary Detection (Derived from Multiclass):")
print(f"  Accuracy  : {bin_acc*100:.2f}%")
print(f"  Precision : {bin_p*100:.2f}%")
print(f"  Recall    : {bin_r*100:.2f}%")
print(f"  F1-Score  : {bin_f1*100:.2f}%")
print("=" * 70)

# Per-Class Classification Report
clf_report = classification_report(
    test_targets,
    test_preds,
    target_names=attack_classes,
    digits=4,
    zero_division=0
)
print("\nPer-Class Classification Report:")
print(clf_report)

# Save reports and metrics
print("\n[6/6] Generating reports, metrics tables, and visualization charts...")

# 1. Text report
with open(os.path.join(REPORTS_DIR, "multiclass_classification_report.txt"), "w") as f:
    f.write("HTSTCL-GNN MULTICLASS ATTACK DETECTION - TEST EVALUATION REPORT\n")
    f.write("=" * 70 + "\n\n")
    f.write(f"Model: HTSTCL_GNN_Multiclass (Dual Head)\n")
    f.write(f"Best Training Epoch: {best_epoch}\n")
    f.write(f"Test Samples: {len(test_targets):,}\n\n")
    f.write("Summary Metrics:\n")
    f.write(f"  Overall Accuracy   : {acc*100:.2f}%\n")
    f.write(f"  Macro Precision    : {macro_p*100:.2f}%\n")
    f.write(f"  Macro Recall       : {macro_r*100:.2f}%\n")
    f.write(f"  Macro F1-Score     : {macro_f1*100:.2f}%\n")
    f.write(f"  Weighted Precision : {weighted_p*100:.2f}%\n")
    f.write(f"  Weighted Recall    : {weighted_r*100:.2f}%\n")
    f.write(f"  Weighted F1-Score  : {weighted_f1*100:.2f}%\n\n")
    f.write("Binary Detection Metrics:\n")
    f.write(f"  Binary Accuracy  : {bin_acc*100:.2f}%\n")
    f.write(f"  Binary Precision : {bin_p*100:.2f}%\n")
    f.write(f"  Binary Recall    : {bin_r*100:.2f}%\n")
    f.write(f"  Binary F1-Score  : {bin_f1*100:.2f}%\n\n")
    f.write("Detailed Per-Class Breakdown:\n")
    f.write(clf_report + "\n")

# 2. Multiclass metrics CSV
per_class_p = precision_score(test_targets, test_preds, average=None, zero_division=0)
per_class_r = recall_score(test_targets, test_preds, average=None, zero_division=0)
per_class_f1 = f1_score(test_targets, test_preds, average=None, zero_division=0)

metrics_rows = []
for c, c_name in enumerate(attack_classes):
    sup = int(np.sum(test_targets == c))
    metrics_rows.append({
        "Class_Index": c,
        "Attack_Type": c_name,
        "Support": sup,
        "Precision": round(float(per_class_p[c]), 4),
        "Recall": round(float(per_class_r[c]), 4),
        "F1_Score": round(float(per_class_f1[c]), 4)
    })

pd.DataFrame(metrics_rows).to_csv(os.path.join(REPORTS_DIR, "multiclass_metrics.csv"), index=False)

# 3. Binary metrics CSV
pd.DataFrame([{
    "Model": "HTSTCL-GNN Multiclass (Derived Binary)",
    "Accuracy": round(float(bin_acc), 4),
    "Precision": round(float(bin_p), 4),
    "Recall": round(float(bin_r), 4),
    "F1_Score": round(float(bin_f1), 4),
    "Test_Samples": len(test_bin_targets)
}]).to_csv(os.path.join(REPORTS_DIR, "binary_metrics.csv"), index=False)

# 4. Multiclass Confusion Matrix
cm = confusion_matrix(test_targets, test_preds)
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=attack_classes, yticklabels=attack_classes)
plt.title("HTSTCL-GNN Multiclass Attack Detection Confusion Matrix", fontsize=14, fontweight="bold")
plt.xlabel("Predicted Attack Class", fontsize=12)
plt.ylabel("True Attack Class", fontsize=12)
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "confusion_matrix_multiclass.png"), dpi=300)
plt.close()

# 5. Binary Confusion Matrix
bin_cm = confusion_matrix(test_bin_targets, test_bin_preds)
plt.figure(figsize=(6, 5))
sns.heatmap(bin_cm, annot=True, fmt="d", cmap="Reds",
            xticklabels=["Benign", "Malicious"], yticklabels=["Benign", "Malicious"])
plt.title("Derived Binary Detection Confusion Matrix", fontsize=13, fontweight="bold")
plt.xlabel("Predicted Status", fontsize=11)
plt.ylabel("True Status", fontsize=11)
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "confusion_matrix_binary.png"), dpi=300)
plt.close()

# 6. Per-Class Metrics Bar Chart
plt.figure(figsize=(12, 6))
x = np.arange(num_classes)
width = 0.25

plt.bar(x - width, per_class_p * 100, width, label="Precision", color="#3b82f6")
plt.bar(x, per_class_r * 100, width, label="Recall", color="#10b981")
plt.bar(x + width, per_class_f1 * 100, width, label="F1-Score", color="#f59e0b")

plt.xlabel("Attack Category", fontsize=12)
plt.ylabel("Score (%)", fontsize=12)
plt.title("Per-Class Performance Metrics (HTSTCL-GNN)", fontsize=14, fontweight="bold")
plt.xticks(x, attack_classes, rotation=35, ha="right")
plt.ylim(0, 105)
plt.legend(frameon=True)
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "per_class_metrics.png"), dpi=300)
plt.close()

# 7. Training History Chart
plt.figure(figsize=(10, 5))
plt.subplot(1, 2, 1)
plt.plot(history["epoch"], history["train_loss"], label="Train Loss", marker="o", color="#ef4444")
plt.plot(history["epoch"], history["val_loss"], label="Val Loss", marker="s", color="#3b82f6")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.title("Training & Validation Loss")
plt.legend()
plt.grid(True, linestyle="--", alpha=0.5)

plt.subplot(1, 2, 2)
plt.plot(history["epoch"], [v * 100 for v in history["val_acc"]], label="Val Accuracy", marker="o", color="#10b981")
plt.plot(history["epoch"], [v * 100 for v in history["val_macro_f1"]], label="Val Macro F1", marker="^", color="#8b5cf6")
plt.xlabel("Epoch")
plt.ylabel("Score (%)")
plt.title("Validation Accuracy & Macro F1")
plt.legend()
plt.grid(True, linestyle="--", alpha=0.5)

plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "training_history.png"), dpi=300)
plt.close()

print(f"\nAll reports and plots generated successfully in: {REPORTS_DIR}")
print("=" * 70)
print("MULTICLASS MODEL TRAINING & EVALUATION COMPLETED!")
print("=" * 70)
