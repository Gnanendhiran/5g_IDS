# HTSTCL-GNN Model Architecture & Multiclass Training Guide

## 1. HTSTCL-GNN Architecture Overview

The Hierarchical Spatio-Temporal Contrastive Learning Graph Neural Network (HTSTCL-GNN) integrates:
1. **Spatial Encoder (GAT):**
   - 4-Head Graph Attention Network
   - Input dimension: 91
   - Hidden dimension: 128
   - Output embedding: 128
   - Captures topological correlations between concurrent IP flows within each 5-node time window.
2. **Global Mean Pooling:**
   - Aggregates node representations into a single graph-level vector $h_t \in \mathbb{R}^{128}$ for each temporal step $t \in \{1..5\}$.
3. **Temporal Encoder (GRU):**
   - 2-layer Gated Recurrent Unit
   - Input dimension: 128
   - Hidden dimension: 128
   - Tracks temporal progression and multi-step attack evolution across the 5 consecutive windows.
4. **Hierarchical Attention Fusion:**
   - Computes dynamic attention weights $(\alpha_{\text{spatial}}, \alpha_{\text{temporal}})$
   - Fuses current spatial state with accumulated temporal context:
     $$h_{\text{fused}} = \alpha_{\text{spatial}} h_5 + \alpha_{\text{temporal}} h_{\text{temporal}}$$
5. **Dual Classification Heads:**
   - **Binary Head:** Linear(128, 64) $\to$ ReLU $\to$ Dropout(0.3) $\to$ Linear(64, 2)
   - **Multiclass Head:** Linear(128, 64) $\to$ ReLU $\to$ Dropout(0.3) $\to$ Linear(64, 9)

---

## 2. Training Hyperparameters

- **Batch Size:** 64
- **Optimizer:** AdamW (Learning Rate: 2e-4, Weight Decay: 1e-4)
- **Learning Rate Scheduler:** ReduceLROnPlateau (factor: 0.5, patience: 2)
- **Early Stopping Patience:** 4 epochs
- **Loss Function:** Class-Weighted CrossEntropyLoss for multiclass + CrossEntropyLoss for binary head:
  $$\mathcal{L} = \mathcal{L}_{\text{multi}} + 0.5 \cdot \mathcal{L}_{\text{binary}}$$
- **Pre-trained Transfer Learning:** Spatio-temporal encoder weights initialized from `saved_models/htstcl_gnn_best.pth`.

---

## 3. Training Execution Command

To reproduce training:
```powershell
python models/train_multiclass.py
```

Outputs generated:
- Checkpoints: `saved_models/htstcl_gnn_multiclass_best.pth`, `saved_models/htstcl_gnn_multiclass_final.pth`
- Reports: `reports/multiclass_classification_report.txt`, `reports/multiclass_metrics.csv`, `reports/binary_metrics.csv`
- Visualizations: `reports/confusion_matrix_multiclass.png`, `reports/confusion_matrix_binary.png`, `reports/per_class_metrics.png`, `reports/training_history.png`
