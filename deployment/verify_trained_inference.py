import sys
import torch

# ============================================================
# Add project root to Python path
# ============================================================
PROJECT_ROOT = r"D:\5G_Wireless_IDS"

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ============================================================
# Import ORIGINAL trained model definition
# ============================================================
from models.htstcl_gnn import HTSTCL_GNN


# ============================================================
# Paths
# ============================================================
MODEL_PATH = (
    r"D:\5G_Wireless_IDS"
    r"\htstcl_gnn_models"
    r"\htstcl_gnn_best.pth"
)


print("=" * 70)
print("STEP 1.4 - LOAD ORIGINAL TRAINED HTSTCL-GNN")
print("=" * 70)


# ============================================================
# Check PyTorch
# ============================================================
print("\nPyTorch version:")
print(torch.__version__)


# ============================================================
# Load checkpoint
# ============================================================
print("\nLoading checkpoint...")

checkpoint = torch.load(
    MODEL_PATH,
    map_location="cpu"
)

print("Checkpoint loaded successfully.")


# ============================================================
# Display training information
# ============================================================
print("\nTRAINING INFORMATION")
print("-" * 70)

print("Best Epoch          :", checkpoint["epoch"])
print("Validation Loss     :", checkpoint["val_loss"])
print("Validation Accuracy :", checkpoint["val_accuracy"])


# ============================================================
# Create ORIGINAL model
# ============================================================
print("\nCreating original HTSTCL-GNN model...")

model = HTSTCL_GNN(
    input_dim=91,
    hidden_dim=128,
    embedding_dim=128,
    num_classes=2,
    gru_layers=2,
    dropout=0.3
)


# ============================================================
# Load trained weights
# ============================================================
print("\nLoading trained model_state_dict...")

model.load_state_dict(
    checkpoint["model_state_dict"]
)

print("Trained weights loaded successfully.")


# ============================================================
# Evaluation mode
# ============================================================
model.eval()

print("\nModel switched to evaluation mode.")
print("Dropout: OFF")


# ============================================================
# Display model
# ============================================================
print("\nORIGINAL MODEL ARCHITECTURE")
print("-" * 70)

print(model)


# ============================================================
# Parameter count
# ============================================================
total_parameters = sum(
    p.numel() for p in model.parameters()
)

trainable_parameters = sum(
    p.numel()
    for p in model.parameters()
    if p.requires_grad
)

print("\nMODEL PARAMETERS")
print("-" * 70)

print("Total parameters     :", total_parameters)
print("Trainable parameters :", trainable_parameters)


# ============================================================
# Final verification
# ============================================================
print("\n" + "=" * 70)
print("STEP 1.4 COMPLETE")
print("=" * 70)

print("\nSTATUS:")
print("✓ Original model class imported")
print("✓ Checkpoint loaded")
print("✓ model_state_dict loaded")
print("✓ Architecture dimensions verified")
print("✓ Evaluation mode enabled")
print("✓ Trained HTSTCL-GNN ready for inference")

print("\nNext:")
print("Verify predictions on the ORIGINAL Python test dataset.")
print("=" * 70)