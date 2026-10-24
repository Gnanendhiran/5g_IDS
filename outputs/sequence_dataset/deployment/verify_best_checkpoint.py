import torch

MODEL_PATH = r"D:\5G_Wireless_IDS\htstcl_gnn_models\htstcl_gnn_best.pth"

print("=" * 70)
print("STEP 1.3 - VERIFY TRAINED HTSTCL-GNN CHECKPOINT")
print("=" * 70)

# ------------------------------------------------------------
# Load checkpoint
# ------------------------------------------------------------
checkpoint = torch.load(
    MODEL_PATH,
    map_location="cpu"
)

print("\nCheckpoint loaded successfully.")

# ------------------------------------------------------------
# Check checkpoint information
# ------------------------------------------------------------
print("\nCHECKPOINT INFORMATION")
print("-" * 70)

print("Epoch       :", checkpoint["epoch"])
print("Validation Loss      :", checkpoint["val_loss"])
print("Validation Accuracy  :", checkpoint["val_accuracy"])

# ------------------------------------------------------------
# Model state dictionary
# ------------------------------------------------------------
state_dict = checkpoint["model_state_dict"]

print("\nMODEL STATE DICTIONARY")
print("-" * 70)

print("Number of parameter tensors :", len(state_dict))

for name, tensor in state_dict.items():
    print(f"{name:55s} {tuple(tensor.shape)}")

# ------------------------------------------------------------
# Basic expected dimensions
# ------------------------------------------------------------
print("\nDIMENSION VERIFICATION")
print("-" * 70)

expected_features = 91
expected_hidden = 128
expected_embedding = 128
expected_classes = 2

print("Expected input features :", expected_features)
print("Expected hidden dim     :", expected_hidden)
print("Expected embedding dim  :", expected_embedding)
print("Expected classes        :", expected_classes)

# ------------------------------------------------------------
# Look for important layers
# ------------------------------------------------------------
print("\nIMPORTANT LAYER CHECK")
print("-" * 70)

for name in state_dict.keys():

    if any(key in name.lower() for key in [
        "gat",
        "spatial",
        "gru",
        "temporal",
        "fusion",
        "projection",
        "classifier"
    ]):
        print("FOUND:", name)

# ------------------------------------------------------------
# Final
# ------------------------------------------------------------
print("\n" + "=" * 70)
print("CHECKPOINT VERIFICATION COMPLETE")
print("=" * 70)