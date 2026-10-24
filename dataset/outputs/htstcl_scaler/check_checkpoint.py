import torch
from pathlib import Path

CHECKPOINT = Path(
    r"D:\5G_Wireless_IDS\htstcl_gnn_models\htstcl_gnn_best.pth"
)

print("=" * 70)
print("HTSTCL-GNN CHECKPOINT INSPECTION")
print("=" * 70)

print("\nCheckpoint:")
print(CHECKPOINT)

if not CHECKPOINT.exists():
    raise FileNotFoundError(f"Checkpoint not found: {CHECKPOINT}")

checkpoint = torch.load(
    CHECKPOINT,
    map_location="cpu",
    weights_only=False
)

print("\nCheckpoint type:")
print(type(checkpoint))

if isinstance(checkpoint, dict):

    print("\nCheckpoint keys:")
    for key in checkpoint.keys():
        print("  ", key)

    state_dict = None

    # Common checkpoint formats
    if "model_state_dict" in checkpoint:
        state_dict = checkpoint["model_state_dict"]
        print("\nUsing: model_state_dict")

    elif "state_dict" in checkpoint:
        state_dict = checkpoint["state_dict"]
        print("\nUsing: state_dict")

    elif all(
        isinstance(v, torch.Tensor)
        for v in checkpoint.values()
    ):
        state_dict = checkpoint
        print("\nUsing checkpoint itself as state_dict")

    if state_dict is not None:

        print("\nNumber of parameters:")
        print(len(state_dict))

        print("\nFirst 30 state-dict keys:")
        for i, key in enumerate(state_dict.keys()):
            if i >= 30:
                break

            tensor = state_dict[key]

            print(
                f"{key:60s} "
                f"{tuple(tensor.shape)}"
            )

else:
    print("\nCheckpoint is not a dictionary.")

print("\n" + "=" * 70)
print("CHECKPOINT INSPECTION COMPLETE")
print("=" * 70)