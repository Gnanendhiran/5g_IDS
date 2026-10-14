import os
import sys
import torch
import numpy as np

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    classification_report
)


# ============================================================
# HTSTCL-GNN - TRAINED MODEL INFERENCE ONLY
# ============================================================
#
# This script:
#
#   1. Loads the already-trained Kaggle model
#   2. Loads the original graph-sequence dataset
#   3. Uses the ORIGINAL HTSTCL_GNN forward() function
#   4. Reads output["logits"]
#   5. Performs inference only
#
# NO TRAINING IS PERFORMED.
# NO MODEL WEIGHTS ARE MODIFIED.
#
# ============================================================


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = r"D:\5G_Wireless_IDS"

MODEL_FILE = os.path.join(
    PROJECT_ROOT,
    "htstcl_gnn_models",
    "htstcl_gnn_best.pth"
)

DATASET_FILE = os.path.join(
    PROJECT_ROOT,
    "outputs",
    "sequence_dataset",
    "graph_sequences.pt"
)


# ============================================================
# 2. MAKE PROJECT IMPORTABLE
# ============================================================

if PROJECT_ROOT not in sys.path:

    sys.path.insert(
        0,
        PROJECT_ROOT
    )


# ============================================================
# 3. IMPORT ORIGINAL TRAINED MODEL
# ============================================================

from models.htstcl_gnn import HTSTCL_GNN


# ============================================================
# 4. MODEL CONFIGURATION
# ============================================================

INPUT_DIM = 91

HIDDEN_DIM = 128

EMBEDDING_DIM = 128

NUM_CLASSES = 2

GRU_LAYERS = 2

DROPOUT = 0.3

SEQUENCE_LENGTH = 5

CLASS_NAMES = [
    "Benign",
    "Malicious"
]


# ============================================================
# 5. LOAD TRAINED MODEL
# ============================================================

def load_trained_model():

    print("=" * 70)
    print("LOADING TRAINED HTSTCL-GNN MODEL")
    print("=" * 70)

    # --------------------------------------------------------
    # Check model
    # --------------------------------------------------------

    if not os.path.isfile(MODEL_FILE):

        raise FileNotFoundError(
            "\nTrained model not found:\n"
            + MODEL_FILE
        )

    # --------------------------------------------------------
    # Load checkpoint
    # --------------------------------------------------------

    checkpoint = torch.load(
        MODEL_FILE,
        map_location="cpu"
    )

    # --------------------------------------------------------
    # Verify checkpoint
    # --------------------------------------------------------

    if not isinstance(
        checkpoint,
        dict
    ):

        raise ValueError(
            "Unexpected checkpoint format."
        )

    if "model_state_dict" not in checkpoint:

        raise KeyError(
            "Checkpoint does not contain "
            "'model_state_dict'."
        )

    # --------------------------------------------------------
    # Create ORIGINAL model architecture
    # --------------------------------------------------------

    model = HTSTCL_GNN(
        input_dim=INPUT_DIM,
        hidden_dim=HIDDEN_DIM,
        embedding_dim=EMBEDDING_DIM,
        num_classes=NUM_CLASSES,
        gru_layers=GRU_LAYERS,
        dropout=DROPOUT
    )

    # --------------------------------------------------------
    # Load trained weights
    # --------------------------------------------------------

    model.load_state_dict(
        checkpoint["model_state_dict"]
    )

    # --------------------------------------------------------
    # Evaluation mode
    # --------------------------------------------------------

    model.eval()

    # --------------------------------------------------------
    # Model information
    # --------------------------------------------------------

    parameter_count = sum(
        p.numel()
        for p in model.parameters()
    )

    print(
        f"Model file      : {MODEL_FILE}"
    )

    print(
        f"Checkpoint epoch: "
        f"{checkpoint.get('epoch', 'N/A')}"
    )

    print(
        f"Validation loss : "
        f"{checkpoint.get('val_loss', 'N/A')}"
    )

    print(
        f"Validation acc  : "
        f"{checkpoint.get('val_accuracy', 'N/A')}"
    )

    print(
        f"Parameter count : "
        f"{parameter_count:,}"
    )

    print()

    print(
        "Model loaded successfully."
    )

    print(
        "Inference mode  : model.eval()"
    )

    print(
        "Training        : DISABLED"
    )

    print(
        "Weights         : NOT MODIFIED"
    )

    return model


# ============================================================
# 6. LOAD GRAPH SEQUENCE DATASET
# ============================================================

def load_dataset():

    print("\n" + "=" * 70)
    print("LOADING GRAPH SEQUENCE DATASET")
    print("=" * 70)

    # --------------------------------------------------------
    # Check dataset
    # --------------------------------------------------------

    if not os.path.isfile(DATASET_FILE):

        raise FileNotFoundError(
            "\nGraph sequence dataset not found:\n"
            + DATASET_FILE
        )

    # --------------------------------------------------------
    # PyTorch 2.6+
    #
    # graph_sequences.pt contains PyTorch Geometric objects.
    #
    # This is a trusted local dataset generated by the project.
    # --------------------------------------------------------

    dataset = torch.load(
        DATASET_FILE,
        map_location="cpu",
        weights_only=False
    )

    if dataset is None:

        raise ValueError(
            "Dataset loaded as None."
        )

    if len(dataset) == 0:

        raise ValueError(
            "Dataset is empty."
        )

    print(
        f"Dataset file   : {DATASET_FILE}"
    )

    print(
        f"Total sequences: {len(dataset)}"
    )

    return dataset


# ============================================================
# 7. VERIFY DATASET
# ============================================================

def verify_dataset(dataset):

    print("\n" + "=" * 70)
    print("VERIFYING DATASET")
    print("=" * 70)

    # --------------------------------------------------------
    # First sequence
    # --------------------------------------------------------

    sequence = dataset[0]

    # --------------------------------------------------------
    # Graphs
    # --------------------------------------------------------

    if "graphs" not in sequence:

        raise ValueError(
            "Sequence does not contain 'graphs'."
        )

    graphs = sequence["graphs"]

    # --------------------------------------------------------
    # Sequence length
    # --------------------------------------------------------

    if len(graphs) != SEQUENCE_LENGTH:

        raise ValueError(
            f"Expected {SEQUENCE_LENGTH} graphs "
            f"per sequence, found {len(graphs)}."
        )

    # --------------------------------------------------------
    # First graph
    # --------------------------------------------------------

    graph = graphs[0]

    # --------------------------------------------------------
    # Features
    # --------------------------------------------------------

    if graph.x is None:

        raise ValueError(
            "Graph has no node features."
        )

    num_features = graph.x.shape[1]

    if num_features != INPUT_DIM:

        raise ValueError(
            f"Expected {INPUT_DIM} features, "
            f"found {num_features}."
        )

    # --------------------------------------------------------
    # Print
    # --------------------------------------------------------

    print(
        f"Sequence length : {len(graphs)}"
    )

    print(
        f"Nodes per graph : {graph.num_nodes}"
    )

    print(
        f"Input features  : {num_features}"
    )

    print(
        f"Edges per graph : "
        f"{graph.edge_index.shape[1]}"
    )

    print(
        f"First sequence label: "
        f"{sequence.get('label', 'N/A')}"
    )

    print()

    print(
        "Dataset structure verified successfully."
    )


# ============================================================
# 8. PREDICT ONE SEQUENCE
# ============================================================

@torch.no_grad()
def predict_sequence(
    model,
    sequence
):

    # --------------------------------------------------------
    # Get five graphs
    # --------------------------------------------------------

    graphs = sequence["graphs"]

    # --------------------------------------------------------
    # Check sequence
    # --------------------------------------------------------

    if len(graphs) != SEQUENCE_LENGTH:

        raise ValueError(
            f"Invalid sequence length: "
            f"{len(graphs)}. "
            f"Expected {SEQUENCE_LENGTH}."
        )

    # --------------------------------------------------------
    # IMPORTANT
    #
    # Your ORIGINAL HTSTCL_GNN.forward() expects:
    #
    #     batch_sequences
    #
    # The forward() returns:
    #
    # {
    #     'logits',
    #     'embedding',
    #     'projection',
    #     'spatial_embedding',
    #     'temporal_embedding',
    #     'spatial_weight',
    #     'temporal_weight'
    # }
    #
    # Therefore we use the exact original forward path.
    # --------------------------------------------------------

    output = model(
        [graphs]
    )

    # --------------------------------------------------------
    # Verify dictionary
    # --------------------------------------------------------

    if not isinstance(
        output,
        dict
    ):

        raise TypeError(
            "Unexpected model output type: "
            f"{type(output)}"
        )

    # --------------------------------------------------------
    # Verify logits
    # --------------------------------------------------------

    if "logits" not in output:

        raise KeyError(
            "Model output does not contain "
            "'logits'."
        )

    logits = output["logits"]

    # --------------------------------------------------------
    # Verify logits tensor
    # --------------------------------------------------------

    if not torch.is_tensor(logits):

        raise TypeError(
            "output['logits'] is not a tensor. "
            f"Found: {type(logits)}"
        )

    # --------------------------------------------------------
    # Expected shape:
    #
    #     [1, 2]
    #
    # --------------------------------------------------------

    if logits.dim() == 1:

        logits = logits.unsqueeze(0)

    if logits.shape[-1] != NUM_CLASSES:

        raise ValueError(
            f"Expected {NUM_CLASSES} "
            f"class logits, "
            f"found shape {tuple(logits.shape)}"
        )

    # --------------------------------------------------------
    # Convert logits to probabilities
    # --------------------------------------------------------

    probabilities = torch.softmax(
        logits,
        dim=-1
    )

    # --------------------------------------------------------
    # Predicted class
    # --------------------------------------------------------

    prediction = torch.argmax(
        probabilities,
        dim=-1
    ).item()

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return (
        prediction,
        probabilities.squeeze(0).cpu().numpy()
    )


# ============================================================
# 9. RUN INFERENCE
# ============================================================

def evaluate(
    model,
    dataset
):

    print("\n" + "=" * 70)
    print("RUNNING INFERENCE")
    print("=" * 70)

    y_true = []

    y_pred = []

    y_prob = []

    total = len(dataset)

    # --------------------------------------------------------
    # Process every sequence
    # --------------------------------------------------------

    for index, sequence in enumerate(dataset):

        prediction, probabilities = predict_sequence(
            model,
            sequence
        )

        # ----------------------------------------------------
        # Ground truth
        # ----------------------------------------------------

        label = sequence["label"]

        if torch.is_tensor(label):

            label = label.item()

        label = int(label)

        # ----------------------------------------------------
        # Store
        # ----------------------------------------------------

        y_true.append(
            label
        )

        y_pred.append(
            prediction
        )

        # Probability of malicious class
        y_prob.append(
            probabilities[1]
        )

        # ----------------------------------------------------
        # Progress
        # ----------------------------------------------------

        if (
            (index + 1) % 500 == 0
            or
            index == total - 1
        ):

            print(
                f"Processed "
                f"{index + 1}/{total} sequences"
            )

    # --------------------------------------------------------
    # Convert to NumPy
    # --------------------------------------------------------

    y_true = np.asarray(
        y_true,
        dtype=np.int64
    )

    y_pred = np.asarray(
        y_pred,
        dtype=np.int64
    )

    y_prob = np.asarray(
        y_prob,
        dtype=np.float64
    )

    return (
        y_true,
        y_pred,
        y_prob
    )


# ============================================================
# 10. CALCULATE METRICS
# ============================================================

def print_results(
    y_true,
    y_pred,
    y_prob
):

    print("\n" + "=" * 70)
    print("TRAINED MODEL INFERENCE RESULTS")
    print("=" * 70)

    # --------------------------------------------------------
    # Accuracy
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    # --------------------------------------------------------
    # Precision
    # --------------------------------------------------------

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0
    )

    # --------------------------------------------------------
    # Recall
    # --------------------------------------------------------

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0
    )

    # --------------------------------------------------------
    # F1
    # --------------------------------------------------------

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    )

    # --------------------------------------------------------
    # ROC-AUC
    # --------------------------------------------------------

    try:

        roc_auc = roc_auc_score(
            y_true,
            y_prob
        )

    except ValueError:

        roc_auc = float("nan")

    # ========================================================
    # PRINT MAIN METRICS
    # ========================================================

    print()

    print(
        f"Accuracy  : {accuracy * 100:.2f}%"
    )

    print(
        f"Precision : {precision * 100:.2f}%"
    )

    print(
        f"Recall    : {recall * 100:.2f}%"
    )

    print(
        f"F1 Score  : {f1 * 100:.2f}%"
    )

    if not np.isnan(roc_auc):

        print(
            f"ROC-AUC   : {roc_auc * 100:.2f}%"
        )

    else:

        print(
            "ROC-AUC   : N/A"
        )

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    print()
    print("Confusion Matrix:")
    print()

    print(
        "                 Predicted"
    )

    print(
        "                 Benign  Malicious"
    )

    print(
        f"Actual Benign    "
        f"{cm[0, 0]:6d}  "
        f"{cm[0, 1]:9d}"
    )

    print(
        f"Actual Malicious "
        f"{cm[1, 0]:6d}  "
        f"{cm[1, 1]:9d}"
    )

    # ========================================================
    # CLASSIFICATION REPORT
    # ========================================================

    print()
    print("Classification Report:")
    print()

    report = classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=[
            "Benign",
            "Malicious"
        ],
        digits=4,
        zero_division=0
    )

    print(report)

    # ========================================================
    # RESULT DICTIONARY
    # ========================================================

    results = {

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1": f1,

        "roc_auc": roc_auc,

        "confusion_matrix": cm
    }

    return results


# ============================================================
# 11. MAIN
# ============================================================

def main():

    print()

    print("#" * 70)

    print(
        "# HTSTCL-GNN TRAINED MODEL - INFERENCE ONLY"
    )

    print("#" * 70)

    # ========================================================
    # STEP 1
    # Load trained model
    # ========================================================

    model = load_trained_model()

    # ========================================================
    # STEP 2
    # Load original dataset
    # ========================================================

    dataset = load_dataset()

    # ========================================================
    # STEP 3
    # Verify dataset
    # ========================================================

    verify_dataset(
        dataset
    )

    # ========================================================
    # STEP 4
    # Run inference
    # ========================================================

    (
        y_true,
        y_pred,
        y_prob
    ) = evaluate(
        model,
        dataset
    )

    # ========================================================
    # STEP 5
    # Calculate metrics
    # ========================================================

    results = print_results(
        y_true,
        y_pred,
        y_prob
    )

    # ========================================================
    # FINAL STATUS
    # ========================================================

    print()

    print("=" * 70)

    print(
        "INFERENCE COMPLETED"
    )

    print("=" * 70)

    print()

    print(
        "Training        : NOT PERFORMED"
    )

    print(
        "Weights updated : NO"
    )

    print(
        "Optimizer       : NOT USED"
    )

    print(
        "Model mode      : EVALUATION"
    )

    print(
        "Checkpoint      : htstcl_gnn_best.pth"
    )

    print()

    print(
        "The downloaded Kaggle-trained model "
        "was used directly."
    )

    print("=" * 70)


# ============================================================
# 12. PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    main()