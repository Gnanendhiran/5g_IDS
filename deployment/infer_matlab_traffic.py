"""
======================================================================
PHASE 10
MATLAB 5G TRAFFIC -> TRAINED HTSTCL-GNN IDS
======================================================================

Purpose
-------
Run the already-trained Python HTSTCL-GNN model on traffic generated
by the MATLAB 5G NR simulation.

IMPORTANT
---------
This script performs INFERENCE ONLY.

It does NOT:
    - train the model
    - update model weights
    - create a new scaler
    - fit StandardScaler
    - use an optimizer
    - modify the trained checkpoint

Pipeline
--------

MATLAB 5G NR Simulation
        |
        v
Phase 5 Traffic
        |
        v
91 MATLAB Model Features
        |
        v
MATLAB v7.3 MAT File
        |
        v
Python h5py Loader
        |
        v
Original Python StandardScaler
        |
        v
5 Nodes x 91 Features
        |
        v
KNN Graph
5 Nodes + 10 Directed Edges
        |
        v
5 Graphs
        |
        v
HTSTCL-GNN
GAT -> GRU -> Hierarchical Fusion
        |
        v
Benign / Malicious
        |
        v
Prediction + Probability
        |
        v
MATLAB-readable results

======================================================================
"""

# ======================================================================
# IMPORTS
# ======================================================================

import os
import sys
import csv

import numpy as np
import torch

from scipy.io import loadmat, savemat
from sklearn.neighbors import NearestNeighbors


# ======================================================================
# PATH CONFIGURATION
# ======================================================================

PYTHON_ROOT = r"D:\5G_Wireless_IDS"

# Trained model
MODEL_FILE = os.path.join(
    PYTHON_ROOT,
    "htstcl_gnn_models",
    "htstcl_gnn_best.pth"
)

# Original scaler exported from Python training
SCALER_FILE = os.path.join(
    PYTHON_ROOT,
    "outputs",
    "sequence_dataset",
    "python_scaler_91.mat"
)

# MATLAB export
MATLAB_INPUT = (
    r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB"
    r"\results\ids\matlab_ids_input.mat"
)

# Output directory
OUTPUT_DIR = os.path.join(
    PYTHON_ROOT,
    "outputs",
    "matlab_ids"
)

# Output MAT file
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "matlab_ids_predictions.mat"
)

# Output CSV
CSV_FILE = os.path.join(
    OUTPUT_DIR,
    "matlab_ids_predictions.csv"
)


# ======================================================================
# PYTHON PROJECT PATH
# ======================================================================

sys.path.insert(
    0,
    PYTHON_ROOT
)


# ======================================================================
# LOAD ORIGINAL MODEL CLASS
# ======================================================================

from models.htstcl_gnn import HTSTCL_GNN


# ======================================================================
# UTILITY: CHECK FILE
# ======================================================================

def check_file(path, description):

    if not os.path.isfile(path):

        raise FileNotFoundError(
            "\n"
            + "=" * 70
            + "\n"
            + description
            + " NOT FOUND\n"
            + "=" * 70
            + "\n"
            + path
            + "\n"
        )


# ======================================================================
# LOAD MATLAB MAT FILE
# ======================================================================

def load_matlab_file(path):

    """
    Load both:

        MATLAB <= v7.2
        MATLAB v7.3

    v7.3 files are HDF5 files and therefore require h5py.
    """

    print("\nLoading MATLAB traffic file...")
    print(path)

    # --------------------------------------------------------------
    # First try scipy
    # --------------------------------------------------------------

    try:

        data = loadmat(path)

        print(
            "MATLAB file format: standard MAT-file"
        )

        return data

    except NotImplementedError:

        pass

    # --------------------------------------------------------------
    # MATLAB v7.3
    # --------------------------------------------------------------

    try:

        import h5py

    except ImportError:

        raise ImportError(
            "\n"
            "MATLAB v7.3 file detected, but h5py is not installed.\n\n"
            "Install it using:\n\n"
            "    pip install h5py\n"
        )

    print(
        "MATLAB file format: v7.3"
    )

    print(
        "Using HDF5/h5py loader..."
    )

    data = {}

    with h5py.File(path, "r") as f:

        print("\nMATLAB variables found:")

        for key in f.keys():

            print(
                f"  {key}"
            )

            data[key] = np.array(
                f[key]
            )

    return data


# ======================================================================
# LOAD ORIGINAL PYTHON SCALER
# ======================================================================

def load_python_scaler(path):

    print("\n")
    print("=" * 70)
    print("LOADING ORIGINAL PYTHON STANDARD SCALER")
    print("=" * 70)

    print(path)

    scaler = loadmat(path)

    mean_ = np.asarray(
        scaler["mean_"],
        dtype=np.float32
    ).reshape(-1)

    scale_ = np.asarray(
        scaler["scale_"],
        dtype=np.float32
    ).reshape(-1)

    # --------------------------------------------------------------
    # Validate scaler
    # --------------------------------------------------------------

    if mean_.shape[0] != 91:

        raise ValueError(
            f"Scaler mean contains "
            f"{mean_.shape[0]} features. "
            f"Expected 91."
        )

    if scale_.shape[0] != 91:

        raise ValueError(
            f"Scaler scale contains "
            f"{scale_.shape[0]} features. "
            f"Expected 91."
        )

    if not np.all(
        np.isfinite(mean_)
    ):

        raise ValueError(
            "Scaler mean contains NaN or Inf."
        )

    if not np.all(
        np.isfinite(scale_)
    ):

        raise ValueError(
            "Scaler scale contains NaN or Inf."
        )

    if np.any(
        scale_ == 0
    ):

        raise ValueError(
            "Scaler contains zero scale values."
        )

    print(
        f"Scaler features : {len(mean_)}"
    )

    print(
        "Scaler verified  : 91 features"
    )

    return mean_, scale_


# ======================================================================
# APPLY ORIGINAL PYTHON STANDARD SCALER
# ======================================================================

def apply_python_scaler(
    X,
    mean_,
    scale_
):

    """
    Apply the SAME transformation used during Python training.

        X_scaled = (X - mean_) / scale_

    No new scaler is fitted here.
    """

    X = np.asarray(
        X,
        dtype=np.float32
    )

    if X.shape[-1] != 91:

        raise ValueError(
            f"Expected 91 features. "
            f"Received shape {X.shape}."
        )

    X_scaled = (
        X - mean_
    ) / scale_

    return X_scaled.astype(
        np.float32
    )


# ======================================================================
# BUILD KNN GRAPH
# ======================================================================

def build_knn_graph(X):

    """
    Construct the graph used by the trained model.

    Input:
        X = [5, 91]

    Output:
        edge_index = [2, 10]

    Graph:
        5 nodes
        10 directed edges

    Logic:
        sklearn NearestNeighbors
        n_neighbors = 3

    For every source node:
        - nearest neighbor is itself
        - take next two nearest nodes
        - create directed edges
    """

    X = np.asarray(
        X,
        dtype=np.float32
    )

    if X.shape != (5, 91):

        raise ValueError(
            f"Expected graph shape "
            f"(5, 91), got {X.shape}"
        )

    # --------------------------------------------------------------
    # KNN
    # --------------------------------------------------------------

    nbrs = NearestNeighbors(
        n_neighbors=3,
        metric="euclidean"
    )

    nbrs.fit(X)

    distances, indices = nbrs.kneighbors(X)

    edges = []

    # --------------------------------------------------------------
    # Two nearest OTHER nodes
    # --------------------------------------------------------------

    for source in range(5):

        neighbors_added = 0

        for position in range(
            1,
            indices.shape[1]
        ):

            target = int(
                indices[
                    source,
                    position
                ]
            )

            # No self loops
            if target == source:
                continue

            edges.append(
                (
                    source,
                    target
                )
            )

            neighbors_added += 1

            if neighbors_added >= 2:
                break

    # --------------------------------------------------------------
    # Remove duplicate directed edges
    # --------------------------------------------------------------

    unique_edges = list(
        dict.fromkeys(edges)
    )

    if len(unique_edges) != 10:

        raise ValueError(
            "KNN graph validation failed. "
            f"Expected 10 edges, "
            f"received {len(unique_edges)}."
        )

    edge_index = np.asarray(
        unique_edges,
        dtype=np.int64
    ).T

    # --------------------------------------------------------------
    # Final validation
    # --------------------------------------------------------------

    if edge_index.shape != (2, 10):

        raise ValueError(
            f"edge_index has shape "
            f"{edge_index.shape}, "
            f"expected (2, 10)."
        )

    return edge_index


# ======================================================================
# CREATE PYTORCH GEOMETRIC GRAPH
# ======================================================================

def make_pyg_graph(
    X,
    edge_index
):

    """
    Convert a NumPy graph into PyTorch Geometric Data.
    """

    from torch_geometric.data import Data

    x = torch.tensor(
        X,
        dtype=torch.float32
    )

    edge_index_tensor = torch.tensor(
        edge_index,
        dtype=torch.long
    )

    graph = Data(
        x=x,
        edge_index=edge_index_tensor
    )

    return graph


# ======================================================================
# EXTRACT MATLAB ARRAY
# ======================================================================

def extract_array(
    matlab_data,
    name
):

    if name not in matlab_data:

        raise KeyError(
            f"MATLAB variable '{name}' "
            f"was not found."
        )

    return np.asarray(
        matlab_data[name]
    )


# ======================================================================
# FIX MATLAB/PYTHON DIMENSION ORDER
# ======================================================================

def prepare_sequence_array(
    Xseq
):

    """
    MATLAB exporter creates:

        X91_sequences

        [91 x 5 x 5 x N]

    Meaning:

        dimension 1 = feature
        dimension 2 = node
        dimension 3 = graph/time
        dimension 4 = sequence

    h5py reads MATLAB v7.3 arrays with reversed dimension
    ordering compared with normal MATLAB interpretation.

    Therefore this function handles both possibilities.

    Desired final NumPy representation:

        [91, 5, 5, N]

    """

    Xseq = np.asarray(
        Xseq,
        dtype=np.float32
    )

    print(
        "\nRaw loaded X91_sequences shape:",
        Xseq.shape
    )

    # --------------------------------------------------------------
    # Case 1:
    # scipy.io.loadmat
    #
    # Already:
    # [91, 5, 5, N]
    # --------------------------------------------------------------

    if (
        Xseq.ndim == 4
        and Xseq.shape[0] == 91
        and Xseq.shape[1] == 5
        and Xseq.shape[2] == 5
    ):

        print(
            "Dimension order: MATLAB standard"
        )

        return Xseq

    # --------------------------------------------------------------
    # Case 2:
    # h5py MATLAB v7.3
    #
    # Usually:
    # [N, 5, 5, 91]
    #
    # Convert to:
    # [91, 5, 5, N]
    # --------------------------------------------------------------

    if (
        Xseq.ndim == 4
        and Xseq.shape[1] == 5
        and Xseq.shape[2] == 5
        and Xseq.shape[3] == 91
    ):

        print(
            "Dimension order: MATLAB v7.3/HDF5"
        )

        Xseq = np.transpose(
            Xseq,
            (3, 1, 2, 0)
        )

        print(
            "Converted X91_sequences shape:",
            Xseq.shape
        )

        return Xseq

    # --------------------------------------------------------------
    # Unexpected shape
    # --------------------------------------------------------------

    raise ValueError(
        "\n"
        "Unable to interpret X91_sequences.\n"
        f"Received shape: {Xseq.shape}\n"
        "\n"
        "Expected either:\n"
        "    [91, 5, 5, N]\n"
        "or\n"
        "    [N, 5, 5, 91]\n"
    )


# ======================================================================
# PREPARE LABEL ARRAY
# ======================================================================

def prepare_sequence_labels(
    matlab_data,
    num_sequences
):

    if "sequenceLabels" not in matlab_data:

        print(
            "\nWARNING: sequenceLabels not found."
        )

        return None

    labels = np.asarray(
        matlab_data["sequenceLabels"]
    ).reshape(-1)

    labels = labels.astype(
        np.int64
    )

    if len(labels) != num_sequences:

        raise ValueError(
            f"Expected {num_sequences} sequence labels, "
            f"received {len(labels)}."
        )

    # --------------------------------------------------------------
    # Validate binary labels
    # --------------------------------------------------------------

    unique_labels = np.unique(
        labels
    )

    if not np.all(
        np.isin(
            unique_labels,
            [0, 1]
        )
    ):

        raise ValueError(
            f"Unexpected labels: {unique_labels}"
        )

    return labels


# ======================================================================
# MAIN
# ======================================================================

def main():

    print("\n")
    print("=" * 70)
    print(" PHASE 10 - MATLAB TRAFFIC HTSTCL-GNN INFERENCE")
    print("=" * 70)

    # ==================================================================
    # 1. CHECK FILES
    # ==================================================================

    check_file(
        MODEL_FILE,
        "Trained HTSTCL-GNN checkpoint"
    )

    check_file(
        SCALER_FILE,
        "Original Python StandardScaler"
    )

    check_file(
        MATLAB_INPUT,
        "MATLAB IDS input file"
    )

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # ==================================================================
    # 2. SELECT DEVICE
    # ==================================================================

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print(
        "\nDevice:",
        device
    )

    # ==================================================================
    # 3. LOAD TRAINED MODEL
    # ==================================================================

    print("\n")
    print("=" * 70)
    print("LOADING TRAINED HTSTCL-GNN")
    print("=" * 70)

    print(
        "Checkpoint:",
        MODEL_FILE
    )

    checkpoint = torch.load(
        MODEL_FILE,
        map_location=device,
        weights_only=False
    )

    # --------------------------------------------------------------
    # Build EXACT original architecture
    # --------------------------------------------------------------

    model = HTSTCL_GNN(
        input_dim=91,
        hidden_dim=128,
        embedding_dim=128,
        num_classes=2,
        gru_layers=2,
        dropout=0.3
    )

    # --------------------------------------------------------------
    # Load trained weights
    # --------------------------------------------------------------

    model.load_state_dict(
        checkpoint[
            "model_state_dict"
        ]
    )

    model.to(device)

    # --------------------------------------------------------------
    # Evaluation mode
    # --------------------------------------------------------------

    model.eval()

    print(
        "Model loaded successfully."
    )

    print(
        "Model mode      : EVALUATION"
    )

    print(
        "Weights updated : NO"
    )

    print(
        "Optimizer used  : NO"
    )

    if "epoch" in checkpoint:

        print(
            "Checkpoint epoch:",
            checkpoint["epoch"]
        )

    if "val_accuracy" in checkpoint:

        print(
            "Checkpoint validation accuracy:",
            f"{checkpoint['val_accuracy']:.4f}%"
        )

    # ==================================================================
    # 4. LOAD ORIGINAL SCALER
    # ==================================================================

    mean_, scale_ = load_python_scaler(
        SCALER_FILE
    )

    # ==================================================================
    # 5. LOAD MATLAB FILE
    # ==================================================================

    matlab_data = load_matlab_file(
        MATLAB_INPUT
    )

    # --------------------------------------------------------------
    # Required variable
    # --------------------------------------------------------------

    Xseq_raw = extract_array(
        matlab_data,
        "X91_sequences"
    )

    # --------------------------------------------------------------
    # Convert dimension order
    # --------------------------------------------------------------

    Xseq = prepare_sequence_array(
        Xseq_raw
    )

    # --------------------------------------------------------------
    # Validate dimensions
    # --------------------------------------------------------------

    if Xseq.shape[0] != 91:

        raise ValueError(
            f"Expected 91 features, "
            f"got {Xseq.shape[0]}"
        )

    if Xseq.shape[1] != 5:

        raise ValueError(
            f"Expected 5 nodes per graph, "
            f"got {Xseq.shape[1]}"
        )

    if Xseq.shape[2] != 5:

        raise ValueError(
            f"Expected 5 graphs per sequence, "
            f"got {Xseq.shape[2]}"
        )

    num_sequences = Xseq.shape[3]

    print("\n")
    print("=" * 70)
    print("MATLAB INPUT VALIDATION")
    print("=" * 70)

    print(
        "Features per node  :",
        Xseq.shape[0]
    )

    print(
        "Nodes per graph    :",
        Xseq.shape[1]
    )

    print(
        "Graphs per sequence:",
        Xseq.shape[2]
    )

    print(
        "Total sequences    :",
        num_sequences
    )

    # ==================================================================
    # 6. LOAD GROUND TRUTH
    # ==================================================================

    true_labels = prepare_sequence_labels(
        matlab_data,
        num_sequences
    )

    if true_labels is not None:

        print(
            "\nGround-truth labels loaded."
        )

        print(
            "Benign sequences:",
            np.sum(
                true_labels == 0
            )
        )

        print(
            "Malicious sequences:",
            np.sum(
                true_labels == 1
            )
        )

    else:

        print(
            "\nGround-truth labels unavailable."
        )

    # ==================================================================
    # 7. PREPARE OUTPUT ARRAYS
    # ==================================================================

    predictions = np.zeros(
        num_sequences,
        dtype=np.int64
    )

    benign_probability = np.zeros(
        num_sequences,
        dtype=np.float32
    )

    malicious_probability = np.zeros(
        num_sequences,
        dtype=np.float32
    )

    # ==================================================================
    # 8. INFERENCE
    # ==================================================================

    print("\n")
    print("=" * 70)
    print("STARTING HTSTCL-GNN INFERENCE")
    print("=" * 70)

    print(
        "Sequences:",
        num_sequences
    )

    print(
        "Graphs/sequence: 5"
    )

    print(
        "Nodes/graph: 5"
    )

    print(
        "Features/node: 91"
    )

    print(
        "Edges/graph: 10"
    )

    print(
        "-" * 70
    )

    # --------------------------------------------------------------
    # Inference mode
    # --------------------------------------------------------------

    with torch.no_grad():

        for seq_idx in range(
            num_sequences
        ):

            graphs = []

            # ==========================================================
            # TEMPORAL GRAPHS
            # ==========================================================

            for graph_idx in range(5):

                # ------------------------------------------------------
                # Extract raw MATLAB graph
                #
                # Desired:
                #
                # [5 nodes x 91 features]
                # ------------------------------------------------------

                X_raw = Xseq[
                    :,
                    :,
                    graph_idx,
                    seq_idx
                ].T

                # ------------------------------------------------------
                # Validate
                # ------------------------------------------------------

                if X_raw.shape != (
                    5,
                    91
                ):

                    raise ValueError(
                        f"Sequence {seq_idx + 1}, "
                        f"graph {graph_idx + 1}: "
                        f"expected (5,91), "
                        f"got {X_raw.shape}"
                    )

                # ------------------------------------------------------
                # Apply ORIGINAL Python scaler
                # ------------------------------------------------------

                X_scaled = apply_python_scaler(
                    X_raw,
                    mean_,
                    scale_
                )

                # ------------------------------------------------------
                # Check scaled data
                # ------------------------------------------------------

                if not np.all(
                    np.isfinite(
                        X_scaled
                    )
                ):

                    raise ValueError(
                        f"NaN/Inf after scaling "
                        f"in sequence "
                        f"{seq_idx + 1}, "
                        f"graph "
                        f"{graph_idx + 1}"
                    )

                # ------------------------------------------------------
                # Build exact KNN graph
                # ------------------------------------------------------

                edge_index = build_knn_graph(
                    X_scaled
                )

                # ------------------------------------------------------
                # Convert to PyG
                # ------------------------------------------------------

                graph = make_pyg_graph(
                    X_scaled,
                    edge_index
                )

                graphs.append(
                    graph
                )

            # ==========================================================
            # RUN ORIGINAL MODEL
            # ==========================================================

            output = model(
                [graphs]
            )

            # ----------------------------------------------------------
            # Original model returns dictionary
            # ----------------------------------------------------------

            if not isinstance(
                output,
                dict
            ):

                raise TypeError(
                    "HTSTCL-GNN output is not a dictionary."
                )

            if "logits" not in output:

                raise KeyError(
                    "Model output does not contain 'logits'."
                )

            logits = output[
                "logits"
            ]

            # ----------------------------------------------------------
            # Softmax probabilities
            # ----------------------------------------------------------

            probabilities = torch.softmax(
                logits,
                dim=1
            )

            # ----------------------------------------------------------
            # Prediction
            # ----------------------------------------------------------

            prediction = torch.argmax(
                probabilities,
                dim=1
            ).item()

            predictions[
                seq_idx
            ] = prediction

            benign_probability[
                seq_idx
            ] = probabilities[
                0,
                0
            ].item()

            malicious_probability[
                seq_idx
            ] = probabilities[
                0,
                1
            ].item()

            # ==========================================================
            # PROGRESS
            # ==========================================================

            if (
                seq_idx == 0
                or (seq_idx + 1) % 10 == 0
                or seq_idx + 1 == num_sequences
            ):

                label_text = (
                    "MALICIOUS"
                    if prediction == 1
                    else "BENIGN"
                )

                print(
                    f"Sequence "
                    f"{seq_idx + 1:4d}/"
                    f"{num_sequences:<4d} "
                    f"-> "
                    f"{label_text:<9s} "
                    f"| P(B)="
                    f"{benign_probability[seq_idx]:.4f} "
                    f"| P(M)="
                    f"{malicious_probability[seq_idx]:.4f}"
                )

    # ==================================================================
    # 9. CALCULATE METRICS
    # ==================================================================

    accuracy = np.nan
    precision = np.nan
    recall = np.nan
    f1 = np.nan

    tn = 0
    fp = 0
    fn = 0
    tp = 0

    if true_labels is not None:

        tn = int(
            np.sum(
                (true_labels == 0)
                &
                (predictions == 0)
            )
        )

        fp = int(
            np.sum(
                (true_labels == 0)
                &
                (predictions == 1)
            )
        )

        fn = int(
            np.sum(
                (true_labels == 1)
                &
                (predictions == 0)
            )
        )

        tp = int(
            np.sum(
                (true_labels == 1)
                &
                (predictions == 1)
            )
        )

        # ----------------------------------------------------------
        # Metrics
        # ----------------------------------------------------------

        accuracy = (
            (tp + tn)
            /
            max(
                len(true_labels),
                1
            )
        )

        precision = (
            tp
            /
            max(
                tp + fp,
                1
            )
        )

        recall = (
            tp
            /
            max(
                tp + fn,
                1
            )
        )

        f1 = (
            2.0
            *
            precision
            *
            recall
            /
            max(
                precision + recall,
                1e-12
            )
        )

    # ==================================================================
    # 10. PRINT RESULTS
    # ==================================================================

    print("\n")
    print("=" * 70)
    print(" MATLAB 5G TRAFFIC IDS RESULTS")
    print("=" * 70)

    print(
        "\nTotal sequences:",
        num_sequences
    )

    print(
        "Benign predictions:",
        int(
            np.sum(
                predictions == 0
            )
        )
    )

    print(
        "Malicious predictions:",
        int(
            np.sum(
                predictions == 1
            )
        )
    )

    if true_labels is not None:

        print(
            "\nAccuracy  : "
            f"{accuracy * 100:.2f}%"
        )

        print(
            "Precision : "
            f"{precision * 100:.2f}%"
        )

        print(
            "Recall    : "
            f"{recall * 100:.2f}%"
        )

        print(
            "F1 Score  : "
            f"{f1 * 100:.2f}%"
        )

        print(
            "\nConfusion Matrix"
        )

        print(
            "----------------"
        )

        print(
            "                 Predicted"
        )

        print(
            "                 Benign  Malicious"
        )

        print(
            f"Actual Benign    "
            f"{tn:6d}  "
            f"{fp:9d}"
        )

        print(
            f"Actual Malicious "
            f"{fn:6d}  "
            f"{tp:9d}"
        )

    # ==================================================================
    # 11. SAVE MATLAB OUTPUT
    # ==================================================================

    output_data = {

        "predictions":
            predictions.astype(
                np.int32
            ),

        "benign_probability":
            benign_probability.astype(
                np.float32
            ),

        "malicious_probability":
            malicious_probability.astype(
                np.float32
            ),

        "num_sequences":
            np.array(
                [[num_sequences]],
                dtype=np.int32
            ),

        "accuracy":
            np.array(
                [[accuracy]],
                dtype=np.float64
            ),

        "precision":
            np.array(
                [[precision]],
                dtype=np.float64
            ),

        "recall":
            np.array(
                [[recall]],
                dtype=np.float64
            ),

        "f1":
            np.array(
                [[f1]],
                dtype=np.float64
            ),

        "true_negatives":
            np.array(
                [[tn]],
                dtype=np.int32
            ),

        "false_positives":
            np.array(
                [[fp]],
                dtype=np.int32
            ),

        "false_negatives":
            np.array(
                [[fn]],
                dtype=np.int32
            ),

        "true_positives":
            np.array(
                [[tp]],
                dtype=np.int32
            )
    }

    if true_labels is not None:

        output_data[
            "true_labels"
        ] = true_labels.astype(
            np.int32
        )

    # --------------------------------------------------------------
    # Save MAT
    # --------------------------------------------------------------

    savemat(
        OUTPUT_FILE,
        output_data
    )

    # ==================================================================
    # 12. SAVE CSV
    # ==================================================================

    with open(
        CSV_FILE,
        "w",
        newline=""
    ) as f:

        writer = csv.writer(
            f
        )

        writer.writerow([
            "SequenceID",
            "TrueLabel",
            "PredictedLabel",
            "BenignProbability",
            "MaliciousProbability"
        ])

        for i in range(
            num_sequences
        ):

            if true_labels is not None:

                true_value = int(
                    true_labels[i]
                )

            else:

                true_value = ""

            writer.writerow([
                i + 1,
                true_value,
                int(
                    predictions[i]
                ),
                float(
                    benign_probability[i]
                ),
                float(
                    malicious_probability[i]
                )
            ])

    # ==================================================================
    # 13. FINAL SUMMARY
    # ==================================================================

    print("\n")
    print("=" * 70)
    print(" PHASE 10 COMPLETE")
    print("=" * 70)

    print(
        "\nMATLAB sequences processed :",
        num_sequences
    )

    print(
        "Benign predictions         :",
        int(
            np.sum(
                predictions == 0
            )
        )
    )

    print(
        "Malicious predictions      :",
        int(
            np.sum(
                predictions == 1
            )
        )
    )

    print(
        "\nTrained model:"
    )

    print(
        "  HTSTCL-GNN"
    )

    print(
        "  htstcl_gnn_best.pth"
    )

    print(
        "\nTraining performed:"
    )

    print(
        "  NO"
    )

    print(
        "\nWeights updated:"
    )

    print(
        "  NO"
    )

    print(
        "\nOptimizer:"
    )

    print(
        "  NOT USED"
    )

    print(
        "\nScaler:"
    )

    print(
        "  Original Python StandardScaler"
    )

    print(
        "\nMATLAB output:"
    )

    print(
        OUTPUT_FILE
    )

    print(
        "\nCSV output:"
    )

    print(
        CSV_FILE
    )

    print(
        "\n" + "=" * 70
    )

    print(
        " PHASE 10 FINISHED SUCCESSFULLY"
    )

    print(
        "=" * 70
    )

    print()


# ======================================================================
# ENTRY POINT
# ======================================================================

if __name__ == "__main__":

    main()