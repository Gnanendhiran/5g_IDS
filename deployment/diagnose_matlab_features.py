import os
import numpy as np
import torch
from scipy.io import loadmat
import h5py


# ================================================================
# PATHS
# ================================================================

MATLAB_INPUT = (
    r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB"
    r"\results\ids\matlab_ids_input.mat"
)

SCALER_FILE = (
    r"D:\5G_Wireless_IDS"
    r"\outputs\sequence_dataset\python_scaler_91.mat"
)


# ================================================================
# LOAD MATLAB FILE
# ================================================================

def load_mat(path):

    try:

        return loadmat(path)

    except NotImplementedError:

        data = {}

        with h5py.File(path, "r") as f:

            for key in f.keys():

                data[key] = np.array(f[key])

        return data


# ================================================================
# MAIN
# ================================================================

def main():

    print("\n")
    print("=" * 75)
    print(" PHASE 10A - MATLAB FEATURE DISTRIBUTION DIAGNOSTIC")
    print("=" * 75)

    # ------------------------------------------------------------
    # Load MATLAB data
    # ------------------------------------------------------------

    data = load_mat(
        MATLAB_INPUT
    )

    X = np.asarray(
        data["X91_sequences"],
        dtype=np.float32
    )

    # MATLAB v7.3:
    #
    # [N, 5, 5, 91]
    #
    # Convert:
    #
    # [91, 5, 5, N]

    if X.shape[-1] == 91:

        X = np.transpose(
            X,
            (3, 1, 2, 0)
        )

    print("\nMATLAB feature shape:")
    print(X.shape)

    # ------------------------------------------------------------
    # Flatten all nodes
    # ------------------------------------------------------------

    X_flat = np.transpose(
        X,
        (3, 2, 1, 0)
    ).reshape(
        -1,
        91
    )

    print(
        "\nFlattened MATLAB features:",
        X_flat.shape
    )

    # ------------------------------------------------------------
    # Labels
    # ------------------------------------------------------------

    labels = np.asarray(
        data["sequenceLabels"]
    ).reshape(-1)

    labels = labels.astype(
        np.int64
    )

    print(
        "Sequences:",
        len(labels)
    )

    # ------------------------------------------------------------
    # Load scaler
    # ------------------------------------------------------------

    scaler = loadmat(
        SCALER_FILE
    )

    mean_ = np.asarray(
        scaler["mean_"],
        dtype=np.float32
    ).reshape(-1)

    scale_ = np.asarray(
        scaler["scale_"],
        dtype=np.float32
    ).reshape(-1)

    # ------------------------------------------------------------
    # Feature names
    # ------------------------------------------------------------

    feature_names = None

    if "featureNames91" in data:

        raw_names = data[
            "featureNames91"
        ]

        names = []

        for item in raw_names.reshape(-1):

            if isinstance(item, bytes):

                names.append(
                    item.decode(
                        errors="ignore"
                    )
                )

            else:

                names.append(
                    str(item)
                )

        if len(names) == 91:

            feature_names = names

    if feature_names is None:

        feature_names = [
            f"Feature_{i+1}"
            for i in range(91)
        ]

    # ------------------------------------------------------------
    # Scaled MATLAB data
    # ------------------------------------------------------------

    X_scaled = (
        X_flat - mean_
    ) / scale_

    # ============================================================
    # BASIC STATISTICS
    # ============================================================

    print("\n")
    print("=" * 75)
    print("FEATURE STATISTICS")
    print("=" * 75)

    print(
        f"{'No.':>3} "
        f"{'Feature':<20} "
        f"{'Raw Mean':>12} "
        f"{'Raw Std':>12} "
        f"{'Raw Min':>12} "
        f"{'Raw Max':>12} "
        f"{'Zero %':>9} "
        f"{'Scaled Mean':>12} "
        f"{'Scaled Std':>12}"
    )

    print("-" * 115)

    for i in range(91):

        raw = X_flat[:, i]

        scaled = X_scaled[:, i]

        zero_pct = (
            np.mean(
                raw == 0
            )
            * 100
        )

        print(
            f"{i+1:3d} "
            f"{feature_names[i][:20]:<20} "
            f"{np.mean(raw):12.4f} "
            f"{np.std(raw):12.4f} "
            f"{np.min(raw):12.4f} "
            f"{np.max(raw):12.4f} "
            f"{zero_pct:8.2f}% "
            f"{np.mean(scaled):12.4f} "
            f"{np.std(scaled):12.4f}"
        )

    # ============================================================
    # ZERO-FEATURE ANALYSIS
    # ============================================================

    zero_percentage = np.mean(
        X_flat == 0,
        axis=0
    ) * 100

    print("\n")
    print("=" * 75)
    print("ZERO-FILLED / CONSTANT FEATURES")
    print("=" * 75)

    zero_features = np.where(
        zero_percentage >= 99.99
    )[0]

    print(
        "Features effectively zero:",
        len(zero_features)
    )

    for i in zero_features:

        print(
            f"{i+1:3d} "
            f"{feature_names[i]}"
        )

    # ============================================================
    # MALICIOUS VS BENIGN
    # ============================================================

    print("\n")
    print("=" * 75)
    print("BENIGN VS MALICIOUS FEATURE DIFFERENCE")
    print("=" * 75)

    benign_sequence_idx = np.where(
        labels == 0
    )[0]

    malicious_sequence_idx = np.where(
        labels == 1
    )[0]

    # Each sequence contains:
    # 25 nodes/records

    benign_nodes = np.concatenate([
        np.arange(
            i * 25,
            (i + 1) * 25
        )
        for i in benign_sequence_idx
    ])

    malicious_nodes = np.concatenate([
        np.arange(
            i * 25,
            (i + 1) * 25
        )
        for i in malicious_sequence_idx
    ])

    benign_mean = np.mean(
        X_flat[benign_nodes],
        axis=0
    )

    malicious_mean = np.mean(
        X_flat[malicious_nodes],
        axis=0
    )

    difference = np.abs(
        malicious_mean
        -
        benign_mean
    )

    order = np.argsort(
        difference
    )[::-1]

    print(
        f"{'No.':>3} "
        f"{'Feature':<20} "
        f"{'Benign Mean':>15} "
        f"{'Malicious Mean':>15} "
        f"{'Difference':>15}"
    )

    print("-" * 75)

    for idx in order[:25]:

        print(
            f"{idx+1:3d} "
            f"{feature_names[idx][:20]:<20} "
            f"{benign_mean[idx]:15.4f} "
            f"{malicious_mean[idx]:15.4f} "
            f"{difference[idx]:15.4f}"
        )

    # ============================================================
    # SCALED OUTLIER ANALYSIS
    # ============================================================

    print("\n")
    print("=" * 75)
    print("SCALED FEATURE OUTLIER ANALYSIS")
    print("=" * 75)

    extreme = np.mean(
        np.abs(X_scaled) > 5,
        axis=0
    ) * 100

    extreme_order = np.argsort(
        extreme
    )[::-1]

    print(
        f"{'No.':>3} "
        f"{'Feature':<20} "
        f"{'|Z| > 5 %':>12} "
        f"{'Scaled Mean':>15} "
        f"{'Scaled Std':>15}"
    )

    print("-" * 75)

    for idx in extreme_order[:25]:

        print(
            f"{idx+1:3d} "
            f"{feature_names[idx][:20]:<20} "
            f"{extreme[idx]:12.2f} "
            f"{np.mean(X_scaled[:,idx]):15.4f} "
            f"{np.std(X_scaled[:,idx]):15.4f}"
        )

    # ============================================================
    # SUMMARY
    # ============================================================

    print("\n")
    print("=" * 75)
    print("DIAGNOSTIC SUMMARY")
    print("=" * 75)

    print(
        "Total MATLAB nodes:",
        len(X_flat)
    )

    print(
        "Total features:",
        X_flat.shape[1]
    )

    print(
        "Constant/zero features:",
        len(zero_features)
    )

    print(
        "Mean absolute scaled value:",
        f"{np.mean(np.abs(X_scaled)):.4f}"
    )

    print(
        "Maximum absolute scaled value:",
        f"{np.max(np.abs(X_scaled)):.4f}"
    )

    print(
        "\nThis diagnostic does NOT modify the trained model."
    )

    print(
        "No training or weight updates were performed."
    )

    print(
        "\nPhase 10A diagnostic complete."
    )


if __name__ == "__main__":

    main()