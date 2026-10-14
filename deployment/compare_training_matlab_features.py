import os
import numpy as np
import pandas as pd
import scipy.io
import h5py

# ============================================================
# PHASE 10B
# PYTHON TRAINING vs MATLAB FEATURE COMPATIBILITY ANALYSIS
# ============================================================

print("\n" + "=" * 75)
print(" PHASE 10B - PYTHON/MATLAB FEATURE COMPATIBILITY ANALYSIS")
print("=" * 75)

# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

MATLAB_INPUT = (
    r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB"
    r"\results\ids\matlab_ids_input.mat"
)

SCALER_FILE = (
    r"D:\5G_Wireless_IDS\outputs\sequence_dataset"
    r"\python_scaler_91.mat"
)

OUTPUT_DIR = r"D:\5G_Wireless_IDS\outputs\matlab_ids"

os.makedirs(OUTPUT_DIR, exist_ok=True)

CSV_OUTPUT = os.path.join(
    OUTPUT_DIR,
    "phase10B_feature_compatibility.csv"
)

# ------------------------------------------------------------
# EXACT 91 PYTHON TRAINING FEATURE NAMES
# ------------------------------------------------------------

FEATURE_NAMES = [
    "Dur",
    "RunTime",
    "Mean",
    "Sum",
    "Min",
    "Max",
    "sTos",
    "dTos",
    "sTtl",
    "dTtl",
    "sHops",
    "dHops",
    "TotPkts",
    "SrcPkts",
    "DstPkts",
    "TotBytes",
    "SrcBytes",
    "DstBytes",
    "Offset",
    "sMeanPktSz",
    "dMeanPktSz",
    "Load",
    "SrcLoad",
    "DstLoad",
    "Loss",
    "SrcLoss",
    "DstLoss",
    "pLoss",
    "SrcGap",
    "DstGap",
    "Rate",
    "SrcRate",
    "DstRate",
    "SrcWin",
    "DstWin",
    "sVid",
    "dVid",
    "SrcTCPBase",
    "DstTCPBase",
    "TcpRtt",
    "SynAck",
    "AckDat",
    " *        ",
    " *    V   ",
    " *    f   ",
    " e        ",
    " e    f   ",
    " e &      ",
    " e *      ",
    " e d      ",
    " e g      ",
    " e i      ",
    " e r      ",
    " e s      ",
    " eU       ",
    "e        ",
    "arp",
    "icmp",
    "ipv6-icmp",
    "llc",
    "lldp",
    "sctp",
    "tcp",
    "udp",
    "ACC",
    "CON",
    "ECO",
    "FIN",
    "INT",
    "NRS",
    "REQ",
    "RSP",
    "RST",
    "TST",
    "URP",
    "Shutdown",
    "Start",
    "Status",
    "39",
    "4",
    "52",
    "54",
    "af11",
    "af12",
    "af41",
    "cs0",
    "cs4",
    "cs6",
    "cs7",
    "ef",
    "nan"
]

assert len(FEATURE_NAMES) == 91

# ------------------------------------------------------------
# LOAD MATLAB V7.3 FILE
# ------------------------------------------------------------

print("\nLoading MATLAB input...")

try:
    data = scipy.io.loadmat(MATLAB_INPUT)

    X = np.asarray(
        data["X91_sequences"],
        dtype=np.float32
    )

    print("Loaded using scipy.io.loadmat")

except NotImplementedError:

    print("MATLAB file is v7.3. Using h5py...")

    with h5py.File(MATLAB_INPUT, "r") as f:

        X = np.asarray(
            f["X91_sequences"],
            dtype=np.float32
        )

    print("Loaded using h5py")

print("\nOriginal MATLAB array shape:")
print(X.shape)

# ------------------------------------------------------------
# NORMALIZE ARRAY ORDER
#
# Current MATLAB export through v7.3 is read by h5py as:
# [sequence, graph, node, feature]
#
# Convert to:
# [feature, graph, node, sequence]
# ------------------------------------------------------------

if X.ndim != 4:
    raise ValueError(
        f"Expected 4-D X91_sequences, got {X.ndim}-D"
    )

if X.shape[-1] == 91:

    # [sequence, graph, node, feature]
    X = np.transpose(
        X,
        (3, 1, 2, 0)
    )

elif X.shape[0] == 91:

    # Already [feature, graph, node, sequence]
    pass

else:
    raise ValueError(
        f"Cannot identify feature dimension in shape {X.shape}"
    )

print("Normalized MATLAB array shape:")
print(X.shape)

if X.shape[0] != 91:
    raise ValueError("Feature dimension is not 91.")

num_sequences = X.shape[3]

print("\nNumber of sequences:", num_sequences)

# ------------------------------------------------------------
# FLATTEN
#
# [91, graph, node, sequence]
# ->
# [sequence, graph, node, 91]
# ->
# [6000, 91]
# ------------------------------------------------------------

X_flat = np.transpose(
    X,
    (3, 1, 2, 0)
).reshape(-1, 91)

print("Flattened MATLAB features:")
print(X_flat.shape)

# ------------------------------------------------------------
# LOAD PYTHON SCALER
# ------------------------------------------------------------

print("\nLoading Python training scaler...")

scaler = scipy.io.loadmat(SCALER_FILE)

mean_ = np.asarray(
    scaler["mean_"],
    dtype=np.float64
).reshape(-1)

scale_ = np.asarray(
    scaler["scale_"],
    dtype=np.float64
).reshape(-1)

if len(mean_) != 91 or len(scale_) != 91:
    raise ValueError("Python scaler is not 91-dimensional.")

print("Scaler dimensions:", len(mean_))

# ------------------------------------------------------------
# APPLY TRAINING SCALER
# ------------------------------------------------------------

X_scaled = (
    X_flat.astype(np.float64) - mean_
) / scale_

# ------------------------------------------------------------
# BUILD FEATURE REPORT
# ------------------------------------------------------------

rows = []

for i, name in enumerate(FEATURE_NAMES):

    raw = X_flat[:, i]
    scaled = X_scaled[:, i]

    raw_mean = np.mean(raw)
    raw_std = np.std(raw)

    raw_min = np.min(raw)
    raw_max = np.max(raw)

    zero_percent = (
        np.mean(np.isclose(raw, 0.0))
        * 100.0
    )

    scaled_mean = np.mean(scaled)
    scaled_std = np.std(scaled)

    abs_z = np.abs(scaled)

    outlier_3 = np.mean(abs_z > 3) * 100
    outlier_5 = np.mean(abs_z > 5) * 100
    outlier_10 = np.mean(abs_z > 10) * 100

    rows.append({
        "Index": i + 1,
        "Feature": name,

        "TrainingScalerMean": mean_[i],
        "TrainingScalerScale": scale_[i],

        "MATLABRawMean": raw_mean,
        "MATLABRawStd": raw_std,
        "MATLABRawMin": raw_min,
        "MATLABRawMax": raw_max,

        "MATLABZeroPercent": zero_percent,

        "ScaledMean": scaled_mean,
        "ScaledStd": scaled_std,

        "AbsZ_GT_3_Percent": outlier_3,
        "AbsZ_GT_5_Percent": outlier_5,
        "AbsZ_GT_10_Percent": outlier_10
    })

report = pd.DataFrame(rows)

# ------------------------------------------------------------
# CLASS LABELS
#
# Current deployment construction:
# first 120 sequences = benign
# next 120 sequences = malicious
#
# 25 nodes per sequence.
# ------------------------------------------------------------

labels = np.repeat(
    np.concatenate([
        np.zeros(num_sequences // 2),
        np.ones(num_sequences // 2)
    ]),
    25
)

if len(labels) != len(X_flat):

    print(
        "\nWARNING: Could not construct class labels "
        "from assumed balanced sequence layout."
    )

else:

    benign_mask = labels == 0
    malicious_mask = labels == 1

    benign_means = np.mean(
        X_flat[benign_mask],
        axis=0
    )

    malicious_means = np.mean(
        X_flat[malicious_mask],
        axis=0
    )

    difference = np.abs(
        malicious_means - benign_means
    )

    report["BenignMean"] = benign_means
    report["MaliciousMean"] = malicious_means
    report["ClassMeanDifference"] = difference

# ------------------------------------------------------------
# SORT MOST IMPORTANT MISMATCHES
# ------------------------------------------------------------

report["DistributionMismatch"] = (
    np.abs(report["ScaledMean"])
    + np.abs(report["ScaledStd"] - 1.0)
)

report_sorted = report.sort_values(
    "DistributionMismatch",
    ascending=False
)

# ------------------------------------------------------------
# SAVE COMPLETE REPORT
# ------------------------------------------------------------

report.to_csv(
    CSV_OUTPUT,
    index=False
)

# ------------------------------------------------------------
# PRINT RESULTS
# ------------------------------------------------------------

print("\n" + "=" * 75)
print(" TOP FEATURES WITH LARGEST DISTRIBUTION MISMATCH")
print("=" * 75)

display_cols = [
    "Index",
    "Feature",
    "MATLABRawMean",
    "MATLABRawStd",
    "ScaledMean",
    "ScaledStd",
    "AbsZ_GT_5_Percent"
]

print(
    report_sorted[
        display_cols
    ].head(30).to_string(
        index=False
    )
)

# ------------------------------------------------------------
# ZERO FEATURES
# ------------------------------------------------------------

zero_features = report[
    report["MATLABZeroPercent"] >= 99.99
]

print("\n" + "=" * 75)
print(" CONSTANT / ZERO MATLAB FEATURES")
print("=" * 75)

print(
    f"Count: {len(zero_features)} / 91"
)

for _, row in zero_features.iterrows():

    print(
        f"{int(row['Index']):2d}  "
        f"{row['Feature']}"
    )

# ------------------------------------------------------------
# FEATURES WITH REASONABLE STANDARDIZED DISTRIBUTION
# ------------------------------------------------------------

reasonable = report[
    (np.abs(report["ScaledMean"]) < 3)
    &
    (report["ScaledStd"] > 0.25)
    &
    (report["ScaledStd"] < 3)
]

print("\n" + "=" * 75)
print(" FEATURES WITH RELATIVELY REASONABLE SCALED DISTRIBUTION")
print("=" * 75)

print(
    f"Count: {len(reasonable)} / 91"
)

for _, row in reasonable.iterrows():

    print(
        f"{int(row['Index']):2d}  "
        f"{row['Feature']:15s} "
        f"mean={row['ScaledMean']:8.3f} "
        f"std={row['ScaledStd']:8.3f}"
    )

# ------------------------------------------------------------
# CLASS-SEPARATING FEATURES
# ------------------------------------------------------------

if "ClassMeanDifference" in report.columns:

    class_sorted = report.sort_values(
        "ClassMeanDifference",
        ascending=False
    )

    print("\n" + "=" * 75)
    print(" STRONGEST MATLAB BENIGN/MALICIOUS FEATURE DIFFERENCES")
    print("=" * 75)

    print(
        class_sorted[
            [
                "Index",
                "Feature",
                "BenignMean",
                "MaliciousMean",
                "ClassMeanDifference"
            ]
        ].head(30).to_string(
            index=False
        )
    )

# ------------------------------------------------------------
# EXTREME SCALED FEATURES
# ------------------------------------------------------------

extreme = report[
    report["AbsZ_GT_5_Percent"] > 50
]

print("\n" + "=" * 75)
print(" EXTREME FEATURES (>50% OF VALUES HAVE |Z| > 5)")
print("=" * 75)

print(
    f"Count: {len(extreme)}"
)

for _, row in extreme.iterrows():

    print(
        f"{int(row['Index']):2d} "
        f"{row['Feature']:15s} "
        f"|Z|>5 = "
        f"{row['AbsZ_GT_5_Percent']:7.2f}%"
    )

# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

print("\n" + "=" * 75)
print(" PHASE 10B SUMMARY")
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
    "Zero/constant features:",
    len(zero_features)
)

print(
    "Reasonably distributed features:",
    len(reasonable)
)

print(
    "Extreme features:",
    len(extreme)
)

print(
    "Mean |scaled value|:",
    np.mean(np.abs(X_scaled))
)

print(
    "Maximum |scaled value|:",
    np.max(np.abs(X_scaled))
)

print("\nComplete report:")
print(CSV_OUTPUT)

print("\nNo model weights were modified.")
print("No training was performed.")
print("No scaler was modified.")

print("\n" + "=" * 75)
print(" PHASE 10B COMPLETE")
print("=" * 75)