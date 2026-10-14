# ================================================================
# Phase 10D
# Original Python Training Features vs MATLAB Phase 10C Features
#
# Purpose:
#   Compare the feature distributions used by the trained Python
#   HTSTCL-GNN model against the reconstructed MATLAB 91 features.
#
# IMPORTANT:
#   This script DOES NOT modify the trained model.
#   This script DOES NOT retrain the model.
#   This script DOES NOT modify the Python scaler.
#
# Output:
#   D:\5G_Wireless_IDS\outputs\matlab_ids\
#       phase10D_training_vs_matlab.csv
#
# ================================================================

import os
import numpy as np
import pandas as pd

from scipy.io import loadmat

# ================================================================
# Optional HDF5 support for MATLAB v7.3 files
# ================================================================

import h5py


# ================================================================
# PATHS
# ================================================================

PYTHON_TRAINING_FILE = (
    r"D:\5G_Wireless_IDS\outputs\progressive_windows\window_5.csv"
)

MATLAB_FEATURE_FILE = (
    r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB"
    r"\results\features\phase10C_reconstructed_features.mat"
)

OUTPUT_DIR = (
    r"D:\5G_Wireless_IDS\outputs\matlab_ids"
)

OUTPUT_CSV = os.path.join(
    OUTPUT_DIR,
    "phase10D_training_vs_matlab.csv"
)


# ================================================================
# EXACT 91 FEATURE ORDER USED BY PYTHON TRAINING
# ================================================================

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
    "nan",
]


# ================================================================
# HELPER
# ================================================================

def print_section(title):
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


# ================================================================
# LOAD MATLAB v7.3 FILE
# ================================================================

def load_matlab_v73(filename):
    """
    Load a MATLAB .mat file.

    First attempts scipy.io.loadmat().
    If the file is MATLAB v7.3, falls back to h5py.
    """

    try:
        mat = loadmat(filename)

        print("MATLAB file loaded using scipy.io.loadmat")

        return mat

    except NotImplementedError:

        print(
            "MATLAB file is v7.3. "
            "Using h5py..."
        )

        mat = {}

        with h5py.File(filename, "r") as f:

            print()
            print("MATLAB HDF5 variables:")

            for key in f.keys():

                item = f[key]

                if hasattr(item, "shape"):
                    print(
                        f"  {key}: shape={item.shape}, "
                        f"dtype={item.dtype}"
                    )

                else:
                    print(
                        f"  {key}"
                    )

                # Read datasets into NumPy arrays
                if isinstance(item, h5py.Dataset):
                    mat[key] = np.array(item)

        return mat


# ================================================================
# LOAD ORIGINAL PYTHON TRAINING DATA
# ================================================================

print_section(
    "PHASE 10D - PYTHON TRAINING vs MATLAB FEATURES"
)

print()
print("Loading original Python training data:")
print(PYTHON_TRAINING_FILE)

if not os.path.isfile(PYTHON_TRAINING_FILE):

    raise FileNotFoundError(
        "\nPython training file not found:\n"
        + PYTHON_TRAINING_FILE
    )


df_python = pd.read_csv(
    PYTHON_TRAINING_FILE
)

print()
print("Original dataset:")
print(df_python.shape)

print()
print("Columns:")
print(df_python.columns.tolist())


# ================================================================
# REMOVE PYTHON METADATA COLUMNS
# ================================================================

METADATA_COLUMNS = [
    "Flow_ID",
    "Window_ID",
    "Window_Size",
    "Label",
    "Attack Type",
    "Attack Tool",
]


print_section(
    "REMOVING METADATA / LABEL COLUMNS"
)

print(
    "Columns removed:"
)

for column in METADATA_COLUMNS:

    if column in df_python.columns:
        print(
            f"  - {column}"
        )


df_features_python = df_python.drop(
    columns=[
        c for c in METADATA_COLUMNS
        if c in df_python.columns
    ],
    errors="ignore"
)


# ================================================================
# VERIFY EXACT 91 FEATURES
# ================================================================

python_columns = df_features_python.columns.tolist()

print()
print(
    "Number of feature columns:",
    len(python_columns)
)


if len(python_columns) != 91:

    raise ValueError(
        "\nERROR: Python dataset does not contain exactly "
        "91 feature columns.\n"
        f"Found: {len(python_columns)}"
    )


# ================================================================
# VERIFY FEATURE ORDER
# ================================================================

missing_features = [
    f for f in FEATURE_NAMES
    if f not in python_columns
]

extra_features = [
    f for f in python_columns
    if f not in FEATURE_NAMES
]


if missing_features:

    print()
    print("ERROR: Missing expected features:")

    for f in missing_features:
        print(
            f"  {repr(f)}"
        )

    raise ValueError(
        "Python dataset feature mismatch."
    )


if extra_features:

    print()
    print("ERROR: Unexpected feature columns:")

    for f in extra_features:
        print(
            f"  {repr(f)}"
        )

    raise ValueError(
        "Python dataset feature mismatch."
    )


# ================================================================
# FORCE EXACT PYTHON FEATURE ORDER
# ================================================================

df_features_python = (
    df_features_python[
        FEATURE_NAMES
    ]
)


# ================================================================
# NUMERIC CONVERSION
# ================================================================

print()
print(
    "Converting Python features to numeric..."
)

df_features_python = (
    df_features_python.apply(
        pd.to_numeric,
        errors="coerce"
    )
)


# ================================================================
# NaN BEFORE FILL
# ================================================================

nan_before = int(
    df_features_python.isna()
    .sum()
    .sum()
)

print(
    "NaN values before fill:",
    f"{nan_before:,}"
)


# ================================================================
# MATCH ORIGINAL PYTHON PREPROCESSING
# ================================================================

df_features_python = (
    df_features_python.fillna(0)
)


nan_after = int(
    df_features_python.isna()
    .sum()
    .sum()
)

print(
    "NaN values after fill:",
    f"{nan_after:,}"
)


# ================================================================
# CONVERT TO NUMPY
# ================================================================

X_python = (
    df_features_python
    .to_numpy(dtype=np.float64)
)


print()
print(
    "Python feature matrix:"
)

print(
    X_python.shape
)


if X_python.shape[1] != 91:

    raise ValueError(
        "Python feature matrix does not have 91 columns."
    )


# ================================================================
# LOAD MATLAB PHASE 10C
# ================================================================

print_section(
    "LOADING MATLAB PHASE 10C FEATURES"
)

print()
print(
    "MATLAB feature file:"
)

print(
    MATLAB_FEATURE_FILE
)


if not os.path.isfile(MATLAB_FEATURE_FILE):

    raise FileNotFoundError(
        "\nMATLAB Phase 10C feature file not found:\n"
        + MATLAB_FEATURE_FILE
    )


mat = load_matlab_v73(
    MATLAB_FEATURE_FILE
)


# ================================================================
# CHECK MATLAB VARIABLE
# ================================================================

if "X91" not in mat:

    print()
    print(
        "Available MATLAB variables:"
    )

    for key in mat.keys():

        print(
            "  ",
            key
        )

    raise KeyError(
        "\nVariable 'X91' was not found "
        "inside the MATLAB file."
    )


X_matlab = np.asarray(
    mat["X91"]
)


print()
print(
    "Raw MATLAB X91 shape:"
)

print(
    X_matlab.shape
)


# ================================================================
# REMOVE MATLAB EXTRA DIMENSIONS
# ================================================================

X_matlab = np.squeeze(
    X_matlab
)


print()
print(
    "MATLAB X91 shape after squeeze:"
)

print(
    X_matlab.shape
)


# ================================================================
# MATLAB FEATURE MATRIX ORIENTATION
# ================================================================

if X_matlab.ndim != 2:

    raise ValueError(
        "\nExpected MATLAB X91 to be a 2-D matrix.\n"
        f"Actual shape: {X_matlab.shape}"
    )


if X_matlab.shape[1] == 91:

    # Already N × 91
    X_matlab = X_matlab

elif X_matlab.shape[0] == 91:

    # 91 × N
    X_matlab = X_matlab.T

else:

    raise ValueError(
        "\nUnexpected MATLAB X91 shape:\n"
        f"{X_matlab.shape}\n"
        "Expected N×91 or 91×N."
    )


print()
print(
    "MATLAB feature matrix:"
)

print(
    X_matlab.shape
)


# ================================================================
# CONVERT MATLAB TO FLOAT
# ================================================================

X_matlab = np.asarray(
    X_matlab,
    dtype=np.float64
)


# ================================================================
# FINITE VALUE CHECK
# ================================================================

python_nan = int(
    np.isnan(X_python).sum()
)

python_inf = int(
    np.isinf(X_python).sum()
)

matlab_nan = int(
    np.isnan(X_matlab).sum()
)

matlab_inf = int(
    np.isinf(X_matlab).sum()
)


print_section(
    "FINITE VALUE CHECK"
)

print(
    f"Python NaN : {python_nan:,}"
)

print(
    f"Python Inf : {python_inf:,}"
)

print(
    f"MATLAB NaN : {matlab_nan:,}"
)

print(
    f"MATLAB Inf : {matlab_inf:,}"
)


if matlab_nan > 0 or matlab_inf > 0:

    print()
    print(
        "WARNING: MATLAB contains NaN/Inf values."
    )


# ================================================================
# BASIC SHAPE COMPARISON
# ================================================================

print_section(
    "SHAPE COMPARISON"
)

print(
    "Python:"
)

print(
    f"  Samples : {X_python.shape[0]:,}"
)

print(
    f"  Features: {X_python.shape[1]}"
)

print()
print(
    "MATLAB:"
)

print(
    f"  Samples : {X_matlab.shape[0]:,}"
)

print(
    f"  Features: {X_matlab.shape[1]}"
)


if X_matlab.shape[1] != 91:

    raise ValueError(
        "MATLAB feature matrix must have 91 columns."
    )


# ================================================================
# STATISTICS
# ================================================================

print_section(
    "CALCULATING FEATURE DISTRIBUTION STATISTICS"
)


python_mean = np.mean(
    X_python,
    axis=0
)

python_std = np.std(
    X_python,
    axis=0
)

python_min = np.min(
    X_python,
    axis=0
)

python_max = np.max(
    X_python,
    axis=0
)

python_zero_pct = (
    np.mean(
        X_python == 0,
        axis=0
    )
    * 100
)


matlab_mean = np.mean(
    X_matlab,
    axis=0
)

matlab_std = np.std(
    X_matlab,
    axis=0
)

matlab_min = np.min(
    X_matlab,
    axis=0
)

matlab_max = np.max(
    X_matlab,
    axis=0
)

matlab_zero_pct = (
    np.mean(
        X_matlab == 0,
        axis=0
    )
    * 100
)


# ================================================================
# DIFFERENCES
# ================================================================

mean_difference = (
    matlab_mean - python_mean
)

absolute_mean_difference = np.abs(
    mean_difference
)

std_difference = (
    matlab_std - python_std
)

absolute_std_difference = np.abs(
    std_difference
)


# ================================================================
# RATIOS
# ================================================================

EPSILON = 1e-12


mean_ratio = (
    np.abs(matlab_mean)
    /
    (np.abs(python_mean) + EPSILON)
)


std_ratio = (
    matlab_std
    /
    (python_std + EPSILON)
)


# ================================================================
# ZERO FEATURE IDENTIFICATION
# ================================================================

python_zero_features = [
    FEATURE_NAMES[i]
    for i in range(91)
    if python_zero_pct[i] >= 99.999
]


matlab_zero_features = [
    FEATURE_NAMES[i]
    for i in range(91)
    if matlab_zero_pct[i] >= 99.999
]


# ================================================================
# PYTHON NONZERO / MATLAB ZERO
# ================================================================

python_nonzero_matlab_zero = [
    FEATURE_NAMES[i]
    for i in range(91)
    if (
        python_zero_pct[i] < 99.999
        and
        matlab_zero_pct[i] >= 99.999
    )
]


# ================================================================
# MATLAB NONZERO / PYTHON ZERO
# ================================================================

matlab_nonzero_python_zero = [
    FEATURE_NAMES[i]
    for i in range(91)
    if (
        matlab_zero_pct[i] < 99.999
        and
        python_zero_pct[i] >= 99.999
    )
]


# ================================================================
# CREATE COMPARISON DATAFRAME
# ================================================================

comparison = pd.DataFrame({

    "Feature_Index": np.arange(
        1,
        92
    ),

    "Feature": FEATURE_NAMES,

    "Python_Mean": python_mean,

    "MATLAB_Mean": matlab_mean,

    "Mean_Difference": mean_difference,

    "Abs_Mean_Difference": absolute_mean_difference,

    "Mean_Ratio_MATLAB_to_Python": mean_ratio,

    "Python_Std": python_std,

    "MATLAB_Std": matlab_std,

    "Std_Difference": std_difference,

    "Abs_Std_Difference": absolute_std_difference,

    "Std_Ratio_MATLAB_to_Python": std_ratio,

    "Python_Min": python_min,

    "MATLAB_Min": matlab_min,

    "Python_Max": python_max,

    "MATLAB_Max": matlab_max,

    "Python_Zero_Percent": python_zero_pct,

    "MATLAB_Zero_Percent": matlab_zero_pct,

})


# ================================================================
# SAVE FULL COMPARISON
# ================================================================

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


comparison.to_csv(
    OUTPUT_CSV,
    index=False
)


# ================================================================
# PRINT FULL TABLE
# ================================================================

print_section(
    "FULL FEATURE COMPARISON"
)

pd.set_option(
    "display.max_rows",
    100
)

pd.set_option(
    "display.max_columns",
    30
)

pd.set_option(
    "display.width",
    240
)

pd.set_option(
    "display.float_format",
    lambda x: f"{x:.6g}"
)


print(
    comparison[
        [
            "Feature_Index",
            "Feature",
            "Python_Mean",
            "MATLAB_Mean",
            "Python_Std",
            "MATLAB_Std",
            "Python_Zero_Percent",
            "MATLAB_Zero_Percent",
        ]
    ].to_string(
        index=False
    )
)


# ================================================================
# LARGEST MEAN MISMATCHES
# ================================================================

print_section(
    "TOP 20 LARGEST MEAN MISMATCHES"
)

top_mean = (
    comparison
    .sort_values(
        "Abs_Mean_Difference",
        ascending=False
    )
    .head(20)
)


print(
    top_mean[
        [
            "Feature_Index",
            "Feature",
            "Python_Mean",
            "MATLAB_Mean",
            "Abs_Mean_Difference",
            "Mean_Ratio_MATLAB_to_Python",
        ]
    ].to_string(
        index=False
    )
)


# ================================================================
# LARGEST STD MISMATCHES
# ================================================================

print_section(
    "TOP 20 LARGEST STD MISMATCHES"
)

top_std = (
    comparison
    .sort_values(
        "Abs_Std_Difference",
        ascending=False
    )
    .head(20)
)


print(
    top_std[
        [
            "Feature_Index",
            "Feature",
            "Python_Std",
            "MATLAB_Std",
            "Abs_Std_Difference",
            "Std_Ratio_MATLAB_to_Python",
        ]
    ].to_string(
        index=False
    )
)


# ================================================================
# FEATURES WITH VERY LARGE MEAN RATIO
# ================================================================

print_section(
    "FEATURES WITH LARGE MATLAB/PYTHON MEAN RATIO"
)

large_mean_ratio = (
    comparison[
        comparison[
            "Mean_Ratio_MATLAB_to_Python"
        ]
        > 10
    ]
    .sort_values(
        "Mean_Ratio_MATLAB_to_Python",
        ascending=False
    )
)


if len(large_mean_ratio) == 0:

    print(
        "No features with mean ratio > 10."
    )

else:

    print(
        large_mean_ratio[
            [
                "Feature_Index",
                "Feature",
                "Python_Mean",
                "MATLAB_Mean",
                "Mean_Ratio_MATLAB_to_Python",
            ]
        ].to_string(
            index=False
        )
    )


# ================================================================
# FEATURES WITH VERY SMALL MEAN RATIO
# ================================================================

print_section(
    "FEATURES WITH VERY SMALL MATLAB/PYTHON MEAN RATIO"
)

small_mean_ratio = (
    comparison[
        comparison[
            "Mean_Ratio_MATLAB_to_Python"
        ]
        < 0.1
    ]
    .sort_values(
        "Mean_Ratio_MATLAB_to_Python",
        ascending=True
    )
)


if len(small_mean_ratio) == 0:

    print(
        "No features with mean ratio < 0.1."
    )

else:

    print(
        small_mean_ratio[
            [
                "Feature_Index",
                "Feature",
                "Python_Mean",
                "MATLAB_Mean",
                "Mean_Ratio_MATLAB_to_Python",
            ]
        ].to_string(
            index=False
        )
    )


# ================================================================
# PYTHON CONSTANT-ZERO FEATURES
# ================================================================

print_section(
    "PYTHON TRAINING FEATURES THAT ARE EFFECTIVELY ZERO"
)

print(
    f"Count: {len(python_zero_features)} / 91"
)

for i, feature in enumerate(
    python_zero_features,
    start=1
):

    print(
        f"{i:2d}. {feature!r}"
    )


# ================================================================
# MATLAB CONSTANT-ZERO FEATURES
# ================================================================

print_section(
    "MATLAB FEATURES THAT ARE EFFECTIVELY ZERO"
)

print(
    f"Count: {len(matlab_zero_features)} / 91"
)

for i, feature in enumerate(
    matlab_zero_features,
    start=1
):

    print(
        f"{i:2d}. {feature!r}"
    )


# ================================================================
# PYTHON NONZERO BUT MATLAB ZERO
# ================================================================

print_section(
    "PYTHON NONZERO BUT MATLAB ZERO"
)

print(
    "These are especially important for domain mismatch."
)

print(
    f"Count: {len(python_nonzero_matlab_zero)}"
)

for i, feature in enumerate(
    python_nonzero_matlab_zero,
    start=1
):

    index = FEATURE_NAMES.index(
        feature
    )

    print(
        f"{i:2d}. "
        f"Feature {index + 1:2d}: "
        f"{feature!r} | "
        f"Python zero% = "
        f"{python_zero_pct[index]:.2f}% | "
        f"MATLAB zero% = "
        f"{matlab_zero_pct[index]:.2f}%"
    )


# ================================================================
# MATLAB NONZERO BUT PYTHON ZERO
# ================================================================

print_section(
    "MATLAB NONZERO BUT PYTHON ZERO"
)

print(
    f"Count: {len(matlab_nonzero_python_zero)}"
)

for i, feature in enumerate(
    matlab_nonzero_python_zero,
    start=1
):

    index = FEATURE_NAMES.index(
        feature
    )

    print(
        f"{i:2d}. "
        f"Feature {index + 1:2d}: "
        f"{feature!r} | "
        f"Python zero% = "
        f"{python_zero_pct[index]:.2f}% | "
        f"MATLAB zero% = "
        f"{matlab_zero_pct[index]:.2f}%"
    )


# ================================================================
# FEATURES WITH HIGH ZERO DIFFERENCE
# ================================================================

comparison["Zero_Percent_Difference"] = (
    np.abs(
        comparison["MATLAB_Zero_Percent"]
        -
        comparison["Python_Zero_Percent"]
    )
)


print_section(
    "TOP 20 ZERO-PERCENTAGE DIFFERENCES"
)

top_zero_difference = (
    comparison
    .sort_values(
        "Zero_Percent_Difference",
        ascending=False
    )
    .head(20)
)


print(
    top_zero_difference[
        [
            "Feature_Index",
            "Feature",
            "Python_Zero_Percent",
            "MATLAB_Zero_Percent",
            "Zero_Percent_Difference",
        ]
    ].to_string(
        index=False
    )
)


# ================================================================
# IMPORTANT TRAFFIC FEATURES
# ================================================================

IMPORTANT_FEATURES = [
    "Dur",
    "RunTime",
    "Mean",
    "Sum",
    "Min",
    "Max",
    "TotPkts",
    "SrcPkts",
    "DstPkts",
    "TotBytes",
    "SrcBytes",
    "DstBytes",
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
]


print_section(
    "IMPORTANT TRAFFIC FEATURE COMPARISON"
)

important_df = comparison[
    comparison["Feature"].isin(
        IMPORTANT_FEATURES
    )
].copy()


important_df["Importance_Order"] = (
    important_df["Feature"]
    .map(
        {
            feature: i
            for i, feature in enumerate(
                IMPORTANT_FEATURES
            )
        }
    )
)


important_df = (
    important_df
    .sort_values(
        "Importance_Order"
    )
    .drop(
        columns=[
            "Importance_Order"
        ]
    )
)


print(
    important_df[
        [
            "Feature_Index",
            "Feature",
            "Python_Mean",
            "MATLAB_Mean",
            "Mean_Ratio_MATLAB_to_Python",
            "Python_Std",
            "MATLAB_Std",
            "Std_Ratio_MATLAB_to_Python",
        ]
    ].to_string(
        index=False
    )
)


# ================================================================
# FINAL SUMMARY
# ================================================================

print_section(
    "PHASE 10D SUMMARY"
)

print(
    f"Python samples       : {X_python.shape[0]:,}"
)

print(
    f"MATLAB samples       : {X_matlab.shape[0]:,}"
)

print(
    f"Python features      : {X_python.shape[1]}"
)

print(
    f"MATLAB features      : {X_matlab.shape[1]}"
)

print(
    f"Python zero features : {len(python_zero_features)}"
)

print(
    f"MATLAB zero features : {len(matlab_zero_features)}"
)

print(
    "Python nonzero / MATLAB zero:",
    len(python_nonzero_matlab_zero)
)

print(
    "MATLAB nonzero / Python zero:",
    len(matlab_nonzero_python_zero)
)


# ================================================================
# SAVE AGAIN WITH ZERO DIFFERENCE COLUMN
# ================================================================

comparison.to_csv(
    OUTPUT_CSV,
    index=False
)


print()
print(
    "Comparison saved to:"
)

print(
    OUTPUT_CSV
)


# ================================================================
# FINAL INTERPRETATION
# ================================================================

print_section(
    "INTERPRETATION"
)

print(
    "This analysis compares feature distributions only."
)

print(
    "It does NOT modify the trained HTSTCL-GNN model."
)

print(
    "It does NOT retrain the model."
)

print(
    "It does NOT modify the Python StandardScaler."
)

print()
print(
    "The main purpose is to identify which MATLAB features"
)

print(
    "do not match the original Python training distribution."
)

print()
print(
    "Use the results to determine which features can be"
)

print(
    "legitimately reconstructed from the MATLAB 5G simulation."
)

print()
print(
    "Do NOT artificially force MATLAB values to match Python"
)

print(
    "training statistics without a valid feature definition."
)

print()
print(
    "Phase 10D analysis completed successfully."
)

# ================================================================
# END OF FILE
# ================================================================