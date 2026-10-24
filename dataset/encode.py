# ============================================================
# EXTRACT HTSTCL-GNN FEATURE SCALER
# ============================================================

import os
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

print("=" * 70)
print("HTSTCL-GNN FEATURE SCALER EXTRACTION")
print("=" * 70)

# ============================================================
# PATHS
# ============================================================

INPUT_FILE = "dataset/encoded.csv"

OUTPUT_DIR = "outputs/htstcl_scaler"

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)

# ============================================================
# LOAD ORIGINAL ENCODED DATASET
# ============================================================

print("\nLoading encoded dataset...")

df = pd.read_csv(INPUT_FILE)

print("Input File    :", INPUT_FILE)
print("Dataset Shape :", df.shape)

# ============================================================
# REMOVE COLUMNS EXACTLY AS flow_generation.py
# ============================================================

remove_columns = [
    "Unnamed: 0",
    "Seq"
]

flow_columns = [
    col
    for col in df.columns
    if col not in remove_columns
]

flow_df = df[flow_columns].copy()

# ============================================================
# REMOVE NON-INPUT COLUMNS EXACTLY AS pyg_dataset.py
# ============================================================

remove_feature_columns = [
    "Flow_ID",
    "Window_ID",
    "Window_Size",
    "Label",
    "Attack Type",
    "Attack Tool"
]

feature_columns = [
    col
    for col in flow_df.columns
    if col not in remove_feature_columns
]

print("\n" + "=" * 70)
print("FEATURE INFORMATION")
print("=" * 70)

print("Number of features :", len(feature_columns))

# ============================================================
# VERIFY EXACTLY 91 FEATURES
# ============================================================

if len(feature_columns) != 91:

    raise ValueError(
        f"Expected exactly 91 features, "
        f"but found {len(feature_columns)}"
    )

print("91-feature verification : PASSED")

# ============================================================
# DISPLAY FEATURE ORDER
# ============================================================

print("\nExact Feature Order")

for index, feature in enumerate(
    feature_columns,
    start=1
):

    print(
        f"{index:02d}. {repr(feature)}"
    )

# ============================================================
# CONVERT TO NUMERIC
# ============================================================

print("\nConverting features to numeric...")

X = flow_df[
    feature_columns
].apply(
    pd.to_numeric,
    errors="coerce"
)

nan_before = int(
    X.isna().sum().sum()
)

print(
    "NaN values before cleaning :",
    nan_before
)

# EXACTLY MATCH ORIGINAL NODE CREATION
X = X.fillna(0)

nan_after = int(
    X.isna().sum().sum()
)

print(
    "NaN values after cleaning  :",
    nan_after
)

# ============================================================
# FIT STANDARD SCALER
# ============================================================

print("\nFitting StandardScaler...")

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

print(
    "StandardScaler fitted successfully."
)

# ============================================================
# VERIFY SCALER
# ============================================================

print("\n" + "=" * 70)
print("SCALER VERIFICATION")
print("=" * 70)

print(
    "Samples :", X.shape[0]
)

print(
    "Features:", X.shape[1]
)

print(
    "Mean vector shape:",
    scaler.mean_.shape
)

print(
    "Scale vector shape:",
    scaler.scale_.shape
)

# ============================================================
# SAVE FEATURE NAMES
# ============================================================

feature_df = pd.DataFrame({

    "Feature_Index":
        np.arange(
            1,
            len(feature_columns) + 1
        ),

    "Feature_Name":
        feature_columns

})

feature_file = os.path.join(
    OUTPUT_DIR,
    "feature_names.csv"
)

feature_df.to_csv(
    feature_file,
    index=False
)

# ============================================================
# SAVE SCALER PARAMETERS
# ============================================================

scaler_df = pd.DataFrame({

    "Feature_Index":
        np.arange(
            1,
            len(feature_columns) + 1
        ),

    "Feature_Name":
        feature_columns,

    "Mean":
        scaler.mean_,

    "Std":
        scaler.scale_

})

scaler_file = os.path.join(
    OUTPUT_DIR,
    "scaler_parameters.csv"
)

scaler_df.to_csv(
    scaler_file,
    index=False
)

# ============================================================
# SAVE NUMPY ARRAYS
# ============================================================

np.save(
    os.path.join(
        OUTPUT_DIR,
        "feature_mean.npy"
    ),
    scaler.mean_
)

np.save(
    os.path.join(
        OUTPUT_DIR,
        "feature_std.npy"
    ),
    scaler.scale_
)

# ============================================================
# SAVE JSON METADATA
# ============================================================

metadata = {

    "source_file":
        INPUT_FILE,

    "number_of_features":
        len(feature_columns),

    "number_of_samples":
        len(df),

    "missing_values_before_fill":
        nan_before,

    "missing_values_after_fill":
        nan_after,

    "scaler":
        "sklearn.preprocessing.StandardScaler",

    "normalization":
        "(x - mean) / std",

    "feature_order":
        feature_columns

}

metadata_file = os.path.join(
    OUTPUT_DIR,
    "scaler_metadata.json"
)

with open(
    metadata_file,
    "w"
) as f:

    json.dump(
        metadata,
        f,
        indent=4
    )

# ============================================================
# SAVE A SMALL MATLAB-FRIENDLY CSV
# ============================================================

matlab_scaler_df = pd.DataFrame(
    scaler.mean_.reshape(1, -1),
    columns=feature_columns
)

matlab_mean_file = os.path.join(
    OUTPUT_DIR,
    "feature_mean.csv"
)

matlab_scaler_df.to_csv(
    matlab_mean_file,
    index=False
)

matlab_std_df = pd.DataFrame(
    scaler.scale_.reshape(1, -1),
    columns=feature_columns
)

matlab_std_file = os.path.join(
    OUTPUT_DIR,
    "feature_std.csv"
)

matlab_std_df.to_csv(
    matlab_std_file,
    index=False
)

# ============================================================
# TEST NORMALIZATION
# ============================================================

print("\n" + "=" * 70)
print("NORMALIZATION TEST")
print("=" * 70)

test_sample = X.iloc[0].values

manual_scaled = (
    test_sample - scaler.mean_
) / scaler.scale_

sklearn_scaled = X_scaled[0]

difference = np.max(
    np.abs(
        manual_scaled -
        sklearn_scaled
    )
)

print(
    "Maximum difference:",
    difference
)

if difference < 1e-6:

    print(
        "Normalization verification : PASSED"
    )

else:

    raise ValueError(
        "Normalization verification FAILED"
    )

# ============================================================
# DISPLAY FIRST 10 PARAMETERS
# ============================================================

print("\n" + "=" * 70)
print("FIRST 10 SCALER PARAMETERS")
print("=" * 70)

for i in range(10):

    print(
        f"{i+1:02d}. "
        f"{feature_columns[i]!r}"
    )

    print(
        f"    Mean = {scaler.mean_[i]:.10f}"
    )

    print(
        f"    Std  = {scaler.scale_[i]:.10f}"
    )

# ============================================================
# FINAL OUTPUT
# ============================================================

print("\n" + "=" * 70)
print("HTSTCL-GNN SCALER EXTRACTION COMPLETED")
print("=" * 70)

print("\nGenerated Files:")

print(
    "1.",
    feature_file
)

print(
    "2.",
    scaler_file
)

print(
    "3.",
    os.path.join(
        OUTPUT_DIR,
        "feature_mean.npy"
    )
)

print(
    "4.",
    os.path.join(
        OUTPUT_DIR,
        "feature_std.npy"
    )
)

print(
    "5.",
    matlab_mean_file
)

print(
    "6.",
    matlab_std_file
)

print(
    "7.",
    metadata_file
)

print("\n" + "=" * 70)
print("READY FOR MATLAB INTEGRATION")
print("=" * 70)