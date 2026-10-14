# ================================================================
# Phase 10E
# Inspect Raw Python Training Feature Values
#
# Purpose:
#   Verify the actual values stored in the original Python
#   training CSV before changing the MATLAB feature mapping.
#
# IMPORTANT:
#   - Does NOT modify the dataset
#   - Does NOT modify the scaler
#   - Does NOT modify the trained model
#   - Does NOT retrain anything
#
# ================================================================

import os
import numpy as np
import pandas as pd


# ================================================================
# PATH
# ================================================================

PYTHON_TRAINING_FILE = (
    r"D:\5G_Wireless_IDS\outputs\progressive_windows\window_5.csv"
)


# ================================================================
# EXACT FEATURES TO INSPECT
# ================================================================

KEY_FEATURES = [
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


# ================================================================
# HELPER
# ================================================================

def section(title):
    print()
    print("=" * 90)
    print(title)
    print("=" * 90)


def print_values(values):
    """
    Print values cleanly.
    """

    for i, value in enumerate(values):

        print(
            f"  {i + 1:2d}: {value!r}"
        )


# ================================================================
# START
# ================================================================

section(
    "PHASE 10E - RAW PYTHON TRAINING FEATURE INSPECTION"
)

print()
print(
    "Python training file:"
)

print(
    PYTHON_TRAINING_FILE
)


# ================================================================
# FILE CHECK
# ================================================================

if not os.path.isfile(
    PYTHON_TRAINING_FILE
):

    raise FileNotFoundError(
        "\nTraining file not found:\n"
        + PYTHON_TRAINING_FILE
    )


# ================================================================
# LOAD DATA
# ================================================================

print()
print(
    "Loading CSV..."
)

df = pd.read_csv(
    PYTHON_TRAINING_FILE
)

print()
print(
    "Dataset shape:"
)

print(
    df.shape
)


# ================================================================
# COLUMN CHECK
# ================================================================

print()
print(
    "Checking requested features..."
)

missing = [
    feature
    for feature in KEY_FEATURES
    if feature not in df.columns
]

if missing:

    print()
    print(
        "Missing features:"
    )

    for feature in missing:
        print(
            f"  {feature!r}"
        )

    raise ValueError(
        "One or more requested features are missing."
    )

print(
    f"All {len(KEY_FEATURES)} requested features are present."
)


# ================================================================
# RAW VALUE INSPECTION
# ================================================================

section(
    "FIRST 20 RAW VALUES"
)

for feature in KEY_FEATURES:

    print()
    print(
        f"FEATURE: {feature!r}"
    )

    values = df[
        feature
    ].head(20).tolist()

    print_values(
        values
    )


# ================================================================
# UNIQUE VALUE INSPECTION
# ================================================================

section(
    "UNIQUE VALUE ANALYSIS"
)

for feature in KEY_FEATURES:

    series = pd.to_numeric(
        df[feature],
        errors="coerce"
    )

    unique_values = (
        series
        .dropna()
        .unique()
    )

    print()
    print(
        f"{feature!r}"
    )

    print(
        f"  Unique values: {len(unique_values):,}"
    )

    if len(unique_values) <= 20:

        print(
            "  Values:"
        )

        print(
            unique_values
        )

    else:

        print(
            "  First 10 unique values:"
        )

        print(
            unique_values[:10]
        )


# ================================================================
# DETAILED STATISTICS
# ================================================================

section(
    "DETAILED RAW STATISTICS"
)

statistics = []


for feature in KEY_FEATURES:

    series = pd.to_numeric(
        df[feature],
        errors="coerce"
    )

    values = series.dropna()

    statistics.append({

        "Feature": feature,

        "Count": len(values),

        "NaN_Count": int(
            series.isna().sum()
        ),

        "Zero_Percent": (
            (values == 0).mean()
            * 100
        ),

        "Unique_Count": (
            values.nunique()
        ),

        "Min": values.min(),

        "P01": values.quantile(0.01),

        "P05": values.quantile(0.05),

        "P25": values.quantile(0.25),

        "Median": values.median(),

        "Mean": values.mean(),

        "P75": values.quantile(0.75),

        "P95": values.quantile(0.95),

        "P99": values.quantile(0.99),

        "Max": values.max(),

        "Std": values.std(),
    })


stats_df = pd.DataFrame(
    statistics
)


pd.set_option(
    "display.max_columns",
    30
)

pd.set_option(
    "display.width",
    260
)

pd.set_option(
    "display.max_rows",
    100
)

pd.set_option(
    "display.float_format",
    lambda x: f"{x:.8g}"
)


print(
    stats_df.to_string(
        index=False
    )
)


# ================================================================
# CHECK IDENTICAL DISTRIBUTIONS
# ================================================================

section(
    "CHECK FOR IDENTICAL FEATURE COLUMNS"
)

feature_pairs = [
    ("Dur", "RunTime"),
    ("Dur", "Mean"),
    ("Dur", "Sum"),
    ("Dur", "Min"),
    ("Dur", "Max"),
    ("Mean", "Sum"),
    ("Mean", "Min"),
    ("Mean", "Max"),
    ("Sum", "Min"),
    ("Sum", "Max"),
    ("Min", "Max"),
]


for feature_a, feature_b in feature_pairs:

    a = pd.to_numeric(
        df[feature_a],
        errors="coerce"
    ).fillna(0)

    b = pd.to_numeric(
        df[feature_b],
        errors="coerce"
    ).fillna(0)

    identical = np.array_equal(
        a.to_numpy(),
        b.to_numpy()
    )

    correlation = a.corr(
        b
    )

    max_difference = np.max(
        np.abs(
            a.to_numpy()
            -
            b.to_numpy()
        )
    )

    print()
    print(
        f"{feature_a!r} vs {feature_b!r}"
    )

    print(
        f"  Identical : {identical}"
    )

    print(
        f"  Correlation: {correlation:.8f}"
    )

    print(
        f"  Max absolute difference: "
        f"{max_difference:.8g}"
    )


# ================================================================
# RANDOM ROW INSPECTION
# ================================================================

section(
    "RANDOM ROW INSPECTION"
)

rng = np.random.default_rng(
    42
)

random_indices = rng.choice(
    len(df),
    size=10,
    replace=False
)


print(
    "Random row indices:"
)

print(
    random_indices
)


random_columns = [
    "Flow_ID",
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
    "Load",
    "SrcLoad",
    "DstLoad",
    "Rate",
    "SrcRate",
    "DstRate",
    "Label",
    "Attack Type",
]


available_random_columns = [
    column
    for column in random_columns
    if column in df.columns
]


print()

print(
    df.loc[
        random_indices,
        available_random_columns
    ].to_string(
        index=True
    )
)


# ================================================================
# LABEL DISTRIBUTION
# ================================================================

section(
    "LABEL DISTRIBUTION"
)

if "Label" in df.columns:

    print(
        df["Label"]
        .value_counts(
            dropna=False
        )
        .sort_index()
        .to_string()
    )


# ================================================================
# ATTACK TYPE DISTRIBUTION
# ================================================================

section(
    "ATTACK TYPE DISTRIBUTION"
)

if "Attack Type" in df.columns:

    print(
        df["Attack Type"]
        .value_counts(
            dropna=False
        )
        .head(30)
        .to_string()
    )


# ================================================================
# LABEL-WISE FEATURE STATISTICS
# ================================================================

section(
    "LABEL-WISE STATISTICS FOR KEY FEATURES"
)


if "Label" in df.columns:

    label_values = (
        df["Label"]
        .dropna()
        .unique()
    )

    print(
        "Labels found:",
        label_values
    )

    label_statistics = []

    for feature in KEY_FEATURES:

        series = pd.to_numeric(
            df[feature],
            errors="coerce"
        )

        row = {
            "Feature": feature
        }

        for label in sorted(
            label_values
        ):

            values = series[
                df["Label"] == label
            ].dropna()

            row[
                f"Label_{label}_Mean"
            ] = values.mean()

            row[
                f"Label_{label}_Std"
            ] = values.std()

            row[
                f"Label_{label}_Median"
            ] = values.median()

            row[
                f"Label_{label}_Zero%"
            ] = (
                (values == 0).mean()
                * 100
            )

        label_statistics.append(
            row
        )

    label_stats_df = pd.DataFrame(
        label_statistics
    )

    print(
        label_stats_df.to_string(
            index=False
        )
    )


# ================================================================
# CHECK WHETHER NUMERIC FEATURES ARE ACTUALLY CORRUPTED
# ================================================================

section(
    "SANITY CHECK: TRAFFIC FEATURE RELATIONSHIPS"
)


checks = []


def relationship_check(
    name,
    feature_a,
    feature_b
):

    a = pd.to_numeric(
        df[feature_a],
        errors="coerce"
    ).fillna(0)

    b = pd.to_numeric(
        df[feature_b],
        errors="coerce"
    ).fillna(0)

    valid = (
        np.isfinite(a)
        &
        np.isfinite(b)
    )

    if valid.sum() == 0:

        return

    a_values = a[
        valid
    ].to_numpy()

    b_values = b[
        valid
    ].to_numpy()

    correlation = np.corrcoef(
        a_values,
        b_values
    )[0, 1]

    checks.append({

        "Relationship": name,

        "Feature_A": feature_a,

        "Feature_B": feature_b,

        "Correlation": correlation,

        "Mean_A": np.mean(a_values),

        "Mean_B": np.mean(b_values),

        "Mean_A_over_B": (
            np.mean(a_values)
            /
            (
                np.mean(b_values)
                +
                1e-12
            )
        ),

    })


relationship_check(
    "PacketCount vs TotPkts",
    "TotPkts",
    "Dur"
)

relationship_check(
    "SrcPkts vs DstPkts",
    "SrcPkts",
    "DstPkts"
)

relationship_check(
    "SrcBytes vs DstBytes",
    "SrcBytes",
    "DstBytes"
)

relationship_check(
    "SrcLoad vs DstLoad",
    "SrcLoad",
    "DstLoad"
)

relationship_check(
    "SrcRate vs DstRate",
    "SrcRate",
    "DstRate"
)


if checks:

    checks_df = pd.DataFrame(
        checks
    )

    print(
        checks_df.to_string(
            index=False
        )
    )


# ================================================================
# SAVE STATISTICS
# ================================================================

OUTPUT_DIR = (
    r"D:\5G_Wireless_IDS\outputs\matlab_ids"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "phase10E_python_raw_feature_statistics.csv"
)


stats_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ================================================================
# FINAL SUMMARY
# ================================================================

section(
    "PHASE 10E SUMMARY"
)

print(
    f"Dataset rows          : {len(df):,}"
)

print(
    f"Requested features    : {len(KEY_FEATURES)}"
)

print(
    f"Statistics generated  : {len(stats_df)}"
)

print()
print(
    "The raw Python feature values have now been inspected."
)

print()
print(
    "Most important items to verify:"
)

print(
    "  1. Are Dur, RunTime, Mean, Sum, Min and Max actually"
)

print(
    "     identical in the CSV?"
)

print(
    "  2. What are their real raw values?"
)

print(
    "  3. Are source/destination features asymmetric?"
)

print(
    "  4. What are the benign/malicious distributions?"
)

print(
    "  5. Which features can legitimately be reconstructed"
)

print(
    "     from the MATLAB 5G simulation?"
)

print()
print(
    "Statistics saved to:"
)

print(
    OUTPUT_FILE
)

print()
print(
    "PHASE 10E COMPLETED."
)

# ================================================================
# END
# ================================================================