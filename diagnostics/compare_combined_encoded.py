import pandas as pd
import numpy as np

COMBINED = r"D:\5G_Wireless_IDS\dataset\Combined.csv"
ENCODED  = r"D:\5G_Wireless_IDS\dataset\Encoded.csv"

print("=" * 80)
print("5G-NIDD COMBINED vs ENCODED ANALYSIS")
print("=" * 80)

# ------------------------------------------------------------
# Load
# ------------------------------------------------------------

combined = pd.read_csv(COMBINED)
encoded = pd.read_csv(ENCODED)

print("\nCombined shape:", combined.shape)
print("Encoded shape :", encoded.shape)

print("\nCombined columns:")
for i, c in enumerate(combined.columns, 1):
    print(f"{i:3d}: {repr(c)}")

print("\nEncoded columns:")
for i, c in enumerate(encoded.columns, 1):
    print(f"{i:3d}: {repr(c)}")

# ------------------------------------------------------------
# Align rows using Seq
# ------------------------------------------------------------

if "Seq" in combined.columns and "Seq" in encoded.columns:

    merged = combined.merge(
        encoded,
        on="Seq",
        suffixes=("_combined", "_encoded"),
        how="inner"
    )

else:
    raise RuntimeError("Seq column not found.")

print("\nMerged rows:", len(merged))

# ------------------------------------------------------------
# Raw categorical distributions
# ------------------------------------------------------------

categorical = [
    "Proto",
    "sTos",
    "dTos",
    "sDSb",
    "dDSb",
    "Cause",
    "State"
]

for col in categorical:

    if col not in combined.columns:
        continue

    print("\n" + "=" * 80)
    print("RAW COLUMN:", col)
    print("=" * 80)

    print(
        combined[col]
        .value_counts(dropna=False)
        .head(30)
        .to_string()
    )

# ------------------------------------------------------------
# Numerical relationships
# ------------------------------------------------------------

numeric = [
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
    "Rate",
    "SrcRate",
    "DstRate"
]

print("\n")
print("=" * 80)
print("NUMERICAL FEATURE STATISTICS")
print("=" * 80)

for col in numeric:

    if col not in combined.columns:
        continue

    x = pd.to_numeric(combined[col], errors="coerce")

    print(
        f"{col:15s} "
        f"mean={x.mean():14.6g} "
        f"std={x.std():14.6g} "
        f"min={x.min():14.6g} "
        f"max={x.max():14.6g} "
        f"zero={(x == 0).sum():10d}"
    )

# ------------------------------------------------------------
# Algebraic consistency checks
# ------------------------------------------------------------

print("\n")
print("=" * 80)
print("FLOW FEATURE CONSISTENCY")
print("=" * 80)

def numeric_col(df, col):
    return pd.to_numeric(df[col], errors="coerce").fillna(0).to_numpy(
        dtype=np.float64
    )

if all(c in combined.columns for c in
       ["TotPkts", "SrcPkts", "DstPkts"]):

    tot = numeric_col(combined, "TotPkts")
    src = numeric_col(combined, "SrcPkts")
    dst = numeric_col(combined, "DstPkts")

    err = np.abs(tot - (src + dst))

    print("TotPkts - (SrcPkts + DstPkts)")
    print("  max error :", err.max())
    print("  mean error:", err.mean())

if all(c in combined.columns for c in
       ["TotBytes", "SrcBytes", "DstBytes"]):

    tot = numeric_col(combined, "TotBytes")
    src = numeric_col(combined, "SrcBytes")
    dst = numeric_col(combined, "DstBytes")

    err = np.abs(tot - (src + dst))

    print("\nTotBytes - (SrcBytes + DstBytes)")
    print("  max error :", err.max())
    print("  mean error:", err.mean())

# ------------------------------------------------------------
# Packet-size relationships
# ------------------------------------------------------------

if all(c in combined.columns for c in
       ["SrcBytes", "SrcPkts", "sMeanPktSz"]):

    src_bytes = numeric_col(combined, "SrcBytes")
    src_pkts  = numeric_col(combined, "SrcPkts")
    smean     = numeric_col(combined, "sMeanPktSz")

    calculated = np.divide(
        src_bytes,
        src_pkts,
        out=np.zeros_like(src_bytes),
        where=src_pkts != 0
    )

    valid = src_pkts != 0

    err = np.abs(calculated[valid] - smean[valid])

    print("\nSrcBytes / SrcPkts vs sMeanPktSz")
    print("  max error :", err.max())
    print("  mean error:", err.mean())

if all(c in combined.columns for c in
       ["DstBytes", "DstPkts", "dMeanPktSz"]):

    dst_bytes = numeric_col(combined, "DstBytes")
    dst_pkts  = numeric_col(combined, "DstPkts")
    dmean     = numeric_col(combined, "dMeanPktSz")

    calculated = np.divide(
        dst_bytes,
        dst_pkts,
        out=np.zeros_like(dst_bytes),
        where=dst_pkts != 0
    )

    valid = dst_pkts != 0

    if valid.any():

        err = np.abs(calculated[valid] - dmean[valid])

        print("\nDstBytes / DstPkts vs dMeanPktSz")
        print("  max error :", err.max())
        print("  mean error:", err.mean())

# ------------------------------------------------------------
# Duration relationships
# ------------------------------------------------------------

print("\n")
print("=" * 80)
print("DURATION RELATIONSHIPS")
print("=" * 80)

for a, b in [
    ("Dur", "RunTime"),
    ("Dur", "Mean"),
    ("Dur", "Sum"),
    ("Dur", "Min"),
    ("Dur", "Max")
]:

    if a in combined.columns and b in combined.columns:

        x = numeric_col(combined, a)
        y = numeric_col(combined, b)

        err = np.abs(x - y)

        print(
            f"{a} vs {b}: "
            f"max_error={err.max():.12g}, "
            f"mean_error={err.mean():.12g}"
        )

# ------------------------------------------------------------
# Encoded feature sparsity
# ------------------------------------------------------------

print("\n")
print("=" * 80)
print("ENCODED FEATURE SPARSITY")
print("=" * 80)

metadata = {
    "Seq",
    "Label",
    "Attack Type",
    "Attack Tool"
}

encoded_features = [
    c for c in encoded.columns
    if c not in metadata
]

print("Encoded model features:", len(encoded_features))

for i, col in enumerate(encoded_features, 1):

    x = pd.to_numeric(encoded[col], errors="coerce").fillna(0)

    nonzero = (x != 0).sum()

    print(
        f"{i:3d} {repr(col):20s} "
        f"nonzero={nonzero:9d} "
        f"zero={len(x)-nonzero:9d} "
        f"mean={x.mean():12.6g}"
    )

print("\n")
print("=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)