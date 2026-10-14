from pathlib import Path
import re

ROOT = Path(r"D:\5G_Wireless_IDS")

# Feature names that are especially important for reproducing
# the original Python training representation.
TARGETS = [
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

# Ignore virtual environment and generated diagnostic scripts.
IGNORE_DIRS = {
    ".venv",
    "__pycache__",
    ".git",
}

IGNORE_FILES = {
    "analyze_original_training_features.py",
    "inspect_python_feature_values.py",
    "compare_training_matlab_features.py",
    "find_feature_generator.py",
    "infer_matlab_traffic.py",
    "inference_only.py",
}

# Strong indicators that a file may be responsible for
# generating the original flow/feature dataset.
GENERATOR_WORDS = [
    "flow",
    "feature",
    "dataset",
    "progressive",
    "window",
    "pcap",
    "traffic",
    "extract",
    "generate",
    "preprocess",
]


def source_files():
    for path in ROOT.rglob("*.py"):
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.name in IGNORE_FILES:
            continue
        yield path


def score_file(path, text):
    lower = text.lower()
    score = 0

    for word in GENERATOR_WORDS:
        if word in lower:
            score += 1

    for target in TARGETS:
        if target.lower() in lower:
            score += 3

    # Strong evidence of dataframe feature construction.
    patterns = [
        r"to_csv\s*\(",
        r"read_csv\s*\(",
        r"DataFrame\s*\(",
        r"\[\s*[\"']Dur[\"']",
        r"\[\s*[\"']TotPkts[\"']",
        r"\[\s*[\"']TotBytes[\"']",
        r"flow_records",
        r"window_5",
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            score += 5

    return score


results = []

for path in source_files():
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue

    score = score_file(path, text)

    if score > 0:
        results.append((score, path, text))


results.sort(key=lambda x: (-x[0], str(x[1])))

print("=" * 100)
print("PHASE 10F - ORIGINAL PYTHON FEATURE GENERATOR SEARCH")
print("=" * 100)
print()

print(f"Python files searched : {sum(1 for _ in source_files())}")
print(f"Candidate files found: {len(results)}")
print()

for rank, (score, path, text) in enumerate(results[:20], 1):

    print("-" * 100)
    print(f"[{rank}] SCORE = {score}")
    print(f"FILE  = {path}")
    print("-" * 100)

    lines = text.splitlines()

    matched = []

    for i, line in enumerate(lines):
        if any(
            re.search(rf"\b{re.escape(target)}\b", line)
            for target in TARGETS
        ):
            matched.append(i)

    # Show a small amount of source context around matches.
    shown = set()

    for line_no in matched:
        start = max(0, line_no - 3)
        end = min(len(lines), line_no + 4)

        block = tuple(range(start, end))

        if any(x in shown for x in block):
            continue

        print()
        print(f"  Lines {start + 1}-{end}:")

        for j in range(start, end):
            marker = ">>>" if j == line_no else "   "
            print(f"{marker} {j + 1:5}: {lines[j]}")

        shown.update(block)

    print()


print("=" * 100)
print("WHAT WE ARE LOOKING FOR")
print("=" * 100)
print("""
The important result is the Python file that actually CREATES the original
flow_records/window_5 features.

Especially look for formulas or assignments involving:

Dur
RunTime
Mean
Sum
Min
Max

TotPkts
SrcPkts
DstPkts

TotBytes
SrcBytes
DstBytes

sMeanPktSz
dMeanPktSz

Load
SrcLoad
DstLoad

Loss
SrcLoss
DstLoss
pLoss

SrcGap
DstGap

Rate
SrcRate
DstRate

Do NOT modify the trained model or scaler based on this search.
""")