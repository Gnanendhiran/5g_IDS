
from pathlib import Path
import json
import warnings

import numpy as np
import pandas as pd
import torch
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    average_precision_score,
    matthews_corrcoef,
    balanced_accuracy_score,
    cohen_kappa_score,
    log_loss,
)

# Change these paths to your actual project files.
PROJECT_DIR = Path(r"D:\5G_Wireless_IDS")
DATASET_PATH = PROJECT_DIR / "outputs" / "sequence_dataset" / "graph_sequences.pt"
CHECKPOINT_PATH = (
    PROJECT_DIR / "htstcl_gnn_models" / "htstcl_gnn_best.pth"
)
OUTPUT_DIR = PROJECT_DIR / "reports" / "multiclass_evaluation"

# Set these to match the fields in your upgraded dataset.
MULTICLASS_LABEL_KEY = "multiclass_label"
BINARY_LABEL_KEY = "binary_label"
GRAPHS_KEY = "graphs"

# Class index 0 must correspond to Benign for this mapping.
CLASS_NAMES = [
    "Benign",
    "UDPFlood",
    "HTTPFlood",
    "SlowrateDoS",
    "TCPConnectScan",
    "SYNScan",
    "UDPScan",
    "SYNFlood",
    "ICMPFlood",
]
BENIGN_CLASS_ID = 0

INPUT_DIM = 91
HIDDEN_DIM = 128
EMBEDDING_DIM = 128
GRU_LAYERS = 2
DROPOUT = 0.3
RANDOM_SEED = 42
BATCH_SIZE = 16

# Set True ONLY if the model checkpoint was trained with this exact
# class order and this exact preprocessing/data-split convention.
USE_REPRODUCIBLE_RANDOM_SPLIT = True


def load_serialized_dataset(path):
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    # Only load trusted files produced by your own pipeline.
    data = torch.load(path, map_location="cpu", weights_only=False)

    # Support a dataset saved as {"samples": [...]}.
    if isinstance(data, dict) and "samples" in data:
        data = data["samples"]

    if not isinstance(data, (list, tuple)):
        raise TypeError(
            "Expected a list of sequence dictionaries, or a dict "
            "containing a 'samples' list."
        )

    return list(data)


def require_integer_label(value, key, sample_index):
    if value is None:
        raise ValueError(
            f"Sample {sample_index} has no '{key}' label. "
            "Check your dataset schema."
        )

    # This script expects encoded integer class IDs.
    if isinstance(value, torch.Tensor):
        if value.numel() != 1:
            raise ValueError(
                f"Sample {sample_index}: '{key}' must be a scalar label."
            )
        value = value.item()

    if isinstance(value, np.generic):
        value = value.item()

    if not isinstance(value, (int, np.integer)):
        raise TypeError(
            f"Sample {sample_index}: '{key}' must be an integer class ID; "
            f"got {value!r}. Encode string labels using a documented mapping."
        )

    return int(value)


def extract_labels(samples):
    multiclass_labels = []
    binary_labels = []

    for i, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise TypeError(
                f"Sample {i} must be a dictionary containing "
                f"'{GRAPHS_KEY}' and label fields."
            )

        if GRAPHS_KEY not in sample:
            raise KeyError(f"Sample {i} has no '{GRAPHS_KEY}' field.")

        graphs = sample[GRAPHS_KEY]
        if len(graphs) != 5:
            raise ValueError(
                f"Sample {i} has {len(graphs)} graphs; expected 5."
            )

        if MULTICLASS_LABEL_KEY not in sample:
            raise KeyError(
                f"Sample {i} has no '{MULTICLASS_LABEL_KEY}' field. "
                "A binary label cannot be used as a genuine nine-class label. "
                "Add the original attack-class label to the dataset."
            )

        mc = require_integer_label(
            sample[MULTICLASS_LABEL_KEY], MULTICLASS_LABEL_KEY, i
        )

        if not 0 <= mc < len(CLASS_NAMES):
            raise ValueError(
                f"Sample {i}: class ID {mc} is outside 0.."
                f"{len(CLASS_NAMES)-1}. Verify the class mapping."
            )

        # Prefer a stored binary label; otherwise derive it from the
        # documented multiclass label mapping.
        if BINARY_LABEL_KEY in sample:
            binary = require_integer_label(
                sample[BINARY_LABEL_KEY], BINARY_LABEL_KEY, i
            )
        else:
            binary = int(mc != BENIGN_CLASS_ID)

        if binary not in (0, 1):
            raise ValueError(f"Sample {i}: binary label must be 0 or 1.")

        if binary != int(mc != BENIGN_CLASS_ID):
            raise ValueError(
                f"Sample {i}: binary and multiclass labels disagree. "
                "Check the label mapping and benign class ID."
            )

        multiclass_labels.append(mc)
        binary_labels.append(binary)

    return (
        np.asarray(multiclass_labels, dtype=np.int64),
        np.asarray(binary_labels, dtype=np.int64),
    )


def load_model_checkpoint(model, checkpoint_path, device):
    if not checkpoint_path.exists():
        raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")

    checkpoint = torch.load(
        checkpoint_path, map_location=device, weights_only=False
    )

    # Support common checkpoint dictionary formats.
    if isinstance(checkpoint, dict):
        if "model_state_dict" in checkpoint:
            state_dict = checkpoint["model_state_dict"]
        elif "state_dict" in checkpoint:
            state_dict = checkpoint["state_dict"]
        else:
            state_dict = checkpoint
    else:
        raise TypeError(
            "Checkpoint must be a state_dict or a dictionary containing "
            "'model_state_dict'/'state_dict'."
        )

    model.load_state_dict(state_dict, strict=True)
    model.to(device)
    model.eval()
    return checkpoint


def predict_split(model, samples, indices, device, split_name):
    y_mc, y_bin = [], []
    prob_mc, prob_bin = [], []
    pred_mc, pred_bin = [], []

    with torch.inference_mode():
        for start in range(0, len(indices), BATCH_SIZE):
            batch_indices = indices[start:start + BATCH_SIZE]
            batch_sequences = [
                samples[int(i)][GRAPHS_KEY] for i in batch_indices
            ]

            output = model(batch_sequences)

            if "multiclass_logits" not in output:
                raise KeyError("Model output lacks 'multiclass_logits'.")
            if "binary_logits" not in output:
                raise KeyError("Model output lacks 'binary_logits'.")

            mc_logits = output["multiclass_logits"]
            bin_logits = output["binary_logits"]

            if mc_logits.ndim != 2 or mc_logits.shape[1] != len(CLASS_NAMES):
                raise ValueError(
                    f"Expected multiclass logits [batch, 9], got "
                    f"{tuple(mc_logits.shape)}."
                )
            if bin_logits.ndim != 2 or bin_logits.shape[1] != 2:
                raise ValueError(
                    f"Expected binary logits [batch, 2], got "
                    f"{tuple(bin_logits.shape)}."
                )

            pm = torch.softmax(mc_logits, dim=1).cpu().numpy()
            pb = torch.softmax(bin_logits, dim=1).cpu().numpy()

            prob_mc.extend(pm)
            prob_bin.extend(pb)
            pred_mc.extend(pm.argmax(axis=1))
            pred_bin.extend(pb.argmax(axis=1))

            for i in batch_indices:
                sample = samples[int(i)]
                y_mc.append(int(sample[MULTICLASS_LABEL_KEY]))
                if BINARY_LABEL_KEY in sample:
                    y_bin.append(int(sample[BINARY_LABEL_KEY]))
                else:
                    y_bin.append(
                        int(int(sample[MULTICLASS_LABEL_KEY]) != BENIGN_CLASS_ID)
                    )

    return {
        "split": split_name,
        "indices": np.asarray(indices, dtype=int),
        "y_mc": np.asarray(y_mc, dtype=int),
        "pred_mc": np.asarray(pred_mc, dtype=int),
        "prob_mc": np.asarray(prob_mc, dtype=float),
        "y_bin": np.asarray(y_bin, dtype=int),
        "pred_bin": np.asarray(pred_bin, dtype=int),
        "prob_bin": np.asarray(prob_bin, dtype=float),
    }


def calculate_metrics(result):
    rows = []
    y, p, prob = result["y_mc"], result["pred_mc"], result["prob_mc"]

    rows.append({
        "task": "multiclass",
        "accuracy": accuracy_score(y, p),
        "balanced_accuracy": balanced_accuracy_score(y, p),
        "precision_macro": precision_score(y, p, average="macro", zero_division=0),
        "recall_macro": recall_score(y, p, average="macro", zero_division=0),
        "f1_macro": f1_score(y, p, average="macro", zero_division=0),
        "precision_weighted": precision_score(y, p, average="weighted", zero_division=0),
        "recall_weighted": recall_score(y, p, average="weighted", zero_division=0),
        "f1_weighted": f1_score(y, p, average="weighted", zero_division=0),
        "mcc": matthews_corrcoef(y, p),
        "cohen_kappa": cohen_kappa_score(y, p),
        "log_loss": log_loss(y, prob, labels=np.arange(len(CLASS_NAMES))),
        "roc_auc_ovr_macro": safe_auc_multiclass(y, prob),
    })

    # Per-class precision, recall, F1, support, ROC-AUC and average precision.
    report = classification_report(
        y,
        p,
        labels=np.arange(len(CLASS_NAMES)),
        target_names=CLASS_NAMES,
        output_dict=True,
        zero_division=0,
    )

    for class_id, class_name in enumerate(CLASS_NAMES):
        one_vs_rest = (y == class_id).astype(int)
        auc, ap = np.nan, np.nan
        if len(np.unique(one_vs_rest)) == 2:
            auc = roc_auc_score(one_vs_rest, prob[:, class_id])
            ap = average_precision_score(one_vs_rest, prob[:, class_id])

        row = report[class_name]
        rows.append({
            "task": f"class:{class_name}",
            "accuracy": np.nan,
            "balanced_accuracy": np.nan,
            "precision_macro": row["precision"],
            "recall_macro": row["recall"],
            "f1_macro": row["f1-score"],
            "precision_weighted": np.nan,
            "recall_weighted": np.nan,
            "f1_weighted": np.nan,
            "mcc": np.nan,
            "cohen_kappa": np.nan,
            "log_loss": np.nan,
            "roc_auc_ovr_macro": auc,
            "average_precision": ap,
            "support": row["support"],
        })

    # Binary head: 0 = benign, 1 = malicious.
    yb, pb, probb = result["y_bin"], result["pred_bin"], result["prob_bin"]
    tn, fp, fn, tp = confusion_matrix(yb, pb, labels=[0, 1]).ravel()

    rows.append({
        "task": "binary",
        "accuracy": accuracy_score(yb, pb),
        "balanced_accuracy": balanced_accuracy_score(yb, pb),
        "precision_macro": precision_score(yb, pb, average="binary", zero_division=0),
        "recall_macro": recall_score(yb, pb, average="binary", zero_division=0),
        "f1_macro": f1_score(yb, pb, average="binary", zero_division=0),
        "precision_weighted": np.nan,
        "recall_weighted": np.nan,
        "f1_weighted": np.nan,
        "specificity": tn / (tn + fp) if (tn + fp) else np.nan,
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "mcc": matthews_corrcoef(yb, pb),
        "cohen_kappa": cohen_kappa_score(yb, pb),
        "log_loss": log_loss(yb, probb, labels=[0, 1]),
        "roc_auc_ovr_macro": (
            roc_auc_score(yb, probb[:, 1])
            if len(np.unique(yb)) == 2 else np.nan
        ),
        "average_precision": (
            average_precision_score(yb, probb[:, 1])
            if len(np.unique(yb)) == 2 else np.nan
        ),
    })

    return pd.DataFrame(rows), report


def safe_auc_multiclass(y, probabilities):
    try:
        if len(np.unique(y)) < 2:
            return np.nan
        return roc_auc_score(
            y,
            probabilities,
            labels=np.arange(len(CLASS_NAMES)),
            multi_class="ovr",
            average="macro",
        )
    except ValueError:
        return np.nan


def plot_confusion(y, pred, labels, names, title, output_path, normalize=False):
    cm = confusion_matrix(y, pred, labels=labels)
    if normalize:
        row_sums = cm.sum(axis=1, keepdims=True)
        cm = np.divide(
            cm, row_sums,
            out=np.zeros_like(cm, dtype=float),
            where=row_sums != 0,
        )
        fmt = ".2%"
    else:
        fmt = "d"

    plt.figure(figsize=(11, 9))
    sns.heatmap(
        cm, annot=True, fmt=fmt, cmap="Blues",
        xticklabels=names, yticklabels=names
    )
    plt.title(title)
    plt.xlabel("Predicted label")
    plt.ylabel("True label")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_multiclass_roc(result, output_path):
    y, probs = result["y_mc"], result["prob_mc"]
    plt.figure(figsize=(9, 7))
    plotted = 0

    for i, name in enumerate(CLASS_NAMES):
        binary_y = (y == i).astype(int)
        if len(np.unique(binary_y)) < 2:
            continue
        fpr, tpr, _ = roc_curve(binary_y, probs[:, i])
        auc = roc_auc_score(binary_y, probs[:, i])
        plt.plot(fpr, tpr, label=f"{name} (AUC={auc:.3f})")
        plotted += 1

    plt.plot([0, 1], [0, 1], "k--", label="Random baseline")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(f"{result['split']} Multiclass ROC (One-vs-Rest)")
    plt.legend(fontsize=8, loc="lower right")
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_multiclass_pr(result, output_path):
    y, probs = result["y_mc"], result["prob_mc"]
    plt.figure(figsize=(9, 7))

    for i, name in enumerate(CLASS_NAMES):
        binary_y = (y == i).astype(int)
        if len(np.unique(binary_y)) < 2:
            continue
        precision, recall, _ = precision_recall_curve(binary_y, probs[:, i])
        ap = average_precision_score(binary_y, probs[:, i])
        plt.plot(recall, precision, label=f"{name} (AP={ap:.3f})")

    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title(f"{result['split']} Multiclass Precision–Recall")
    plt.legend(fontsize=8, loc="best")
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_binary_curves(result, output_prefix):
    y = result["y_bin"]
    p = result["prob_bin"][:, 1]

    if len(np.unique(y)) < 2:
        warnings.warn(f"{result['split']}: binary curves require both classes.")
        return

    fpr, tpr, _ = roc_curve(y, p)
    auc = roc_auc_score(y, p)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f"ROC-AUC={auc:.4f}")
    plt.plot([0, 1], [0, 1], "k--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(f"{result['split']} Binary ROC")
    plt.legend()
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(f"{output_prefix}_binary_roc.png", dpi=300)
    plt.close()

    precision, recall, _ = precision_recall_curve(y, p)
    ap = average_precision_score(y, p)
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, label=f"Average Precision={ap:.4f}")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title(f"{result['split']} Binary Precision–Recall")
    plt.legend()
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(f"{output_prefix}_binary_pr.png", dpi=300)
    plt.close()


def save_results(result, output_dir):
    split = result["split"]
    prefix = output_dir / split.lower()

    metrics_df, report = calculate_metrics(result)
    metrics_df.to_csv(f"{prefix}_metrics.csv", index=False)

    with open(f"{prefix}_multiclass_classification_report.json", "w") as f:
        json.dump(report, f, indent=2)

    with open(f"{prefix}_binary_classification_report.txt", "w") as f:
        f.write(classification_report(
            result["y_bin"], result["pred_bin"],
            labels=[0, 1],
            target_names=["Benign", "Malicious"],
            digits=4, zero_division=0,
        ))

    with open(f"{prefix}_multiclass_classification_report.txt", "w") as f:
        f.write(classification_report(
            result["y_mc"], result["pred_mc"],
            labels=np.arange(len(CLASS_NAMES)),
            target_names=CLASS_NAMES,
            digits=4, zero_division=0,
        ))

    # Raw and row-normalized confusion matrices.
    plot_confusion(
        result["y_mc"], result["pred_mc"],
        np.arange(len(CLASS_NAMES)), CLASS_NAMES,
        f"{split} Multiclass Confusion Matrix",
        f"{prefix}_multiclass_confusion_matrix.png",
    )
    plot_confusion(
        result["y_mc"], result["pred_mc"],
        np.arange(len(CLASS_NAMES)), CLASS_NAMES,
        f"{split} Normalized Multiclass Confusion Matrix",
        f"{prefix}_multiclass_confusion_matrix_normalized.png",
        normalize=True,
    )
    plot_confusion(
        result["y_bin"], result["pred_bin"],
        [0, 1], ["Benign", "Malicious"],
        f"{split} Binary Confusion Matrix",
        f"{prefix}_binary_confusion_matrix.png",
    )
    plot_confusion(
        result["y_bin"], result["pred_bin"],
        [0, 1], ["Benign", "Malicious"],
        f"{split} Normalized Binary Confusion Matrix",
        f"{prefix}_binary_confusion_matrix_normalized.png",
        normalize=True,
    )

    plot_multiclass_roc(result, f"{prefix}_multiclass_roc.png")
    plot_multiclass_pr(result, f"{prefix}_multiclass_pr.png")
    plot_binary_curves(result, prefix)

    # Save predictions and class probabilities for error analysis.
    predictions = pd.DataFrame({
        "original_sample_index": result["indices"],
        "true_multiclass_id": result["y_mc"],
        "true_multiclass_name": [
            CLASS_NAMES[i] for i in result["y_mc"]
        ],
        "predicted_multiclass_id": result["pred_mc"],
        "predicted_multiclass_name": [
            CLASS_NAMES[i] for i in result["pred_mc"]
        ],
        "multiclass_correct": (
            result["y_mc"] == result["pred_mc"]
        ),
        "true_binary": result["y_bin"],
        "predicted_binary": result["pred_bin"],
        "binary_correct": (
            result["y_bin"] == result["pred_bin"]
        ),
        "binary_benign_probability": result["prob_bin"][:, 0],
        "binary_malicious_probability": result["prob_bin"][:, 1],
    })

    for i, name in enumerate(CLASS_NAMES):
        safe_name = name.lower().replace(" ", "_")
        predictions[f"prob_{safe_name}"] = result["prob_mc"][:, i]

    predictions.to_csv(f"{prefix}_predictions.csv", index=False)

    print(f"\n===== {split.upper()} RESULTS =====")
    print(metrics_df.to_string(index=False))
    print(f"\nSaved reports and figures to: {output_dir}")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Device:", device)

    samples = load_serialized_dataset(DATASET_PATH)
    y_mc, y_bin = extract_labels(samples)

    print("Total sequences:", len(samples))
    print("Multiclass distribution:")
    for i, name in enumerate(CLASS_NAMES):
        print(f"  {i}: {name}: {(y_mc == i).sum()}")

    # Stratified 70/15/15 split. For final thesis numbers, use the
    # EXACT saved split indices used during training if available.
    all_indices = np.arange(len(samples))

    train_val_indices, test_indices = train_test_split(
        all_indices,
        test_size=0.15,
        random_state=RANDOM_SEED,
        stratify=y_mc,
    )

    relative_val_size = 0.15 / 0.85
    train_indices, val_indices = train_test_split(
        train_val_indices,
        test_size=relative_val_size,
        random_state=RANDOM_SEED,
        stratify=y_mc[train_val_indices],
    )

    print(
        f"Split sizes: train={len(train_indices)}, "
        f"validation={len(val_indices)}, test={len(test_indices)}"
    )

    # Import your actual model from your project package.
    # Change this import if your module has a different path.
    from models.htstcl_gnn_multiclass import HTSTCL_GNN_Multiclass

    model = HTSTCL_GNN_Multiclass(
        input_dim=INPUT_DIM,
        hidden_dim=HIDDEN_DIM,
        embedding_dim=EMBEDDING_DIM,
        num_classes=len(CLASS_NAMES),
        gru_layers=GRU_LAYERS,
        dropout=DROPOUT,
    )

    checkpoint = load_model_checkpoint(
        model, CHECKPOINT_PATH, device
    )

    print("Checkpoint loaded successfully.")
    if isinstance(checkpoint, dict):
        for key in ("epoch", "best_val_accuracy", "val_accuracy"):
            if key in checkpoint:
                print(f"Checkpoint {key}: {checkpoint[key]}")

    # Validation and test only; do not use test metrics to tune the model.
    val_result = predict_split(
        model, samples, val_indices, device, "Validation"
    )
    test_result = predict_split(
        model, samples, test_indices, device, "Test"
    )

    save_results(val_result, OUTPUT_DIR)
    save_results(test_result, OUTPUT_DIR)

    # Compact comparison of the two splits.
    comparison_rows = []
    for result in (val_result, test_result):
        metrics_df, _ = calculate_metrics(result)
        for task in ("binary", "multiclass"):
            row = metrics_df.loc[metrics_df["task"] == task].iloc[0]
            comparison_rows.append({
                "split": result["split"],
                "task": task,
                "accuracy": row["accuracy"],
                "precision": row["precision_macro"],
                "recall": row["recall_macro"],
                "f1": row["f1_macro"],
                "roc_auc": row["roc_auc_ovr_macro"],
            })

    pd.DataFrame(comparison_rows).to_csv(
        OUTPUT_DIR / "validation_vs_test_summary.csv",
        index=False,
    )

    print("\nEvaluation completed.")
    print("Output directory:", OUTPUT_DIR)


if __name__ == "__main__":
    main()
