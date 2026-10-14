# Experimental Evaluation & Model Comparison

## 1. Test Evaluation Summary (Held-Out Test Set: 7,296 Sequences)

### A. Original Binary Baseline vs Upgraded Multiclass Model

| Metric | Original Binary Baseline (Historical) | Upgraded Multiclass HTSTCL-GNN (Dual-Head) |
|---|---|---|
| **Classification Task** | Binary (Benign / Malicious) | **Multiclass (9 Genuine 5G-NIDD Classes)** |
| **Output Classes** | 2 | **9 (Benign + 8 Attacks)** |
| **Overall Accuracy** | 98.41% | **98.12%** |
| **Macro Precision** | 98.83% | **99.00%** |
| **Macro Recall** | 98.66% | **98.68%** |
| **Macro F1-Score** | 98.75% | **98.83%** |
| **Weighted F1-Score** | 98.75% | **98.12%** |
| **Derived Binary Accuracy** | 98.41% | **98.26%** |
| **Derived Binary Recall** | 98.66% | **99.68%** |
| **Derived Binary F1-Score** | 98.75% | **98.64%** |
| **Checkpoint Path** | `saved_models/htstcl_gnn_best.pth` | `saved_models/htstcl_gnn_multiclass_best.pth` |

---

## 2. Per-Class Test Performance Breakdown

From `reports/multiclass_classification_report.txt`:

| Class Index | Attack Category | Test Support | Precision | Recall | F1-Score |
|---|---|---|---|---|---|
| **0** | **Benign** | 2,661 | 0.9941 (99.41%) | 0.9579 (95.79%) | 0.9757 (97.57%) |
| **1** | **UDPFlood** | 2,808 | 0.9615 (96.15%) | 0.9972 (99.72%) | 0.9790 (97.90%) |
| **2** | **HTTPFlood** | 848 | 0.9976 (99.76%) | 0.9917 (99.17%) | 0.9947 (99.47%) |
| **3** | **SlowrateDoS** | 491 | 0.9919 (99.19%) | 0.9939 (99.39%) | 0.9929 (99.29%) |
| **4** | **TCPConnectScan** | 110 | 0.9821 (98.21%) | 1.0000 (100.0%) | 0.9910 (99.10%) |
| **5** | **SYNScan** | 113 | 1.0000 (100.0%) | 0.9912 (99.12%) | 0.9956 (99.56%) |
| **6** | **UDPScan** | 119 | 0.9915 (99.15%) | 0.9832 (98.32%) | 0.9873 (98.73%) |
| **7** | **SYNFlood** | 117 | 0.9912 (99.12%) | 0.9658 (96.58%) | 0.9784 (97.84%) |
| **8** | **ICMPFlood** | 29 | 1.0000 (100.0%) | 1.0000 (100.0%) | 1.0000 (100.0%) |
| **Macro Average** | | **7,296** | **0.9900 (99.00%)** | **0.9868 (98.68%)** | **0.9883 (98.83%)** |

---

## 3. Key Observations
1. **Zero Class Omission:** All 8 attack categories achieve $>97.8\%$ F1-score on the held-out test set.
2. **High Rarity Resilience:** Extremely rare categories such as `ICMPFlood` (only 29 test samples) and `TCPConnectScan` (110 test samples) achieved 100% and 99.10% F1-scores due to the smoothed class-weighted cross-entropy loss.
3. **Preservation of Detection Recall:** Malicious traffic detection recall reached **99.68%**, ensuring less than 0.35% false negative escapes.
