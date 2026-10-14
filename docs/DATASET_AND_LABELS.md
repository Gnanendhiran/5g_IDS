# 5G-NIDD Dataset & Attack Labels Documentation

## 1. Dataset Overview
- **Dataset:** 5G Network Intrusion Detection Dataset (5G-NIDD)
- **Total Flows:** 1,215,890
- **Total Sequences (Temporal Graph):** 48,635
- **Sequence Length:** 5 graphs
- **Nodes per Graph:** 5 nodes (each node = 1 flow record)
- **Total Nodes per Sequence:** 25 nodes
- **Predictive Features:** Exactly 91 continuous and one-hot categorical features

---

## 2. Verified Genuine Attack Classes

All 9 classes were audited and verified directly from `dataset/Combined.csv` and `outputs/node_features/node_features_window_5.csv`:

| Class Index | Attack Category | Binary Status | Total Sequences | Percentage | Train (70%) | Val (15%) | Test (15%) |
|---|---|---|---|---|---|---|---|
| **0** | **Benign** | Benign | 17,738 | 36.47% | 12,416 | 2,661 | 2,661 |
| **1** | **UDPFlood** | Malicious | 18,527 | 38.09% | 12,949 | 2,770 | 2,808 |
| **2** | **HTTPFlood** | Malicious | 5,846 | 12.02% | 4,126 | 872 | 848 |
| **3** | **SlowrateDoS** | Malicious | 3,163 | 6.50% | 2,197 | 475 | 491 |
| **4** | **TCPConnectScan** | Malicious | 819 | 1.68% | 574 | 135 | 110 |
| **5** | **SYNScan** | Malicious | 821 | 1.69% | 586 | 122 | 113 |
| **6** | **UDPScan** | Malicious | 725 | 1.49% | 497 | 109 | 119 |
| **7** | **SYNFlood** | Malicious | 779 | 1.60% | 545 | 117 | 117 |
| **8** | **ICMPFlood** | Malicious | 217 | 0.45% | 154 | 34 | 29 |
| **Total** | | | **48,635** | **100.00%** | **34,044** | **7,295** | **7,296** |

---

## 3. Label Alignment Integrity
- **Sequence Labeling Rule:** If any graph within the 5-graph sequence contains malicious activity, the sequence target is assigned to the predominant malicious attack type. If all nodes across all 5 graphs are benign, the sequence target is `Benign` (Index 0).
- **Mismatch Rate:** Exactly **0.00% (0 / 48,635)** mismatch between binary labels and the 9-class multiclass targets.
- **Split Separation:** Stratified 70% Train, 15% Validation, 15% Test. Zero sequence leakage across partitions.
