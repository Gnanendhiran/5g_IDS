# 5G-NIDD Dataset & Attack Class Schema Report

## Overview
- **Dataset**: 5G-NIDD (5G Network Intrusion Detection Dataset)
- **Total Flows in Raw Dataset**: 1,215,890
- **Total Windows Created (Window Size = 5)**: 243,178
- **Total Sequences Created (Sequence Length = 5)**: 48,635
- **Total Nodes per Sequence**: 25 (5 graphs × 5 nodes)
- **Node Feature Dimension**: 91 features
- **Classification Tasks**: Binary (Benign / Malicious) and Multiclass (9 Classes)

## Verified Attack Categories in 5G-NIDD

| Multiclass Index | Attack Category | Binary Class | Total Sequences | Percentage | Train (70%) | Val (15%) | Test (15%) |
|---|---|---|---|---|---|---|---|
| 0 | Benign | Benign | 17,738 | 36.47% | 12,416 | 2,661 | 2,661 |
| 1 | UDPFlood | Malicious | 18,527 | 38.09% | 12,949 | 2,770 | 2,808 |
| 2 | HTTPFlood | Malicious | 5,846 | 12.02% | 4,126 | 872 | 848 |
| 3 | SlowrateDoS | Malicious | 3,163 | 6.50% | 2,197 | 475 | 491 |
| 4 | TCPConnectScan | Malicious | 819 | 1.68% | 574 | 135 | 110 |
| 5 | SYNScan | Malicious | 821 | 1.69% | 586 | 122 | 113 |
| 6 | UDPScan | Malicious | 725 | 1.49% | 497 | 109 | 119 |
| 7 | SYNFlood | Malicious | 779 | 1.60% | 545 | 117 | 117 |
| 8 | ICMPFlood | Malicious | 217 | 0.45% | 154 | 34 | 29 |

## Label Alignment Integrity
- All 48,635 sequences mapped with zero loss of sample identity.
- Mismatches between sequence-level binary label and multiclass label: 0 (0.00%).
- Train / Validation / Test split strictly matches original stratified baseline.
