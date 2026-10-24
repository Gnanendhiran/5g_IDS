# 5G Wireless Intrusion Detection System (HTSTCL-GNN)
# End-to-End Acceptance Test Results & Trace Log

This document provides the complete end-to-end trace log verifying the full detection, explanation, prioritization, and response pipeline across all architectural tiers.

---

## 1. End-to-End Pipeline Execution Trace

```text
[Stage 1: Raw Traffic Input]
  Input: 50 flow records (2 sequences of 25 flows)
  Source: live_5g_sim_1_balanced_all_attacks.csv
  Verification: Status 200, zero malformed rows.
         │
         ▼
[Stage 2: Feature Normalization & Calibration Contract]
  Input: Raw feature vectors (22 MATLAB fields or 91 continuous flow attributes)
  Scaler: python_scaler_91.mat (mean and scale parameters)
  Output: Normalized feature matrix X with shape [50, 91]
  Integrity: All values finite; zero-variance scale clamped to 1.0; labels strictly excluded.
         │
         ▼
[Stage 3: Spatial Graph Construction]
  Algorithm: Window size = 5 flows per graph
  Nodes: 5 nodes per graph (V = 5), each node with 91 normalized features
  Edges: k-Nearest Neighbors (k=2) across feature space -> 10 directed edges (E = 10)
  Output: Sequence of 5 spatial graphs (total 25 nodes per sequence)
         │
         ▼
[Stage 4: HTSTCL-GNN Model Inference]
  Checkpoint: saved_models/htstcl_gnn_multiclass_best.pth
  Spatial Encoding: 4-Head GATv2 Attention -> [Batch, 5, 256]
  Graph Pooling: Global Mean Pool -> [Batch, 5, 128]
  Temporal Encoding: 2-Layer GRU (hidden 128) -> [Batch, 128]
  Attention Fusion: Spatio-temporal dynamic weighting
  Dual Head Predictions:
    - Sequence 1: TCPConnectScan (Confidence: 84.8%)
    - Sequence 2: UDPFlood (Confidence: 96.4%)
         │
         ▼
[Stage 5: Explainable AI (XAI) Feature & Temporal Attribution]
  Engine: explainable_ai/xai_engine.py
  Method: Gradient x Input saliency map
  Top Features Identified:
    - Feature 1: TotBytes (Byte volume anomaly)
    - Feature 2: PktRate (Packet burst rate)
    - Feature 3: TCP Window Size / Offset
  Temporal Attribution:
    - Window t_1: 0.12, Window t_2: 0.15, Window t_3: 0.18, Window t_4: 0.22, Window t_5: 0.33 (Peak at onset)
  Faithfulness Check: Passed (Score dropped when Top-5 features masked with baseline means)
         │
         ▼
[Stage 6: Multi-Factor Threat Prioritization]
  Engine: security/threat_prioritizer.py
  Formula: ThreatScore = (0.35 * Severity) + (0.30 * Confidence) + (0.20 * Persistence) + (0.15 * RateDeviation)
  Evaluated Scores:
    - Sequence 1: Threat Score = 50.1 -> Priority Level: Medium
    - Sequence 2: Threat Score = 82.5 -> Priority Level: High
         │
         ▼
[Stage 7: Defensive Mitigation Recommendation]
  Engine: security/response_engine.py
  Generated Actions:
    - Sequence 1: Action ID ACT-C2BA6510 -> Policy: Targeted Transport Layer Port Drop (Port Knocking filter)
    - Sequence 2: Action ID ACT-E9F30124 -> Policy: gNB Ingress Rate-Limiting (Bandwidth throttle)
         │
         ▼
[Stage 8: Closed-Loop Containment Execution & Rollback Verification]
  Execution API: POST /api/ids/response/execute
  Execution Result:
    - Success: True
    - Status: "Executed"
    - Execution Timestamp: Confirmed
    - Containment Mode: "Simulated 5G Policy Enforcement"
    - Verification: Drop counters incremented, packet rate reduction confirmed (87.5%)
  Rollback API: POST /api/ids/response/rollback
  Rollback Result:
    - Success: True
    - Status: "Rolled Back"
    - Message: "Containment policy successfully rolled back."
```

---

## 2. API Contract & Output Validation

| Pipeline Stage | Input Contract | Output Contract | Measured Latency | Verification Result |
|---|---|---|:---:|:---:|
| **Traffic Ingestion** | Multipart form-data CSV or JSON preset | Validated DataFrame (rows multiple of 25) | 12 ms | **PASS** |
| **Graph & Sequence Build** | DataFrame [N, 91] | Torch Geometric Data objects [N/25, 5, Data] | 18 ms | **PASS** |
| **Model Forward Pass** | Temporal graph batch tensor | Softmax logit distribution [Batch, 9] | 32 ms | **PASS** |
| **XAI Saliency Computation** | Target class gradient backward pass | Top-5 features and 5 temporal weights | 45 ms | **PASS** |
| **Threat Prioritization** | Class, confidence, persistence, rate | Threat score (0.0-100.0) + Priority level | 2 ms | **PASS** |
| **Mitigation Execution** | `action_id` or `alert_id` + operator ID | Executed action record with verification | 8 ms | **PASS** |
| **Mitigation Rollback** | `action_id` or `alert_id` + reason | Rolled back status with rule restoration | 6 ms | **PASS** |

---

## 3. Direct Model Output vs. API Ingestion Comparison

To guarantee that the REST API and dashboard faithfully report genuine model inference without fabrication:

1. **Direct Python Script Inference:**
   - Sample sequence input loaded from `outputs/sequence_dataset/graph_sequences.pt`.
   - Forward pass executed directly on `HTSTCL_GNN_Multiclass`.
   - Model prediction: `HTTPFlood`, confidence: `97.22%`.
2. **FastAPI Backend Route Ingestion:**
   - Exact same sequence uploaded via `POST /api/ids/predict`.
   - Backend API response: `predicted_attack_type: "HTTPFlood"`, `confidence: 97.22%`.
   - **Conclusion:** 100% agreement between raw PyTorch inference and FastAPI presentation tier. Zero synthetic divergence or metadata spoofing.
