# 5G Wireless Intrusion Detection System — System Architecture

## 1. High-Level System Architecture

```text
  +-------------------------------------------------------------------------+
  |                        5G Network Traffic Sources                       |
  |                                                                         |
  |   +----------------------------+       +----------------------------+   |
  |   | 5G-NIDD Benchmark Dataset  |       | MATLAB Multi-Cell Sim      |   |
  |   | (1.2M flows, 91 features,  |       | (2 gNBs, 30 UEs, 100 sec,  |   |
  |   |  9 genuine attack classes) |       |  22 exported traffic fields|   |
  |   +-------------+--------------+       +-------------+--------------+   |
  +-----------------|------------------------------------|------------------+
                    |                                    |
                    v                                    v
  +-------------------------------------------------------------------------+
  |              Feature Normalization & Calibration Contract               |
  |                                                                         |
  |   - python_scaler_91.mat (91 mean & scale parameters)                   |
  |   - Physical Identifications (TotBytes=Bytes, Rate=PacketRate, etc.)    |
  |   - 8-Dimensional Standardized Log-Calibration Metric                   |
  |   - Ground Truth Segregation (Labels strictly excluded from input)      |
  +-------------------------------------+-----------------------------------+
                                        |
                                        v
  +-------------------------------------------------------------------------+
  |                    Spatial & Temporal Graph Builder                     |
  |                                                                         |
  |   - Node Windowing: 5 flow records -> 5 nodes per graph                 |
  |   - Spatial Graph Construction: k-NN (k=2) -> 10 directed edges         |
  |   - Temporal Sequence Construction: 5 graphs -> 1 sequence (25 nodes)   |
  +-------------------------------------+-----------------------------------+
                                        |
                                        v
  +-------------------------------------------------------------------------+
  |                      HTSTCL-GNN Detection Model                         |
  |                                                                         |
  |   +-----------------------------------------------------------------+   |
  |   | 1. Spatial Encoder: 4-Head Graph Attention Network (GAT)        |   |
  |   +--------------------------------+--------------------------------+   |
  |                                    |                                    |
  |   +--------------------------------v--------------------------------+   |
  |   | 2. Graph Pooling: Global Mean Pool (Batch x 128)                |   |
  |   +--------------------------------+--------------------------------+   |
  |                                    |                                    |
  |   +--------------------------------v--------------------------------+   |
  |   | 3. Temporal Encoder: 2-Layer Gated Recurrent Unit (GRU)         |   |
  |   +--------------------------------+--------------------------------+   |
  |                                    |                                    |
  |   +--------------------------------v--------------------------------+   |
  |   | 4. Hierarchical Fusion: Spatio-Temporal Attention Fusion        |   |
  |   +--------------------------------+--------------------------------+   |
  |                                    |                                    |
  |   +--------------------------------v--------------------------------+   |
  |   | 5. Dual / Multiclass Heads:                                     |   |
  |   |    - Binary Head: Benign vs Malicious                           |   |
  |   |    - Multiclass Head: 9 Genuine Attack Types                    |   |
  |   +--------------------------------+--------------------------------+   |
  +-------------------------------------|-----------------------------------+
                                        |
                    +-------------------+-------------------+
                    |                                       |
                    v                                       v
  +-----------------------------------+   +---------------------------------+
  |      Explainable AI (XAI)         |   |    Threat Prioritization        |
  |                                   |   |                                 |
  | - Integrated Gradients            |   | - Multi-factor Threat Score     |
  | - Top-k Feature Attributions      |   |   (Severity, Confidence,        |
  | - Temporal Window Attribution     |   |    Persistence, Deviation)      |
  | - Human-Readable Alert Rationale  |   | - Priority: Critical/High/      |
  | - Explanation Faithfulness Checks |   |             Med/Low/Review      |
  +-----------------+-----------------+   +-----------------+---------------+
                    |                                       |
                    +-------------------+-------------------+
                                        |
                                        v
  +-------------------------------------------------------------------------+
  |                Defensive Response & Containment Engine                  |
  |                                                                         |
  |   - Response Policy Catalog (Rate limiting, UE Quarantine, Blocking)    |
  |   - State Machine: Detected -> Under Investigation -> Recommended ->    |
  |                    Awaiting Approval -> Executed -> Rolled Back         |
  |   - Audit Logging & Containment Verification                            |
  +-------------------------------------+-----------------------------------+
                                        |
                                        v
  +-------------------------------------------------------------------------+
  |                    Unified SOC Analyst Dashboard                        |
  |                                                                         |
  |   - Backend: FastAPI REST API (port 8000)                               |
  |   - Frontend: Modern Dark-Mode React 18 / Vite Application (port 5173)  |
  |   - Pages: Overview, Live Monitor, Alert Investigation, Analytics,      |
  |            Explainability, Threat Prioritizer, Defensive Response,      |
  |            Network Topology, Model Evaluation, Federated IDS, Reports   |
  +-------------------------------------------------------------------------+
```

## 2. Component Interaction & Data Contracts

1. **Inference Request**: Accepts raw CSV flows or pre-computed temporal graph sequences.
2. **Feature Extractor**: Maps incoming rows to canonical 91-dimensional float32 tensor matching `python_scaler_91.mat`.
3. **Graph Generator**: Applies k-NN (k=2) to generate `[2, 10]` edge index for each 5-node graph.
4. **Model Inference**: HTSTCL-GNN executes forward pass, outputting class logits, spatio-temporal embeddings, and attention weights.
5. **Post-Processing**:
   - Softmax yields 9-class probabilities.
   - Max probability defines predicted attack category and confidence.
   - Ground truth is strictly isolated and used only for evaluation metrics.
6. **XAI Attribution**: Calculates gradient attributions for the top predicting class, highlighting the top 5 contributing traffic features.
7. **Threat Scoring**:
   $$\text{Score} = w_1 \cdot \text{Severity} + w_2 \cdot \text{Confidence} + w_3 \cdot \text{Persistence} + w_4 \cdot \text{TrafficDeviation}$$
8. **Mitigation Recommendation**: Looks up verified response catalog for the detected attack type and priority.
9. **Event Storage**: Stores structured alert in SQLite / memory repository for dashboard consumption.
