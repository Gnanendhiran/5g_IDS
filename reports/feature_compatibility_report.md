# 5G HTSTCL-GNN Feature Compatibility & Graph Alignment Report

## 1. Executive Summary
- **Model Input Dimension**: Exactly 91 features per node.
- **Graph Topology**: 5 nodes per graph (window of 5 flows), k-NN edge construction with k=2 (10 directed edges).
- **Temporal Sequence Length**: 5 graphs per sequence (25 nodes total).
- **Simulation Source Data**: 22 fields exported from MATLAB multi-cell simulation.
- **Ground Truth Integrity**: Ground-truth labels (`AttackType`, `TrafficType`) are strictly separated and NEVER enter feature vectors.

## 2. 91-Feature Schema Overview
The 91 features originated from the 5G-NIDD dataset flow extraction:
- 34 Continuous flow metrics (Dur, RunTime, Mean, Sum, Min, Max, TotPkts, Bytes, Rates, Loss, TCP RTT, etc.)
- 8 Header/QoS attributes (sTos, dTos, sTtl, dTtl, sHops, dHops, sVid, dVid)
- 14 TCP state indicator flags (*, * V, e, eU, etc.)
- 8 Protocol one-hot flags (arp, icmp, ipv6-icmp, llc, lldp, sctp, tcp, udp)
- 11 Transaction/Session state flags (ACC, CON, ECO, FIN, INT, NRS, REQ, RSP, RST, TST, URP)
- 3 Session status flags (Shutdown, Start, Status)
- 13 DSCP / DiffServ QoS markers (39, 4, 52, 54, af11, af12, af41, cs0, cs4, cs6, cs7, ef, nan)

## 3. MATLAB Simulation Alignment Strategy
To prevent data leakage and arbitrary padding:
1. **Physical Derivations**: Where physical identities hold (e.g. `TotBytes = Bytes`, `Rate = PacketRate`, `pLoss = LossRate * 100`, `Load = (Bytes*8)/Dur`), exact derivations are applied.
2. **Standard Protocol Defaults**: For standard headers unobservable in synthetic application layer, deterministic RFC standards are used (e.g., IP TTL=64, best-effort `cs0=1.0`).
3. **Calibration Space**: The backend uses an 8-variable log-calibration contract (`Duration`, `PacketCount`, `Bytes`, `PacketRate`, `MeanPacketSize`, `MinPacketSize`, `MaxPacketSize`, `LossRate`) with a review distance metric (`CALIBRATION_REVIEW_DISTANCE = 10.0`) to flag out-of-distribution simulated records as 'Needs Review' rather than generating ungrounded predictions.

## 4. Graph Construction Integrity
- Each node represents one network flow record.
- Graphs are formed by grouping 5 consecutive flows.
- Edges are computed via k-nearest neighbors (k=2) on standardized feature space, producing 10 directed edges.
- Sequences are formed by non-overlapping windows of 5 consecutive graphs (25 flows total).
