import os
import pandas as pd
import numpy as np

ROOT_DIR = r"d:\5G_Wireless_IDS"
REPORTS_DIR = os.path.join(ROOT_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# 1. 91 Features list and documentation
# From feature_names.txt and node_features_window_5.csv
features_91 = [
    ("Dur", "float32", "Flow duration", "5G-NIDD", "seconds", "Derivable from FlowDuration / Duration", "Dur = Duration", True),
    ("RunTime", "float32", "Total active run time", "5G-NIDD", "seconds", "Derivable from FlowDuration", "RunTime = FlowDuration", True),
    ("Mean", "float32", "Mean flow duration / interval", "5G-NIDD", "seconds", "Derivable from InterArrivalMean", "Mean = InterArrivalMean", True),
    ("Sum", "float32", "Sum of flow active intervals", "5G-NIDD", "seconds", "Derivable from Duration", "Sum = Duration", True),
    ("Min", "float32", "Minimum packet size / interval", "5G-NIDD", "bytes", "Direct in simulation", "Min = MinPacketSize", True),
    ("Max", "float32", "Maximum packet size / interval", "5G-NIDD", "bytes", "Direct in simulation", "Max = MaxPacketSize", True),
    ("sTos", "float32", "Source Type of Service", "5G-NIDD", "raw", "Unavailable in basic simulation (default 0)", "sTos = 0.0", True),
    ("dTos", "float32", "Destination Type of Service", "5G-NIDD", "raw", "Unavailable in basic simulation (default 0)", "dTos = 0.0", True),
    ("sTtl", "float32", "Source Time to Live", "5G-NIDD", "hops", "Derivable (typical IP TTL 64)", "sTtl = 64.0", True),
    ("dTtl", "float32", "Destination Time to Live", "5G-NIDD", "hops", "Derivable (typical IP TTL 64)", "dTtl = 64.0", True),
    ("sHops", "float32", "Source estimated hops", "5G-NIDD", "hops", "Derivable (1-2 wireless hops)", "sHops = 1.0", True),
    ("dHops", "float32", "Destination estimated hops", "5G-NIDD", "hops", "Derivable (1-2 wireless hops)", "dHops = 1.0", True),
    ("TotPkts", "float32", "Total packet count", "5G-NIDD", "packets", "Direct in simulation", "TotPkts = PacketCount", True),
    ("SrcPkts", "float32", "Source packet count", "5G-NIDD", "packets", "Derivable via source fraction", "SrcPkts = round(TotPkts * 0.7)", True),
    ("DstPkts", "float32", "Destination packet count", "5G-NIDD", "packets", "Derivable via TotPkts - SrcPkts", "DstPkts = TotPkts - SrcPkts", True),
    ("TotBytes", "float32", "Total bytes transferred", "5G-NIDD", "bytes", "Direct in simulation", "TotBytes = Bytes", True),
    ("SrcBytes", "float32", "Source bytes transferred", "5G-NIDD", "bytes", "Derivable via SrcPkts * sMeanPktSz", "SrcBytes = SrcPkts * MeanPacketSize", True),
    ("DstBytes", "float32", "Destination bytes transferred", "5G-NIDD", "bytes", "Derivable via TotBytes - SrcBytes", "DstBytes = max(0, TotBytes - SrcBytes)", True),
    ("Offset", "float32", "Packet offset / byte position", "5G-NIDD", "bytes", "Unavailable (default 0)", "Offset = 0.0", True),
    ("sMeanPktSz", "float32", "Source mean packet size", "5G-NIDD", "bytes", "Direct in simulation", "sMeanPktSz = MeanPacketSize", True),
    ("dMeanPktSz", "float32", "Destination mean packet size", "5G-NIDD", "bytes", "Derivable from DstBytes/DstPkts", "dMeanPktSz = MeanPacketSize", True),
    ("Load", "float32", "Bits per second total load", "5G-NIDD", "bps", "Derivable via TotBytes*8/Dur", "Load = (Bytes * 8) / max(0.001, Duration)", True),
    ("SrcLoad", "float32", "Source bits per second load", "5G-NIDD", "bps", "Derivable via SrcBytes*8/Dur", "SrcLoad = (SrcBytes * 8) / max(0.001, Duration)", True),
    ("DstLoad", "float32", "Destination bits per second load", "5G-NIDD", "bps", "Derivable via DstBytes*8/Dur", "DstLoad = (DstBytes * 8) / max(0.001, Duration)", True),
    ("Loss", "float32", "Total packet loss count", "5G-NIDD", "packets", "Derivable via TotPkts * LossRate", "Loss = TotPkts * LossRate", True),
    ("SrcLoss", "float32", "Source packet loss count", "5G-NIDD", "packets", "Derivable via SrcPkts * LossRate", "SrcLoss = SrcPkts * LossRate", True),
    ("DstLoss", "float32", "Destination packet loss count", "5G-NIDD", "packets", "Derivable via DstPkts * LossRate", "DstLoss = DstPkts * LossRate", True),
    ("pLoss", "float32", "Packet loss percentage", "5G-NIDD", "percent", "Direct in simulation", "pLoss = LossRate * 100", True),
    ("SrcGap", "float32", "Source inter-packet gap time", "5G-NIDD", "seconds", "Derivable via InterArrivalMean", "SrcGap = InterArrivalMean", True),
    ("DstGap", "float32", "Destination inter-packet gap time", "5G-NIDD", "seconds", "Derivable via InterArrivalMean", "DstGap = InterArrivalMean", True),
    ("Rate", "float32", "Packets per second rate", "5G-NIDD", "pps", "Direct in simulation", "Rate = PacketRate", True),
    ("SrcRate", "float32", "Source packets per second", "5G-NIDD", "pps", "Derivable via SrcPkts / Duration", "SrcRate = SrcPkts / max(0.001, Duration)", True),
    ("DstRate", "float32", "Destination packets per second", "5G-NIDD", "pps", "Derivable via DstPkts / Duration", "DstRate = DstPkts / max(0.001, Duration)", True),
    ("SrcWin", "float32", "Source TCP window advertisement", "5G-NIDD", "bytes", "Derivable (standard TCP win 65535)", "SrcWin = 65535.0 if Protocol=='TCP' else 0", True),
    ("DstWin", "float32", "Destination TCP window advertisement", "5G-NIDD", "bytes", "Derivable (standard TCP win 65535)", "DstWin = 65535.0 if Protocol=='TCP' else 0", True),
    ("sVid", "float32", "Source VLAN ID", "5G-NIDD", "id", "Unavailable (default 0)", "sVid = 0.0", True),
    ("dVid", "float32", "Destination VLAN ID", "5G-NIDD", "id", "Unavailable (default 0)", "dVid = 0.0", True),
    ("SrcTCPBase", "float32", "Source TCP initial seq base", "5G-NIDD", "seq", "Unavailable (default 0)", "SrcTCPBase = 0.0", True),
    ("DstTCPBase", "float32", "Destination TCP initial seq base", "5G-NIDD", "seq", "Unavailable (default 0)", "DstTCPBase = 0.0", True),
    ("TcpRtt", "float32", "TCP Round Trip Time", "5G-NIDD", "seconds", "Derivable via Jitter / Latency", "TcpRtt = Jitter", True),
    ("SynAck", "float32", "SYN-ACK handshake duration", "5G-NIDD", "seconds", "Derivable via Jitter * 0.5", "SynAck = Jitter * 0.5", True),
    ("AckDat", "float32", "ACK to data handshake duration", "5G-NIDD", "seconds", "Derivable via Jitter * 0.5", "AckDat = Jitter * 0.5", True),
    # State flags
    (" *        ", "float32", "TCP state flag none/established", "5G-NIDD", "binary", "Derivable from Protocol/State", "1.0 if Protocol=='TCP' else 0.0", True),
    (" *    V   ", "float32", "TCP state flag V", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" *    f   ", "float32", "TCP state flag f", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e        ", "float32", "TCP state flag e", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e    f   ", "float32", "TCP state flag e f", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e &      ", "float32", "TCP state flag e &", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e *      ", "float32", "TCP state flag e *", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e d      ", "float32", "TCP state flag e d", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e g      ", "float32", "TCP state flag e g", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e i      ", "float32", "TCP state flag e i", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e r      ", "float32", "TCP state flag e r", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" e s      ", "float32", "TCP state flag e s", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    (" eU       ", "float32", "TCP state flag eU", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("e        ", "float32", "TCP state flag e (alt)", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    # Protocol flags
    ("arp", "float32", "Protocol ARP indicator", "5G-NIDD", "binary", "Derivable from Protocol", "1.0 if Protocol=='ARP' else 0.0", True),
    ("icmp", "float32", "Protocol ICMP indicator", "5G-NIDD", "binary", "Derivable from Protocol", "1.0 if Protocol=='ICMP' else 0.0", True),
    ("ipv6-icmp", "float32", "Protocol ICMPv6 indicator", "5G-NIDD", "binary", "Derivable from Protocol", "1.0 if Protocol=='ICMPv6' else 0.0", True),
    ("llc", "float32", "Protocol LLC indicator", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("lldp", "float32", "Protocol LLDP indicator", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("sctp", "float32", "Protocol SCTP indicator", "5G-NIDD", "binary", "Derivable from Protocol", "1.0 if Protocol=='SCTP' else 0.0", True),
    ("tcp", "float32", "Protocol TCP indicator", "5G-NIDD", "binary", "Derivable from Protocol", "1.0 if Protocol=='TCP' else 0.0", True),
    ("udp", "float32", "Protocol UDP indicator", "5G-NIDD", "binary", "Derivable from Protocol", "1.0 if Protocol=='UDP' else 0.0", True),
    # Transaction codes
    ("ACC", "float32", "Transaction code ACC", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("CON", "float32", "Transaction code CON", "5G-NIDD", "binary", "Derivable (connection open)", "1.0 if Protocol=='TCP' else 0.0", True),
    ("ECO", "float32", "Transaction code ECO (ICMP Echo)", "5G-NIDD", "binary", "Derivable from Protocol", "1.0 if Protocol=='ICMP' else 0.0", True),
    ("FIN", "float32", "Transaction code FIN", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("INT", "float32", "Transaction code INT", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("NRS", "float32", "Transaction code NRS", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("REQ", "float32", "Transaction code REQ", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("RSP", "float32", "Transaction code RSP", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("RST", "float32", "Transaction code RST", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("TST", "float32", "Transaction code TST", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("URP", "float32", "Transaction code URP", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    # Session state
    ("Shutdown", "float32", "Session Shutdown flag", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("Start", "float32", "Session Start flag", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("Status", "float32", "Session Status flag", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    # DSCP / QoS markers
    ("39", "float32", "DSCP marker 39", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("4", "float32", "DSCP marker 4", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("52", "float32", "DSCP marker 52", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("54", "float32", "DSCP marker 54", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("af11", "float32", "DSCP AF11 QoS class", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("af12", "float32", "DSCP AF12 QoS class", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("af41", "float32", "DSCP AF41 QoS class", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("cs0", "float32", "DSCP Class Selector 0 (Default best effort)", "5G-NIDD", "binary", "Default for standard traffic", "1.0", True),
    ("cs4", "float32", "DSCP Class Selector 4", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("cs6", "float32", "DSCP Class Selector 6", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("cs7", "float32", "DSCP Class Selector 7", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("ef", "float32", "DSCP Expedited Forwarding (URLLC/Voice)", "5G-NIDD", "binary", "Unavailable (default 0)", "0.0", True),
    ("nan", "float32", "Missing protocol/QoS marker", "5G-NIDD", "binary", "Indicator for unclassified flows", "0.0", True),
]

assert len(features_91) == 91, f"Expected 91 features, got {len(features_91)}"

schema_df = pd.DataFrame(features_91, columns=[
    "Feature_Name", "Data_Type", "Meaning", "Source", "Unit", 
    "Simulation_Availability", "Derivation_Formula", "Safe_For_Prediction"
])

schema_csv_path = os.path.join(REPORTS_DIR, "feature_schema_91.csv")
schema_df.to_csv(schema_csv_path, index=False)
print(f"Saved: {schema_csv_path}")

# 2. Simulation Feature Mapping
sim_features = [
    ("SampleID", "Metadata", "Record identifier", "Preserved for tracking; excluded from input features"),
    ("UEID", "Metadata", "User Equipment identifier", "Preserved for tracking and SOC visualization; excluded from input features"),
    ("TrafficType", "Metadata", "Traffic profile (e.g., eMBB, URLLC, mMTC)", "Preserved for investigation; excluded from input features"),
    ("AttackType", "Ground Truth", "Ground truth attack category", "STRICTLY GROUND TRUTH ONLY; NEVER fed to model input"),
    ("PacketCount", "Network Measurement", "Total packets in time window", "Mapped to TotPkts"),
    ("Bytes", "Network Measurement", "Total bytes in time window", "Mapped to TotBytes"),
    ("Duration", "Network Measurement", "Flow duration in seconds", "Mapped to Dur and RunTime"),
    ("PacketRate", "Network Measurement", "Packets per second", "Mapped to Rate"),
    ("ByteRate", "Network Measurement", "Bytes per second", "Mapped to Load (scaled to bps)"),
    ("MeanPacketSize", "Network Measurement", "Mean packet size in bytes", "Mapped to sMeanPktSz and dMeanPktSz"),
    ("MinPacketSize", "Network Measurement", "Minimum packet size in bytes", "Mapped to Min"),
    ("MaxPacketSize", "Network Measurement", "Maximum packet size in bytes", "Mapped to Max"),
    ("InterArrivalMean", "Network Measurement", "Mean inter-packet arrival time", "Mapped to Mean and SrcGap"),
    ("InterArrivalStd", "Network Measurement", "Std dev of arrival times", "Used in calibration distance"),
    ("Burstiness", "Network Measurement", "Traffic burst index", "Used in threat prioritization scoring"),
    ("FlowDuration", "Network Measurement", "Total active flow lifetime", "Mapped to Dur and Sum"),
    ("Protocol", "Network Measurement", "Network protocol string (TCP/UDP/ICMP)", "One-hot mapped to tcp, udp, icmp binary flags"),
    ("SourcePort", "Network Measurement", "Source transport port", "Used for flow key; excluded from normalized features"),
    ("DestinationPort", "Network Measurement", "Destination transport port", "Used for attack type heuristic check"),
    ("RetransmissionRate", "Network Measurement", "Fraction of retransmitted packets", "Used in threat prioritization"),
    ("Jitter", "Network Measurement", "Packet delay variation in seconds", "Mapped to TcpRtt, SynAck, AckDat"),
    ("LossRate", "Network Measurement", "Packet loss fraction [0, 1]", "Mapped to pLoss (percent) and Loss counts"),
]

sim_df = pd.DataFrame(sim_features, columns=["Simulation_Field", "Field_Type", "Meaning", "Mapping_Or_Usage"])
sim_csv_path = os.path.join(REPORTS_DIR, "simulation_feature_mapping.csv")
sim_df.to_csv(sim_csv_path, index=False)
print(f"Saved: {sim_csv_path}")

# 3. Feature Compatibility Report
report_md_path = os.path.join(REPORTS_DIR, "feature_compatibility_report.md")
with open(report_md_path, "w", encoding="utf-8") as f:
    f.write("# 5G HTSTCL-GNN Feature Compatibility & Graph Alignment Report\n\n")
    f.write("## 1. Executive Summary\n")
    f.write("- **Model Input Dimension**: Exactly 91 features per node.\n")
    f.write("- **Graph Topology**: 5 nodes per graph (window of 5 flows), k-NN edge construction with k=2 (10 directed edges).\n")
    f.write("- **Temporal Sequence Length**: 5 graphs per sequence (25 nodes total).\n")
    f.write("- **Simulation Source Data**: 22 fields exported from MATLAB multi-cell simulation.\n")
    f.write("- **Ground Truth Integrity**: Ground-truth labels (`AttackType`, `TrafficType`) are strictly separated and NEVER enter feature vectors.\n\n")
    f.write("## 2. 91-Feature Schema Overview\n")
    f.write("The 91 features originated from the 5G-NIDD dataset flow extraction:\n")
    f.write("- 34 Continuous flow metrics (Dur, RunTime, Mean, Sum, Min, Max, TotPkts, Bytes, Rates, Loss, TCP RTT, etc.)\n")
    f.write("- 8 Header/QoS attributes (sTos, dTos, sTtl, dTtl, sHops, dHops, sVid, dVid)\n")
    f.write("- 14 TCP state indicator flags (*, * V, e, eU, etc.)\n")
    f.write("- 8 Protocol one-hot flags (arp, icmp, ipv6-icmp, llc, lldp, sctp, tcp, udp)\n")
    f.write("- 11 Transaction/Session state flags (ACC, CON, ECO, FIN, INT, NRS, REQ, RSP, RST, TST, URP)\n")
    f.write("- 3 Session status flags (Shutdown, Start, Status)\n")
    f.write("- 13 DSCP / DiffServ QoS markers (39, 4, 52, 54, af11, af12, af41, cs0, cs4, cs6, cs7, ef, nan)\n\n")
    f.write("## 3. MATLAB Simulation Alignment Strategy\n")
    f.write("To prevent data leakage and arbitrary padding:\n")
    f.write("1. **Physical Derivations**: Where physical identities hold (e.g. `TotBytes = Bytes`, `Rate = PacketRate`, `pLoss = LossRate * 100`, `Load = (Bytes*8)/Dur`), exact derivations are applied.\n")
    f.write("2. **Standard Protocol Defaults**: For standard headers unobservable in synthetic application layer, deterministic RFC standards are used (e.g., IP TTL=64, best-effort `cs0=1.0`).\n")
    f.write("3. **Calibration Space**: The backend uses an 8-variable log-calibration contract (`Duration`, `PacketCount`, `Bytes`, `PacketRate`, `MeanPacketSize`, `MinPacketSize`, `MaxPacketSize`, `LossRate`) with a review distance metric (`CALIBRATION_REVIEW_DISTANCE = 10.0`) to flag out-of-distribution simulated records as 'Needs Review' rather than generating ungrounded predictions.\n\n")
    f.write("## 4. Graph Construction Integrity\n")
    f.write("- Each node represents one network flow record.\n")
    f.write("- Graphs are formed by grouping 5 consecutive flows.\n")
    f.write("- Edges are computed via k-nearest neighbors (k=2) on standardized feature space, producing 10 directed edges.\n")
    f.write("- Sequences are formed by non-overlapping windows of 5 consecutive graphs (25 flows total).\n")

print(f"Saved: {report_md_path}")
print("Feature compatibility documentation complete!")
