"""
5G Wireless Intrusion Detection System - Multi-Scenario Traffic Generator
Generates 10 distinct, production-grade 5G simulation CSV datasets:
  1. live_5g_sim_1_balanced_all_attacks.csv    (10,000 flows - All 8 attacks + 10% Benign)
  2. live_5g_sim_2_volumetric_ddos_surge.csv   (10,000 flows - Heavy UDP/SYN/ICMP Flood + 10% Benign)
  3. live_5g_sim_3_stealth_recon_scan.csv      (10,000 flows - Heavy Port Scanning + 10% Benign)
  4. live_5g_sim_4_app_layer_service_starvation.csv (10,000 flows - App Layer Starvation + 10% Benign)
  5. live_5g_sim_5_iot_botnet_flood.csv        (10,000 flows - IoT Sensor Fleet Flood + 10% Benign)
  6. live_5g_sim_6_coordinated_apt_campaign.csv(10,000 flows - Multi-Stage APT Campaign + 10% Benign)
  7. live_5g_sim_7_four_attack_perimeter.csv   (10,000 flows - Exactly 4 attacks + 10% Benign)
  8. live_5g_sim_8_tri_attack_surge.csv        (10,000 flows - Exactly 3 attacks + 10% Benign)
  9. live_5g_sim_9_six_attack_advanced.csv     (10,000 flows - Exactly 6 attacks + 10% Benign)
 10. live_5g_sim_10_penta_attack_telemetry.csv (10,000 flows - Exactly 5 attacks + 10% Benign)

Architecture & Topology Specifications:
  - Fleet: Exactly 45 User Equipments (UE-1 to UE-45)
  - Infrastructure: Exactly 3 gNodeBs (gNB-1, gNB-2, gNB-3)
  - Cell Sectors: Sector-Alpha (UE 1-15), Sector-Beta (UE 16-30), Sector-Gamma (UE 31-45)
  - Normal Baseline: Exactly 10.00% Benign traffic (1,000 flows / 40 sequences of 25)
  - Telemetry Schema: 15 standard fields calibrated to 5G-NIDD benchmark contract
"""

import os
import random
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
import numpy as np

def get_5g_nidd_profiles():
    return {
        "Benign": {
            "dur": (0.20, 2.50), "pkts": (4, 18), "bytes": (300, 15000),
            "rate": (10.0, 200.0), "mean_sz": (80.0, 250.0), "min_sz": 40.0, "max_sz": 1460.0,
            "loss": (0.0, 0.01), "proto": "TCP", "traffic": "Benign", "bytes_mode": "range"
        },
        "UDPFlood": {
            "dur": (0.50, 2.50), "pkts": (1, 3), "bytes": (42, 126),
            "rate": (0.10, 1.50), "mean_sz": (42.0, 42.0), "min_sz": 42.0, "max_sz": 42.0,
            "loss": (0.0, 0.0), "proto": "UDP", "traffic": "Malicious", "bytes_mode": "fixed_per_pkt"
        },
        "HTTPFlood": {
            "dur": (0.10, 3.50), "pkts": (3, 16), "bytes": (200, 5000),
            "rate": (500.0, 8000.0), "mean_sz": (66.0, 110.0), "min_sz": 54.0, "max_sz": 1460.0,
            "loss": (0.0, 0.05), "proto": "TCP", "traffic": "Malicious", "bytes_mode": "range"
        },
        "SlowrateDoS": {
            "dur": (2.00, 5.00), "pkts": (6, 12), "bytes": (350, 950),
            "rate": (200.0, 2000.0), "mean_sz": (70.0, 80.0), "min_sz": 40.0, "max_sz": 120.0,
            "loss": (0.0, 0.02), "proto": "TCP", "traffic": "Malicious", "bytes_mode": "range"
        },
        "TCPConnectScan": {
            "dur": (0.001, 0.020), "pkts": (1, 1), "bytes": (70, 78),
            "rate": (0.5, 5.0), "mean_sz": (70.0, 78.0), "min_sz": 70.0, "max_sz": 78.0,
            "loss": (0.0, 0.20), "proto": "TCP", "traffic": "Malicious", "bytes_mode": "range"
        },
        "SYNScan": {
            "dur": (0.0001, 0.0010), "pkts": (1, 1), "bytes": (54, 58),
            "rate": (0.5, 5.0), "mean_sz": (54.0, 58.0), "min_sz": 54.0, "max_sz": 58.0,
            "loss": (0.0, 0.0), "proto": "TCP", "traffic": "Malicious", "bytes_mode": "range"
        },
        "UDPScan": {
            "dur": (0.0001, 0.0010), "pkts": (1, 1), "bytes": (40, 46),
            "rate": (0.5, 5.0), "mean_sz": (40.0, 46.0), "min_sz": 40.0, "max_sz": 46.0,
            "loss": (0.0, 0.0), "proto": "UDP", "traffic": "Malicious", "bytes_mode": "range"
        },
        "SYNFlood": {
            "dur": (0.010, 0.080), "pkts": (2, 4), "bytes": (120, 240),
            "rate": (50.0, 200.0), "mean_sz": (54.0, 60.0), "min_sz": 54.0, "max_sz": 60.0,
            "loss": (0.01, 0.20), "proto": "TCP", "traffic": "Malicious", "bytes_mode": "range"
        },
        "ICMPFlood": {
            "dur": (0.001, 0.005), "pkts": (2, 2), "bytes": (80, 88),
            "rate": (300.0, 600.0), "mean_sz": (42.0, 42.0), "min_sz": 42.0, "max_sz": 42.0,
            "loss": (0.0, 0.0), "proto": "ICMP", "traffic": "Malicious", "bytes_mode": "fixed_per_pkt"
        }
    }

def build_interleaved_seqs(attack_pool, total_seqs=400):
    """Interleave exactly 10% Benign every 10th sequence (40 benign sequences = 1000 flows)."""
    seqs = []
    cursor = 0
    shuffled_attacks = list(attack_pool)
    random.shuffle(shuffled_attacks)
    for s in range(1, total_seqs + 1):
        if s % 10 == 0:
            seqs.append("Benign")
        else:
            seqs.append(shuffled_attacks[cursor])
            cursor += 1
    return seqs

def export_dataset(seq_attacks, profiles, rows_per_seq, filename, target_dirs):
    num_seq = len(seq_attacks)
    total_rows = num_seq * rows_per_seq

    timestamps = []
    ue_ids = []
    gnb_ids = []
    sectors = []
    protocols = []
    durations = []
    packet_counts = []
    bytes_col = []
    packet_rates = []
    mean_pkt_sizes = []
    min_pkt_sizes = []
    max_pkt_sizes = []
    loss_rates = []
    traffic_types = []
    attack_types = []

    base_time = datetime(2026, 10, 14, 10, 0, 0)

    for s_idx, att in enumerate(seq_attacks):
        prof = profiles[att]
        ue_id = (s_idx % 45) + 1
        gnb_id = f"gNB-{((ue_id - 1) % 3) + 1}"

        if ue_id <= 15:
            sector_name = "Sector-Alpha"
        elif ue_id <= 30:
            sector_name = "Sector-Beta"
        else:
            sector_name = "Sector-Gamma"

        seq_time = base_time + timedelta(seconds=s_idx * 1.5)

        for step in range(rows_per_seq):
            curr_time = seq_time + timedelta(milliseconds=step * 40)
            timestamps.append(curr_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
            ue_ids.append(ue_id)
            gnb_ids.append(gnb_id)
            sectors.append(sector_name)
            protocols.append(prof["proto"])

            dur = round(random.uniform(prof["dur"][0], prof["dur"][1]), 4)
            pkts = random.randint(prof["pkts"][0], prof["pkts"][1])
            durations.append(dur)
            packet_counts.append(pkts)

            if prof["bytes_mode"] == "fixed_per_pkt":
                b_val = pkts * int(round(prof["mean_sz"][0]))
            else:
                b_val = random.randint(prof["bytes"][0], prof["bytes"][1])
            bytes_col.append(b_val)

            packet_rates.append(round(random.uniform(prof["rate"][0], prof["rate"][1]), 2))
            mean_pkt_sizes.append(round(random.uniform(prof["mean_sz"][0], prof["mean_sz"][1]), 2))
            min_pkt_sizes.append(prof["min_sz"])
            max_pkt_sizes.append(prof["max_sz"])
            loss_rates.append(round(random.uniform(prof["loss"][0], prof["loss"][1]), 4))

            traffic_types.append(prof["traffic"])
            attack_types.append(att)

    df = pd.DataFrame({
        "Timestamp": timestamps,
        "UEID": ue_ids,
        "gNB_ID": gnb_ids,
        "Sector": sectors,
        "Protocol": protocols,
        "Duration": durations,
        "PacketCount": packet_counts,
        "Bytes": bytes_col,
        "PacketRate": packet_rates,
        "MeanPacketSize": mean_pkt_sizes,
        "MinPacketSize": min_pkt_sizes,
        "MaxPacketSize": max_pkt_sizes,
        "LossRate": loss_rates,
        "TrafficType": traffic_types,
        "AttackType": attack_types
    })

    for d in target_dirs:
        if d.exists():
            out_path = d / filename
            df.to_csv(out_path, index=False)
            print(f"  [OK] Exported {out_path} ({len(df)} rows, {num_seq} sequences)")

def generate_all_datasets():
    random.seed(42)
    np.random.seed(42)

    root = Path(__file__).resolve().parent
    dir_python = root / "outputs" / "simulated_traffic"
    dir_matlab = Path(r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB\results\traffic")
    target_dirs = [dir_python]
    if dir_matlab.exists():
        target_dirs.append(dir_matlab)

    dir_python.mkdir(parents=True, exist_ok=True)
    profiles = get_5g_nidd_profiles()

    total_seqs = 400
    num_attacks = 360 # 90% attacks, 40 benign = 10%

    print("=" * 70)
    print("5G IDS: GENERATING COMPLETE SUITE OF 10 PRODUCTION SIMULATION DATASETS")
    print("=" * 70)

    # Scenario 1: Balanced Multi-Attack Benchmark
    pool_1 = (
        ["UDPFlood"] * 72 + ["HTTPFlood"] * 62 + ["SlowrateDoS"] * 54 +
        ["TCPConnectScan"] * 48 + ["SYNScan"] * 38 + ["UDPScan"] * 34 +
        ["SYNFlood"] * 30 + ["ICMPFlood"] * 22
    )
    seqs_1 = build_interleaved_seqs(pool_1, total_seqs)
    export_dataset(seqs_1, profiles, 25, "live_5g_sim_1_balanced_all_attacks.csv", target_dirs)

    # Scenario 2: Volumetric DDoS Saturation Surge
    pool_2 = (
        ["UDPFlood"] * 85 + ["HTTPFlood"] * 65 + ["SYNFlood"] * 55 +
        ["ICMPFlood"] * 45 + ["SlowrateDoS"] * 35 + ["TCPConnectScan"] * 28 +
        ["SYNScan"] * 25 + ["UDPScan"] * 22
    )
    seqs_2 = build_interleaved_seqs(pool_2, total_seqs)
    export_dataset(seqs_2, profiles, 25, "live_5g_sim_2_volumetric_ddos_surge.csv", target_dirs)

    # Scenario 3: Stealth Reconnaissance Port Sweeps
    pool_3 = (
        ["TCPConnectScan"] * 82 + ["SYNScan"] * 68 + ["UDPScan"] * 58 +
        ["SlowrateDoS"] * 46 + ["HTTPFlood"] * 36 + ["UDPFlood"] * 32 +
        ["SYNFlood"] * 24 + ["ICMPFlood"] * 14
    )
    seqs_3 = build_interleaved_seqs(pool_3, total_seqs)
    export_dataset(seqs_3, profiles, 25, "live_5g_sim_3_stealth_recon_scan.csv", target_dirs)

    # Scenario 4: Application Layer Service Starvation
    pool_4 = (
        ["SlowrateDoS"] * 90 + ["HTTPFlood"] * 76 + ["SYNFlood"] * 52 +
        ["TCPConnectScan"] * 42 + ["UDPFlood"] * 34 + ["SYNScan"] * 28 +
        ["ICMPFlood"] * 20 + ["UDPScan"] * 18
    )
    seqs_4 = build_interleaved_seqs(pool_4, total_seqs)
    export_dataset(seqs_4, profiles, 25, "live_5g_sim_4_app_layer_service_starvation.csv", target_dirs)

    # Scenario 5: IoT Sensor Fleet & Botnet Flood
    pool_5 = (
        ["ICMPFlood"] * 78 + ["UDPScan"] * 66 + ["UDPFlood"] * 56 +
        ["SYNScan"] * 46 + ["HTTPFlood"] * 38 + ["SlowrateDoS"] * 32 +
        ["SYNFlood"] * 26 + ["TCPConnectScan"] * 18
    )
    seqs_5 = build_interleaved_seqs(pool_5, total_seqs)
    export_dataset(seqs_5, profiles, 25, "live_5g_sim_5_iot_botnet_flood.csv", target_dirs)

    # Scenario 6: Coordinated Multi-Stage APT Campaign
    pool_6 = (
        ["HTTPFlood"] * 74 + ["SlowrateDoS"] * 64 + ["TCPConnectScan"] * 54 +
        ["UDPFlood"] * 46 + ["SYNFlood"] * 42 + ["SYNScan"] * 36 +
        ["UDPScan"] * 26 + ["ICMPFlood"] * 18
    )
    seqs_6 = build_interleaved_seqs(pool_6, total_seqs)
    export_dataset(seqs_6, profiles, 25, "live_5g_sim_6_coordinated_apt_campaign.csv", target_dirs)

    # File 7 (1st new): Exactly 4 attacks (90 sequences each) + 10% Benign
    # Attacks: UDPFlood, SYNFlood, TCPConnectScan, SYNScan (No HTTPFlood -> UDPFlood is Top Threat!)
    pool_7 = (
        ["UDPFlood"] * 90 +
        ["SYNFlood"] * 90 +
        ["TCPConnectScan"] * 90 +
        ["SYNScan"] * 90
    )
    seqs_7 = build_interleaved_seqs(pool_7, total_seqs)
    export_dataset(seqs_7, profiles, 25, "live_5g_sim_7_four_attack_perimeter.csv", target_dirs)

    # File 8 (2nd new): Exactly 3 attacks (120 sequences each) + 10% Benign
    # Attacks: UDPFlood, SYNFlood, ICMPFlood (Volumetric floods -> UDPFlood is Top Threat!)
    pool_8 = (
        ["UDPFlood"] * 120 +
        ["SYNFlood"] * 120 +
        ["ICMPFlood"] * 120
    )
    seqs_8 = build_interleaved_seqs(pool_8, total_seqs)
    export_dataset(seqs_8, profiles, 25, "live_5g_sim_8_tri_attack_surge.csv", target_dirs)

    # File 9 (3rd new): Exactly 6 attacks (60 sequences each) + 10% Benign
    # Attacks: SlowrateDoS, TCPConnectScan, SYNScan, UDPScan, SYNFlood, ICMPFlood
    pool_9 = (
        ["SlowrateDoS"] * 60 +
        ["TCPConnectScan"] * 60 +
        ["SYNScan"] * 60 +
        ["UDPScan"] * 60 +
        ["SYNFlood"] * 60 +
        ["ICMPFlood"] * 60
    )
    seqs_9 = build_interleaved_seqs(pool_9, total_seqs)
    export_dataset(seqs_9, profiles, 25, "live_5g_sim_9_six_attack_advanced.csv", target_dirs)

    # File 10 (4th new): Exactly 5 attacks (72 sequences each) + 10% Benign
    # Attacks: HTTPFlood, SlowrateDoS, UDPFlood, SYNFlood, TCPConnectScan
    pool_10 = (
        ["HTTPFlood"] * 72 +
        ["SlowrateDoS"] * 72 +
        ["UDPFlood"] * 72 +
        ["SYNFlood"] * 72 +
        ["TCPConnectScan"] * 72
    )
    seqs_10 = build_interleaved_seqs(pool_10, total_seqs)
    export_dataset(seqs_10, profiles, 25, "live_5g_sim_10_penta_attack_telemetry.csv", target_dirs)

    print("\n[SUCCESS] All 10 simulation datasets generated and exported!")

if __name__ == "__main__":
    generate_all_datasets()
