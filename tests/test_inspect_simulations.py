import os
import sys
from pathlib import Path
import pandas as pd

# Setup path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.engine import IDSEngine

def test_all_simulations():
    traffic_dir = ROOT / "outputs" / "simulated_traffic"
    engine = IDSEngine()

    csv_names = [
        "live_5g_sim_1_balanced_all_attacks.csv",
        "live_5g_sim_2_volumetric_ddos_surge.csv",
        "live_5g_sim_3_stealth_recon_scan.csv",
        "live_5g_sim_4_app_layer_service_starvation.csv",
        "live_5g_sim_5_iot_botnet_flood.csv",
        "live_5g_sim_6_coordinated_apt_campaign.csv",
        "live_5g_sim_7_four_attack_perimeter.csv",
        "live_5g_sim_8_tri_attack_surge.csv",
        "live_5g_sim_9_six_attack_advanced.csv",
        "live_5g_sim_10_penta_attack_telemetry.csv"
    ]

    print(f"=== TESTING ALL {len(csv_names)} SIMULATION CSVs ===")
    
    for fname in csv_names:
        p = traffic_dir / fname
        if not p.exists():
            print(f"[MISSING] {fname}")
            continue
        
        df = pd.read_csv(p)
        res = engine.predict_dataframe(df)
        summary = res["summary"]
        seqs = res["sequences"]
        
        # Ground truth breakdown
        gt_counts = df.groupby(df.index // 25)["AttackType"].first().value_counts().to_dict() if "AttackType" in df.columns else {}
        
        # Predicted breakdown
        pred_counts = pd.Series([s["predicted_attack_type"] for s in seqs]).value_counts().to_dict()
        
        top_threat = seqs[0]
        
        # Check accuracy of attack types present
        correct_match = sum(1 for s in seqs if s["predicted_attack_type"] == s["ground_truth"])
        acc_pct = (correct_match / len(seqs)) * 100.0
        
        print("\n" + "=" * 70)
        print(f"FILE: {fname}")
        print(f"  Rows: {len(df)} | Sequences: {summary['total_sequences']}")
        print(f"  Benign Sequences: {summary['benign_sequences']} ({summary['benign_sequences']/summary['total_sequences']*100:.1f}%)")
        print(f"  Malicious Sequences: {summary['malicious_sequences']} ({summary['malicious_sequences']/summary['total_sequences']*100:.1f}%)")
        print(f"  Multi-class Alignment Accuracy: {acc_pct:.2f}% ({correct_match}/{len(seqs)})")
        print(f"  Ground Truth: {gt_counts}")
        print(f"  Predicted:    {pred_counts}")
        print(f"  Top Prioritized Threat: {top_threat['predicted_attack_type']} | Score: {top_threat['priority_score']}/100 | Level: {top_threat['priority_level']} | Seq #{top_threat['sequence_id']}")
        
        # Verify prioritization order
        scores = [s["priority_score"] for s in seqs]
        is_sorted = all(scores[i] >= scores[i+1] for i in range(len(scores)-1))
        print(f"  Prioritization Correctly Sorted (Descending): {is_sorted}")

if __name__ == "__main__":
    test_all_simulations()
