import os
import sys
import unittest
import pandas as pd
import numpy as np

ROOT_DIR = r"d:\5G_Wireless_IDS"
sys.path.insert(0, ROOT_DIR)

from backend.engine import IDSEngine
from inference.inference_service import InferenceService

class TestEndToEndPipeline(unittest.TestCase):
    """
    End-to-End Integration Test for 5G Wireless Intrusion Detection System.
    Validates the entire pipeline:
      Simulation Data -> Calibration -> Graph Builder -> HTSTCL-GNN -> XAI ->
      Threat Prioritizer -> Response Recommendation -> Response Execution -> Rollback.
    """

    @classmethod
    def setUpClass(cls):
        cls.engine = IDSEngine()
        cls.inference_service = InferenceService()

    def test_01_backend_engine_initialization(self):
        """Verify IDSEngine loads the multiclass checkpoint properly."""
        self.assertTrue(self.engine.is_multiclass)
        self.assertEqual(len(self.engine.attack_classes), 9)
        self.assertIn("UDPFlood", self.engine.attack_classes)

    def test_02_simulation_traffic_inference_pipeline(self):
        """Test complete inference on simulation records."""
        sim_csv = r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB\results\traffic\live_5g_traffic.csv"
        if not os.path.exists(sim_csv):
            sim_csv = os.path.join(ROOT_DIR, "outputs", "flow_records.csv")

        self.assertTrue(os.path.exists(sim_csv))
        df = pd.read_csv(sim_csv, nrows=50) # exactly 2 sequences of 25 rows
        result = self.engine.predict_dataframe(df)

        self.assertIn("summary", result)
        self.assertIn("sequences", result)
        self.assertEqual(len(result["sequences"]), 2)

        first_seq = result["sequences"][0]
        self.assertIn("alert_id", first_seq)
        self.assertIn("predicted_attack_type", first_seq)
        self.assertIn("priority_level", first_seq)
        self.assertIn("recommended_action", first_seq)

    def test_03_inference_service_xai_and_prioritization(self):
        """Test reusable InferenceService with graph sequence, XAI and threat prioritizer."""
        # Load one real sequence from dataset
        seq_path = os.path.join(ROOT_DIR, "outputs", "sequence_dataset", "graph_sequences.pt")
        import torch
        seqs = torch.load(seq_path, map_location="cpu", weights_only=False)
        sample_seq = seqs[0]["graphs"]

        res = self.inference_service.predict_graph_sequence(
            sample_seq,
            ue_id=10,
            gnb_id="gNB-1",
            traffic_rate_ratio=2.0
        )

        self.assertIn("predicted_attack_type", res)
        self.assertIn("confidence", res)
        self.assertIn("threat_prioritization", res)
        self.assertIn("xai_explanation", res)
        self.assertIn("recommended_response", res)

        # Check XAI top features
        top_feats = res["xai_explanation"]["top_features"]
        self.assertEqual(len(top_feats), 5)
        self.assertTrue(res["xai_explanation"]["faithfulness_verification"]["is_faithful"])

    def test_04_defensive_mitigation_lifecycle(self):
        """Test defensive mitigation authorization, containment execution, and rollback."""
        resp_engine = self.engine.response_engine
        rec = resp_engine.recommend_response("ALT-999", 5, "gNB-1", "UDPFlood", "Critical", 90.0)
        action_id = rec["action_id"]

        # Execute
        exec_res = resp_engine.execute_containment_action(action_id, operator_id="SOC-Lead")
        self.assertTrue(exec_res["success"])
        self.assertEqual(exec_res["action"]["status"], "Executed")

        # Rollback
        rb_res = resp_engine.rollback_action(action_id, operator_id="SOC-Lead")
        self.assertTrue(rb_res["success"])
        self.assertEqual(rb_res["status"], "Rolled Back")

if __name__ == "__main__":
    unittest.main()
