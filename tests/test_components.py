import os
import sys
import unittest
import numpy as np
import torch

ROOT_DIR = r"d:\5G_Wireless_IDS"
sys.path.insert(0, ROOT_DIR)

from models.htstcl_gnn import HTSTCL_GNN
from models.htstcl_gnn_multiclass import HTSTCL_GNN_Multiclass
from explainable_ai.xai_engine import ExplainableAIEngine, NIDD_FEATURES
from security.threat_prioritizer import ThreatPrioritizer
from security.response_engine import DefensiveResponseEngine
from federated.federated_simulation import FederatedIDSSimulator
from torch_geometric.data import Data

class Test5GIDSComponents(unittest.TestCase):
    """
    Automated Test Suite for 5G Wireless Intrusion Detection System.
    Validates Dataset, Feature Schema, Model Architecture, XAI, Prioritizer, Response, and Federated IDS.
    """

    def setUp(self):
        self.device = torch.device("cpu")
        self.num_classes = 9
        self.input_dim = 91

    def test_01_feature_schema_integrity(self):
        """Verify feature schema contains exactly 91 features."""
        self.assertEqual(len(NIDD_FEATURES), 91)
        schema_file = os.path.join(ROOT_DIR, "reports", "feature_schema_91.csv")
        self.assertTrue(os.path.exists(schema_file))

    def test_02_dataset_multiclass_labels(self):
        """Verify multiclass label file and class distribution."""
        labels_file = os.path.join(ROOT_DIR, "outputs", "sequence_dataset", "multiclass_sequence_labels.npz")
        self.assertTrue(os.path.exists(labels_file))
        data = np.load(labels_file)
        
        classes = list(data["attack_classes"])
        self.assertEqual(len(classes), 9)
        self.assertEqual(classes[0], "Benign")
        self.assertIn("UDPFlood", classes)
        self.assertIn("HTTPFlood", classes)
        self.assertIn("SlowrateDoS", classes)

        # Check total sequences
        self.assertEqual(len(data["attack_indices"]), 48635)
        self.assertEqual(len(data["train_indices"]), 34044)
        self.assertEqual(len(data["val_indices"]), 7295)
        self.assertEqual(len(data["test_indices"]), 7296)

        # Verify no data leakage between splits
        train_set = set(data["train_indices"])
        val_set = set(data["val_indices"])
        test_set = set(data["test_indices"])
        self.assertEqual(len(train_set.intersection(val_set)), 0)
        self.assertEqual(len(train_set.intersection(test_set)), 0)
        self.assertEqual(len(val_set.intersection(test_set)), 0)

    def test_03_binary_baseline_checkpoint_preservation(self):
        """Verify original binary checkpoint is intact."""
        binary_ckpt = os.path.join(ROOT_DIR, "saved_models", "htstcl_gnn_best.pth")
        self.assertTrue(os.path.exists(binary_ckpt))
        ckpt = torch.load(binary_ckpt, map_location="cpu", weights_only=False)
        self.assertIn("model_state_dict", ckpt)

    def test_04_model_multiclass_forward_pass(self):
        """Test HTSTCL-GNN multiclass dual-head architecture forward pass."""
        model = HTSTCL_GNN_Multiclass(
            input_dim=91,
            hidden_dim=128,
            embedding_dim=128,
            num_classes=9
        )
        model.eval()

        # Create dummy batch of 2 sequences, each with 5 graphs, each with 5 nodes
        dummy_edge_index = torch.tensor([[0, 1, 2, 3, 4, 0, 1, 2, 3, 4],
                                        [1, 2, 3, 4, 0, 2, 3, 4, 0, 1]], dtype=torch.long)
        batch_seq = [
            [Data(x=torch.randn(5, 91), edge_index=dummy_edge_index) for _ in range(5)],
            [Data(x=torch.randn(5, 91), edge_index=dummy_edge_index) for _ in range(5)]
        ]

        out = model(batch_seq)
        self.assertEqual(out["multiclass_logits"].shape, (2, 9))
        self.assertEqual(out["binary_logits"].shape, (2, 2))
        self.assertEqual(out["embedding"].shape, (2, 128))
        self.assertIsNotNone(out["spatial_weight"])
        self.assertIsNotNone(out["temporal_weight"])

    def test_05_explainable_ai_attribution(self):
        """Test gradient-based feature and temporal window attribution."""
        model = HTSTCL_GNN_Multiclass(input_dim=91, hidden_dim=128, embedding_dim=128, num_classes=9)
        model.eval()

        xai = ExplainableAIEngine(NIDD_FEATURES)
        dummy_edge_index = torch.tensor([[0, 1, 2, 3, 4], [1, 2, 3, 4, 0]], dtype=torch.long)
        seq = [Data(x=torch.randn(5, 91), edge_index=dummy_edge_index) for _ in range(5)]

        exp = xai.explain_sequence(model, seq, target_class_idx=1, top_k=5)
        self.assertIn("top_features", exp)
        self.assertEqual(len(exp["top_features"]), 5)
        self.assertIn("temporal_window_attributions", exp)
        self.assertEqual(len(exp["temporal_window_attributions"]), 5)
        self.assertIn("faithfulness_verification", exp)

        # Test human-readable explanation
        summary = xai.generate_human_readable_explanation(5, "gNB-1", "UDPFlood", exp)
        self.assertIn("UDPFlood", summary)
        self.assertIn("gNB-1", summary)

    def test_06_threat_prioritization(self):
        """Test multi-factor threat prioritization scoring and levels."""
        prioritizer = ThreatPrioritizer()
        
        # Critical alert test (High severity HTTPFlood + sustained flood)
        crit = prioritizer.calculate_priority("HTTPFlood", confidence=0.99, is_malicious=True, recent_alert_count=5, traffic_rate_ratio=3.5)
        self.assertEqual(crit["priority_level"], "Critical")
        self.assertGreaterEqual(crit["priority_score"], 80.0)

        # High alert test (UDPFlood)
        high = prioritizer.calculate_priority("UDPFlood", confidence=0.95, is_malicious=True, recent_alert_count=2, traffic_rate_ratio=2.0)
        self.assertEqual(high["priority_level"], "High")

        # Benign test
        benign = prioritizer.calculate_priority("Benign", confidence=0.99, is_malicious=False)
        self.assertEqual(benign["priority_level"], "Benign")
        self.assertEqual(benign["priority_score"], 0.0)

        # Low confidence test
        uncertain = prioritizer.calculate_priority("SYNScan", confidence=0.35, is_malicious=True)
        self.assertEqual(uncertain["priority_level"], "Needs Review")

    def test_07_defensive_response_lifecycle(self):
        """Test defensive mitigation recommendation, approval, execution, and rollback."""
        engine = DefensiveResponseEngine()

        # Recommendation
        rec = engine.recommend_response("ALT-101", 10, "gNB-1", "UDPFlood", "Critical", 92.0)
        self.assertEqual(rec["action_type"], "ENFORCE_RATE_LIMIT")
        self.assertEqual(rec["status"], "Awaiting Approval")

        # Execution
        action_id = rec["action_id"]
        exec_res = engine.execute_containment_action(action_id, operator_id="Admin-1")
        self.assertTrue(exec_res["success"])
        self.assertEqual(exec_res["status"], "Executed")

        # Rollback
        rb_res = engine.rollback_action(action_id, operator_id="Admin-1")
        self.assertTrue(rb_res["success"])
        self.assertEqual(rb_res["status"], "Rolled Back")

    def test_08_federated_ids_simulation(self):
        """Test Federated IDS multi-cell partitioning and FedAvg aggregation."""
        fed = FederatedIDSSimulator(num_gnb_clients=3, num_classes=9)
        results = fed.run_federated_rounds(rounds=2)
        
        self.assertEqual(results["num_clients"], 3)
        self.assertEqual(len(results["rounds_summary"]), 2)
        self.assertGreater(results["bandwidth_per_round_mb"], 0.0)
        self.assertEqual(results["rounds_summary"][0]["aggregation_method"], "FedAvg")

if __name__ == "__main__":
    unittest.main()
