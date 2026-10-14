import unittest
import torch
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.engine import IDSEngine

class TestMultiAgentXAISystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = IDSEngine()

    def test_multi_agent_investigation_lifecycle(self):
        # Load one of the 5,000-flow simulation datasets
        sim_file = ROOT_DIR / "outputs" / "simulated_traffic" / "live_5g_sim_1_balanced_all_attacks.csv"
        self.assertTrue(sim_file.exists(), f"Scenario file {sim_file} does not exist.")

        import pandas as pd
        df = pd.read_csv(sim_file, nrows=50) # exactly 2 sequences of 25 rows
        result = self.engine.predict_dataframe(df)

        self.assertEqual(len(result["sequences"]), 2)
        self.assertIn("primary_investigation", result["summary"])

        # Test on-demand investigation for sequence 1 and sequence 2
        inv1 = self.engine.get_sequence_investigation(1)
        self.assertIn("executive_synthesis", inv1)
        self.assertIn("agent_reports", inv1)
        
        # Verify 3 core SOC specialist agents reported
        agents = inv1["agent_reports"]
        self.assertIn("attack_investigator", agents)
        self.assertIn("risk_analyst", agents)
        self.assertIn("response_advisor", agents)

        # 1. Verify Attack Investigator outputs
        inv_agent = agents["attack_investigator"]
        self.assertIn("attack_detected", inv_agent)
        self.assertIn("confidence", inv_agent)
        self.assertIn("affected_ue", inv_agent)
        self.assertIn("serving_gnb", inv_agent)
        self.assertIn("top_features", inv_agent)
        self.assertIn("peak_window", inv_agent)
        self.assertIn("is_faithful", inv_agent)

        # Verify normalized temporal windows sum to ~1.0 (100%)
        windows = inv_agent["temporal_windows"]
        self.assertEqual(len(windows), 5)
        total_window_score = sum(w["attribution_score"] for w in windows)
        self.assertAlmostEqual(total_window_score, 1.0, places=2)

        # 2. Verify Risk & Impact Analyst outputs
        risk_agent = agents["risk_analyst"]
        self.assertIn("priority_score", risk_agent)
        self.assertIn("severity", risk_agent)
        self.assertIn("persistence", risk_agent)
        self.assertIn("traffic_anomaly", risk_agent)
        self.assertIn("possible_service_impact", risk_agent)
        self.assertIn("urgency_rationale", risk_agent)

        # 3. Verify SOC Response Advisor outputs & tested playbook
        resp_agent = agents["response_advisor"]
        self.assertIn("what_was_detected", resp_agent)
        self.assertIn("what_to_check", resp_agent)
        self.assertIn("how_to_prevent", resp_agent)
        self.assertIn("recommended_mitigation", resp_agent)
        self.assertIn("possible_side_effects", resp_agent)
        self.assertIn("rollback_steps", resp_agent)
        self.assertIn("how_to_verify_recovery", resp_agent)
        self.assertIn("action_name", resp_agent)
        self.assertIn("action_id", resp_agent)

        # Verify executive synthesis
        synth = inv1["executive_synthesis"]
        self.assertIn("incident_title", synth)
        self.assertIn("recommended_directive", synth)

if __name__ == "__main__":
    unittest.main()
