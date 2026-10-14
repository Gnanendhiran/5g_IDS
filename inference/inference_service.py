import os
import sys
import uuid
import time
from typing import Dict, Any, List, Union

import numpy as np
import pandas as pd
import scipy.io as sio
import torch

ROOT_DIR = r"d:\5G_Wireless_IDS"
sys.path.insert(0, ROOT_DIR)

from models.htstcl_gnn import HTSTCL_GNN
from models.htstcl_gnn_multiclass import HTSTCL_GNN_Multiclass
from explainable_ai.xai_engine import ExplainableAIEngine, NIDD_FEATURES
from security.threat_prioritizer import ThreatPrioritizer
from security.response_engine import DefensiveResponseEngine

class InferenceService:
    """
    Unified, Reusable Inference Service for 5G Wireless Intrusion Detection.
    Connects:
      - Model checkpoint loading (Binary Baseline & Multiclass Attack Classifier)
      - Feature normalizer (python_scaler_91.mat)
      - Spatio-temporal graph sequence inference
      - Explainable AI (XAI) feature & temporal attributions
      - Threat prioritization scoring
      - Defensive response recommendations
    """

    def __init__(
        self,
        checkpoint_path: str = None,
        scaler_path: str = None,
        device: str = None
    ):
        self.device = torch.device(device if device else ("cuda" if torch.cuda.is_available() else "cpu"))
        
        # Paths
        self.checkpoint_path = checkpoint_path or os.path.join(ROOT_DIR, "saved_models", "htstcl_gnn_multiclass_best.pth")
        if not os.path.exists(self.checkpoint_path):
            # Fallback to binary baseline if multiclass not yet generated
            self.checkpoint_path = os.path.join(ROOT_DIR, "saved_models", "htstcl_gnn_best.pth")

        self.scaler_path = scaler_path or os.path.join(ROOT_DIR, "outputs", "sequence_dataset", "python_scaler_91.mat")

        # Load Scaler
        if os.path.exists(self.scaler_path):
            mat = sio.loadmat(self.scaler_path)
            self.mean = np.asarray(mat["mean_"]).reshape(-1).astype(np.float32)
            self.scale = np.asarray(mat["scale_"]).reshape(-1).astype(np.float32)
            self.scale = np.where(self.scale == 0, 1.0, self.scale)
        else:
            self.mean = np.zeros(91, dtype=np.float32)
            self.scale = np.ones(91, dtype=np.float32)

        # Attack Classes
        self.attack_classes = [
            "Benign", "UDPFlood", "HTTPFlood", "SlowrateDoS",
            "TCPConnectScan", "SYNScan", "UDPScan", "SYNFlood", "ICMPFlood"
        ]

        # Supporting engines
        self.xai_engine = ExplainableAIEngine(NIDD_FEATURES)
        self.prioritizer = ThreatPrioritizer()
        self.response_engine = DefensiveResponseEngine()

        # Load Model
        self.model, self.is_multiclass = self.load_detection_model(self.checkpoint_path)

    def load_detection_model(self, checkpoint_path: str):
        """
        Dynamically load either Binary HTSTCL-GNN or Multiclass HTSTCL-GNN.
        """
        if not os.path.exists(checkpoint_path):
            raise FileNotFoundError(f"Checkpoint not found at: {checkpoint_path}")

        ckpt = torch.load(checkpoint_path, map_location=self.device, weights_only=False)
        state_dict = ckpt["model_state_dict"] if "model_state_dict" in ckpt else ckpt

        # Check if multiclass or binary
        if "multiclass_classifier.3.weight" in state_dict or "classifier.3.weight" in state_dict and state_dict["classifier.3.weight"].shape[0] > 2:
            is_multiclass = True
            num_classes = state_dict.get("multiclass_classifier.3.weight", state_dict.get("classifier.3.weight")).shape[0]
            model = HTSTCL_GNN_Multiclass(
                input_dim=91,
                hidden_dim=128,
                embedding_dim=128,
                num_classes=num_classes
            )
        else:
            is_multiclass = False
            model = HTSTCL_GNN(
                input_dim=91,
                hidden_dim=128,
                embedding_dim=128,
                num_classes=2
            )

        model.load_state_dict(state_dict)
        model.to(self.device)
        model.eval()
        return model, is_multiclass

    def predict_graph_sequence(
        self,
        sequence: List[Any],
        ue_id: Any = "UE-Unknown",
        gnb_id: Any = "gNB-1",
        traffic_rate_ratio: float = 1.0,
        recent_alert_count: int = 1
    ) -> Dict[str, Any]:
        """
        Run end-to-end inference, explanation, prioritization, and response generation on a single sequence.
        """
        event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"
        alert_id = f"ALT-{uuid.uuid4().hex[:6].upper()}"
        inference_time = time.strftime("%Y-%m-%d %H:%M:%S")

        self.model.eval()
        with torch.no_grad():
            out = self.model([sequence])
            logits = out.get("logits", out.get("multiclass_logits"))
            probs = torch.softmax(logits, dim=1)[0].cpu().numpy()

        pred_idx = int(np.argmax(probs))
        confidence = float(probs[pred_idx])

        if self.is_multiclass:
            predicted_attack_type = self.attack_classes[pred_idx] if pred_idx < len(self.attack_classes) else f"Attack_{pred_idx}"
            is_malicious = (pred_idx > 0)
        else:
            is_malicious = (pred_idx == 1)
            predicted_attack_type = "Malicious" if is_malicious else "Benign"

        # 1. Explainable AI Attribution
        try:
            explanation = self.xai_engine.explain_sequence(
                self.model,
                sequence,
                target_class_idx=pred_idx,
                top_k=5
            )
            human_explanation = self.xai_engine.generate_human_readable_explanation(
                ue_id=ue_id,
                gnb_id=gnb_id,
                attack_type=predicted_attack_type,
                explanation=explanation
            )
        except Exception as e:
            explanation = {"error": str(e), "top_features": []}
            human_explanation = f"Prediction: {predicted_attack_type} ({confidence*100:.1f}% confidence)."

        # 2. Threat Prioritization
        priority_info = self.prioritizer.calculate_priority(
            predicted_attack_type=predicted_attack_type,
            confidence=confidence,
            is_malicious=is_malicious,
            recent_alert_count=recent_alert_count,
            traffic_rate_ratio=traffic_rate_ratio
        )

        # 3. Defensive Response Recommendation
        if is_malicious:
            response_rec = self.response_engine.recommend_response(
                alert_id=alert_id,
                ue_id=ue_id,
                gnb_id=gnb_id,
                predicted_attack_type=predicted_attack_type,
                priority_level=priority_info["priority_level"],
                priority_score=priority_info["priority_score"]
            )
        else:
            response_rec = {
                "action_id": "NONE",
                "alert_id": alert_id,
                "status": "Normal",
                "action_name": "Normal Operation",
                "description": "Traffic verified as benign; no mitigation needed."
            }

        return {
            "event_id": event_id,
            "alert_id": alert_id,
            "timestamp": inference_time,
            "ue_id": ue_id,
            "gnb_id": gnb_id,
            "is_malicious": is_malicious,
            "predicted_attack_type": predicted_attack_type,
            "predicted_class_index": pred_idx,
            "confidence": round(confidence, 4),
            "class_probabilities": {
                self.attack_classes[i] if i < len(self.attack_classes) else f"Class_{i}": round(float(probs[i]), 4)
                for i in range(len(probs))
            },
            "model_architecture": "HTSTCL-GNN-Multiclass" if self.is_multiclass else "HTSTCL-GNN-Binary",
            "model_checkpoint": os.path.basename(self.checkpoint_path),
            "threat_prioritization": priority_info,
            "recommended_response": response_rec,
            "xai_explanation": explanation,
            "human_readable_summary": human_explanation
        }

    def get_model_metadata(self) -> Dict[str, Any]:
        """Return model metadata and configuration."""
        return {
            "model_type": "HTSTCL-GNN-Multiclass" if self.is_multiclass else "HTSTCL-GNN-Binary",
            "checkpoint_path": self.checkpoint_path,
            "device": str(self.device),
            "input_dimension": 91,
            "num_classes": len(self.attack_classes) if self.is_multiclass else 2,
            "classes": self.attack_classes if self.is_multiclass else ["Benign", "Malicious"],
            "scaler_loaded": os.path.exists(self.scaler_path)
        }
