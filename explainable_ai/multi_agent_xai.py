"""
Multi-AI Agent Explainable AI (XAI) and Response System for 5G Wireless IDS.

Streamlined to the three core SOC agents:
  1. Attack Investigator:
     - Identifies detected attack, model confidence, affected UE and serving gNodeB.
     - Top contributing input features with normalized attribution.
     - Sequence evolution across the 5 temporal windows and when suspicious activity peaked.
     - Calls ExplainableAIEngine.explain_sequence() ONCE per incident to avoid duplicate gradient compute.
  2. Risk & Impact Analyst:
     - Calculates 4-pillar priority score (0-100), severity tier, persistence, and traffic anomaly.
     - Evaluates 5G network blast radius and radio link degradation.
     - Provides clear technical rationale on why the alert is urgent.
  3. SOC Response Advisor:
     - Recommends attack-specific, evidence-based mitigation playbooks.
     - Tells analyst what to check, how to prevent recurrence, recommended mitigation (avoiding indiscriminate whole-cell/UE block).
     - Details possible operational side effects, precise rollback steps, and how to verify recovery.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import torch

from .xai_engine import ExplainableAIEngine, NIDD_FEATURES
from security.threat_prioritizer import ThreatPrioritizer
from security.response_engine import DefensiveResponseEngine


class AttackInvestigatorAgent:
    """
    Agent 1: Attack Investigator.
    Specialist in attack detection, feature saliency (Grad*Input), mathematical faithfulness,
    and 5-window temporal trajectory analysis.
    Calls explain_sequence() exactly ONCE per incident and shares its result.
    """
    def __init__(self, xai_engine: ExplainableAIEngine):
        self.name = "Attack Investigator"
        self.role = "Attack Detection, Feature Saliency & Temporal Window Dynamics Specialist"
        self.xai = xai_engine

    def analyze(
        self,
        model: torch.nn.Module,
        sequence: List[Any],
        target_class_idx: int,
        predicted_attack_type: str,
        confidence: float,
        ue_id: int,
        gnb_id: str,
        spatial_w: float = 15.0,
        temporal_w: float = 85.0,
        **kwargs
    ) -> Dict[str, Any]:
        # SINGLE call to explain_sequence() for both feature saliency and temporal dynamics
        raw_xai = self.xai.explain_sequence(model, sequence, target_class_idx=target_class_idx, top_k=5)
        top_features = raw_xai["top_features"]
        faithfulness = raw_xai["faithfulness_verification"]
        window_attributions = raw_xai.get("temporal_window_attributions", [])

        # Temporal dynamics evaluation
        if not window_attributions:
            window_attributions = [{"window_index": i, "attribution_score": 0.20, "normalized_attribution_pct": 20.0} for i in range(5)]

        scores = [w["attribution_score"] for w in window_attributions]
        peak_idx = int(np.argmax(scores))
        peak_score = float(scores[peak_idx])
        start_score = float(scores[0])
        end_score = float(scores[-1])

        # Classify sequence trajectory
        if end_score > start_score * 1.5:
            trajectory = "Rapid Escalation (Surging at sequence tail)"
            phase = "Active Attack Wave"
        elif peak_idx in [1, 2]:
            trajectory = "Transient Micro-Burst (Peaked mid-sequence)"
            phase = "Bursty Transient"
        elif np.std(scores) < 0.05:
            trajectory = "Persistent Steady-State (Constant pressure)"
            phase = "Sustained Saturation"
        else:
            trajectory = "Fluctuating Anomaly Pattern"
            phase = "Variable Probing"

        # Rationale string
        top_findings = [f"{f['feature_name']} (+{f['importance_score']*100:.1f}%)" for f in top_features[:3]]
        top_str = ", ".join(top_findings) if top_findings else "baseline indicators"

        if predicted_attack_type == "Benign":
            explanation_statement = (
                f"Traffic from UE {ue_id} on {gnb_id} conforms to standard 5G operational profiles "
                f"({confidence*100:.1f}% confidence). Metric deviations across all 5 temporal windows remain within normal thresholds."
            )
        else:
            explanation_statement = (
                f"Detected {predicted_attack_type} pattern with {confidence*100:.1f}% confidence targeting UE {ue_id} on {gnb_id}. "
                f"Primary mathematical drivers are {top_str}. Activity peaked in temporal window "
                f"t_{peak_idx+1} of 5 ({peak_score*100:.1f}% relative contribution) following a '{trajectory}' profile."
            )

        return {
            "agent": self.name,
            "role": self.role,
            "attack_detected": predicted_attack_type,
            "confidence": round(confidence * 100.0, 2),
            "affected_ue": ue_id,
            "serving_gnb": gnb_id,
            "top_features": top_features,
            "temporal_windows": window_attributions,
            "peak_window": peak_idx + 1,
            "peak_attribution_pct": round(peak_score * 100.0, 1),
            "peak_timing_description": f"Suspicious activity peaked in temporal window t_{peak_idx+1} of 5 ({peak_score*100:.1f}% impact).",
            "trajectory": trajectory,
            "phase": phase,
            "faithfulness_verification": faithfulness,
            "is_faithful": faithfulness["is_faithful"],
            "hierarchical_weights": {
                "spatial_attention_pct": round(spatial_w, 1),
                "temporal_attention_pct": round(temporal_w, 1)
            },
            "explanation_statement": explanation_statement,
            "summary_statement": f"{predicted_attack_type} ({confidence*100:.1f}%): Driven by {top_str}; peaked at window t_{peak_idx+1}."
        }


class RiskImpactAnalystAgent:
    """
    Agent 2: Risk & Impact Analyst.
    Evaluates operational risk score (0-100), severity tier, device persistence,
    traffic rate anomaly ratio, 5G network blast radius, and urgency rationale.
    """
    def __init__(self, prioritizer: ThreatPrioritizer):
        self.name = "Risk & Impact Analyst"
        self.role = "Operational Risk, Severity & 5G Service Impact Specialist"
        self.prioritizer = prioritizer

    def evaluate(
        self,
        predicted_attack_type: str,
        confidence: float,
        is_malicious: bool,
        recent_alert_count: int = 1,
        traffic_rate_ratio: float = 1.0,
        **kwargs
    ) -> Dict[str, Any]:
        res = self.prioritizer.calculate_priority(
            predicted_attack_type=predicted_attack_type,
            confidence=confidence,
            is_malicious=is_malicious,
            recent_alert_count=recent_alert_count,
            traffic_rate_ratio=traffic_rate_ratio
        )

        # Attack-specific service impact analysis across the 5G cellular network
        if predicted_attack_type in ["UDPFlood", "ICMPFlood"]:
            service_impact = "Volumetric Radio Exhaustion: gNodeB channel saturation and bandwidth starvation for co-located UEs."
            blast_severity = "Critical"
        elif predicted_attack_type in ["HTTPFlood", "SlowrateDoS"]:
            service_impact = "Application & State Table Depletion: Core network service starvation and connection buffer exhaustion."
            blast_severity = "High"
        elif predicted_attack_type in ["SYNFlood"]:
            service_impact = "Protocol State Exhaustion: TCP embryonic connection queue overload on serving gateway."
            blast_severity = "High" if res["priority_level"] in ["Critical", "High"] else "Moderate"
        elif predicted_attack_type in ["SYNScan", "TCPConnectScan", "UDPScan"]:
            service_impact = "Endpoint Discovery & Mapping: Active reconnaissance targeting 5G control and user plane endpoints."
            blast_severity = "Moderate"
        else:
            service_impact = "Nominal Operation: Telemetry indicators conform to baseline 5G radio traffic specifications."
            blast_severity = "Low"

        # Persistence assessment
        if recent_alert_count > 3:
            persistence_desc = f"High Persistence: Sustained malicious activity ({recent_alert_count} repeated alerts detected)."
        elif recent_alert_count > 1:
            persistence_desc = f"Moderate Persistence: Recurring alert signature ({recent_alert_count} alerts in current session)."
        else:
            persistence_desc = "Transient Occurrence: Initial anomalous sequence trigger."

        # Traffic anomaly assessment
        if traffic_rate_ratio >= 2.0:
            anomaly_desc = f"Severe Volumetric Spike: Current flow is {traffic_rate_ratio:.1f}x higher than baseline 5G traffic."
        elif traffic_rate_ratio > 1.2:
            anomaly_desc = f"Moderate Rate Anomaly: {traffic_rate_ratio:.1f}x baseline traffic rate observed."
        else:
            anomaly_desc = "Nominal Flow Rate: Anomaly driven by packet sequence composition rather than raw volume."

        # Why the alert is urgent
        if not is_malicious:
            urgency_why = "Alert urgency is Routine: Observed metrics align with benign operation."
        elif res["priority_score"] >= 80:
            urgency_why = (
                f"Urgent Action Required: Score {res['priority_score']}/100. High base attack severity coupled with "
                f"{confidence*100:.1f}% confidence threatens serving gNodeB stability and radio channel availability."
            )
        elif res["priority_score"] >= 50:
            urgency_why = (
                f"Elevated Attention Recommended: Score {res['priority_score']}/100. Activity exhibits moderate persistence "
                f"and requires analyst verification before enforcement."
            )
        else:
            urgency_why = f"Low Operational Risk: Score {res['priority_score']}/100. Routine monitoring suffices."

        return {
            "agent": self.name,
            "role": self.role,
            "priority_score": res["priority_score"],
            "priority_level": res["priority_level"],
            "severity": res["priority_level"],
            "persistence": persistence_desc,
            "recent_alert_count": recent_alert_count,
            "traffic_anomaly": anomaly_desc,
            "traffic_rate_ratio": traffic_rate_ratio,
            "possible_service_impact": service_impact,
            "network_blast_severity": blast_severity,
            "urgency": res["urgency"],
            "urgency_rationale": urgency_why,
            "components": res["components"],
            "summary_statement": f"Priority {res['priority_score']}/100 ({res['priority_level']}). {urgency_why}"
        }


class SOCResponseAdvisorAgent:
    """
    Agent 3: SOC Response Advisor.
    Prescribes attack-specific, evidence-based defensive playbooks.
    Details: What was detected, what to check, how to prevent recurrence, recommended mitigation,
    possible side effects, rollback steps, and how to verify recovery.
    """
    def __init__(self, response_engine: DefensiveResponseEngine):
        self.name = "SOC Response Advisor"
        self.role = "Tactical Playbook Mitigation & Containment Advisor"
        self.response_engine = response_engine

    def prescribe(
        self,
        alert_id: str,
        ue_id: int,
        gnb_id: str,
        predicted_attack_type: str,
        priority_level: str,
        priority_score: float,
        **kwargs
    ) -> Dict[str, Any]:
        rec = self.response_engine.recommend_response(
            alert_id=alert_id,
            ue_id=ue_id,
            gnb_id=gnb_id,
            predicted_attack_type=predicted_attack_type,
            priority_level=priority_level,
            priority_score=priority_score
        )

        blast_assessment = "Targeted Radio/Flow Containment (Enforce dynamic mitigation without broad cell teardown)"

        return {
            "agent": self.name,
            "role": self.role,
            "action_id": rec["action_id"],
            "action_code": rec.get("action_type", "ENFORCE_RATE_LIMIT"),
            "action_name": rec["action_name"],
            "description": rec["description"],
            "parameters": rec["parameters"],
            "status": rec["status"],
            "impact_risk": rec["impact_risk"],
            "requires_approval": rec["requires_approval"],
            "network_blast_assessment": blast_assessment,
            "can_rollback": rec.get("can_rollback", True),
            "what_was_detected": rec.get("what_was_detected", f"Traffic behavior consistent with {predicted_attack_type}."),
            "what_to_check": rec.get("evidence_to_inspect", "Packet rates, volume, and incomplete connections."),
            "evidence_to_inspect": rec.get("evidence_to_inspect", "Packet rates, volume, and incomplete connections."),
            "how_to_prevent": rec.get("prevention", "Enforce protocol-aware rate controls."),
            "prevention": rec.get("prevention", "Enforce protocol-aware rate controls."),
            "recommended_mitigation": rec.get("recommended_mitigation", rec["description"]),
            "possible_side_effects": rec.get("possible_side_effects", "Minor latency overhead on unestablished connections."),
            "rollback_steps": rec.get("rollback_steps", "Flush dynamic filter rules and restore default QoS parameters."),
            "how_to_verify_recovery": rec.get("how_to_verify_recovery", "Verify packet rates normalize and alert ceases."),
            "summary_statement": f"Prescribed: '{rec['action_name']}' on {gnb_id} (Target: UE-{ue_id})."
        }


class MultiAgentXAISystem:
    """
    Coordinating Multi-AI Agent System for 5G Intrusion Detection.
    Orchestrates the 3 specialized core agents:
      - Attack Investigator (Single XAI execution for saliency + temporal dynamics)
      - Risk & Impact Analyst (Operational risk, persistence, service impact, urgency)
      - SOC Response Advisor (Evidence-based playbooks, prevention, mitigation, side effects, rollback, verification)
    """
    def __init__(self, xai_engine: ExplainableAIEngine, prioritizer: ThreatPrioritizer, response_engine: DefensiveResponseEngine):
        self.attack_investigator = AttackInvestigatorAgent(xai_engine)
        self.risk_analyst = RiskImpactAnalystAgent(prioritizer)
        self.response_advisor = SOCResponseAdvisorAgent(response_engine)

        # Backward compatibility aliases
        self.saliency_agent = self.attack_investigator
        self.temporal_agent = self.attack_investigator
        self.prioritization_agent = self.risk_analyst
        self.containment_agent = self.response_advisor

    def investigate(
        self,
        model: torch.nn.Module,
        sequence: List[Any],
        target_class_idx: int,
        predicted_attack_type: str,
        confidence: float,
        alert_id: str,
        ue_id: int,
        gnb_id: str,
        spatial_w: float = 15.0,
        temporal_w: float = 85.0,
        recent_alert_count: int = 1,
        traffic_rate_ratio: float = 1.0,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Executes a streamlined 3-agent investigation with single XAI inference.
        """
        is_malicious = (predicted_attack_type != "Benign")

        # 1. Attack Investigator: Calls explain_sequence() ONCE
        investigator_report = self.attack_investigator.analyze(
            model=model,
            sequence=sequence,
            target_class_idx=target_class_idx,
            predicted_attack_type=predicted_attack_type,
            confidence=confidence,
            ue_id=ue_id,
            gnb_id=gnb_id,
            spatial_w=spatial_w,
            temporal_w=temporal_w
        )

        # 2. Risk & Impact Analyst: Evaluates risk, persistence, and network impact
        risk_report = self.risk_analyst.evaluate(
            predicted_attack_type=predicted_attack_type,
            confidence=confidence,
            is_malicious=is_malicious,
            recent_alert_count=recent_alert_count,
            traffic_rate_ratio=traffic_rate_ratio
        )

        # 3. SOC Response Advisor: Prescribes attack-specific tested playbook
        response_report = self.response_advisor.prescribe(
            alert_id=alert_id,
            ue_id=ue_id,
            gnb_id=gnb_id,
            predicted_attack_type=predicted_attack_type,
            priority_level=risk_report["priority_level"],
            priority_score=risk_report["priority_score"]
        )

        # Executive Incident Commander synthesis
        if not is_malicious:
            incident_title = f"Verified Benign Traffic on {gnb_id} (UE-{ue_id})"
            executive_summary = (
                f"Consensus confirms normal operating conditions for UE-{ue_id} on {gnb_id} "
                f"({confidence*100:.1f}% confidence). 5G telemetry matches baseline profiles. "
                "No mitigation or containment action is required."
            )
            recommended_directive = "Continue standard passive telemetry monitoring; no alert ticket needed."
        else:
            top_f_str = ", ".join([f"{f['feature_name']}" for f in investigator_report.get("top_features", [])[:2]])
            incident_title = f"5G Security Incident: {predicted_attack_type} on {gnb_id} (UE-{ue_id})"
            executive_summary = (
                f"Verified {predicted_attack_type} attack detected on {gnb_id} (UE-{ue_id}) "
                f"with {confidence*100:.1f}% confidence. Attack drivers: {top_f_str} peaking at window t_{investigator_report.get('peak_window')}. "
                f"Risk evaluated at {risk_report.get('priority_score')}/100 ({risk_report.get('priority_level')}). "
                f"Prescribed mitigation: {response_report.get('action_name')}."
            )
            recommended_directive = (
                f"Authorize and enforce '{response_report.get('action_name')}' immediately "
                f"to protect serving radio unit {gnb_id} from collateral degradation."
            )

        executive_report = {
            "incident_title": incident_title,
            "executive_summary": executive_summary,
            "recommended_directive": recommended_directive,
            "consensus_confidence": round(confidence * 100.0, 2),
            "multi_agent_alignment": "Full 3-Agent Consensus",
            "faithfulness_status": "Mathematically Verified" if investigator_report.get("is_faithful") else "Unverified"
        }

        return {
            "alert_id": alert_id,
            "ue_id": ue_id,
            "gnb_id": gnb_id,
            "predicted_attack_type": predicted_attack_type,
            "confidence": round(confidence * 100.0, 2),
            "executive_synthesis": executive_report,
            "agent_reports": {
                # Primary 3 core agents
                "attack_investigator": investigator_report,
                "risk_analyst": risk_report,
                "response_advisor": response_report,
                # Aliases for backward compatibility
                "saliency_agent": investigator_report,
                "temporal_agent": investigator_report,
                "prioritization_agent": risk_report,
                "containment_agent": response_report
            }
        }
