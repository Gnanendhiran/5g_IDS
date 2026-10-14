from typing import Dict, Any, List

class ThreatPrioritizer:
    """
    Evidence-based Threat Prioritization Engine for 5G Wireless Intrusion Detection.
    Separates attack probability from operational severity and impact.
    Calculates transparent Threat Priority Scores (0-100) with detailed component breakdowns.
    """

    # Baseline attack severity scores (0 - 100)
    ATTACK_SEVERITY_CATALOG = {
        "Benign": 0.0,
        "UDPFlood": 85.0,        # Volumetric gNB exhaustion
        "HTTPFlood": 90.0,       # Core network service starvation
        "SlowrateDoS": 82.0,     # Stealthy connection table exhaustion
        "SYNFlood": 85.0,        # Transport layer connection exhaustion
        "ICMPFlood": 75.0,       # Bandwidth degradation
        "SYNScan": 65.0,         # Stealthy reconnaissance
        "TCPConnectScan": 60.0,  # Network discovery & active scanning
        "UDPScan": 55.0,         # UDP endpoint mapping
    }

    # Default weights for prioritization components
    DEFAULT_WEIGHTS = {
        "base_severity": 0.45,
        "confidence": 0.25,
        "persistence": 0.15,
        "traffic_deviation": 0.15
    }

    def __init__(self, weights: Dict[str, float] = None):
        self.weights = weights or self.DEFAULT_WEIGHTS

    def calculate_priority(
        self,
        predicted_attack_type: str,
        confidence: float,
        is_malicious: bool,
        recent_alert_count: int = 1,
        traffic_rate_ratio: float = 1.0,
        is_calibrated: bool = True
    ) -> Dict[str, Any]:
        """
        Calculate threat priority and operational urgency for an alert.
        """
        if not is_malicious or predicted_attack_type == "Benign":
            return {
                "priority_level": "Benign",
                "priority_score": 0.0,
                "urgency": "None",
                "components": {
                    "base_severity": 0.0,
                    "confidence_contrib": 0.0,
                    "persistence_contrib": 0.0,
                    "traffic_deviation_contrib": 0.0
                },
                "rationale": "Traffic verified as benign; no threat escalation required."
            }

        # Check if out-of-distribution or uncertain
        if not is_calibrated or confidence < 0.50:
            base_sev = self.ATTACK_SEVERITY_CATALOG.get(predicted_attack_type, 65.0)
            graduated_score = round(32.0 + (confidence * 22.0) + (0.1 * base_sev), 1)
            score = float(min(49.9, max(30.0, graduated_score)))
            return {
                "priority_level": "Needs Review",
                "priority_score": score,
                "urgency": "Advisory / Review",
                "components": {
                    "base_severity": round(base_sev, 1),
                    "confidence_contrib": round(confidence * 100.0, 1),
                    "persistence_contrib": 0.0,
                    "traffic_deviation_contrib": 0.0
                },
                "rationale": f"Low model confidence ({confidence*100:.1f}%) requires analyst verification."
            }

        # 1. Base Severity
        base_sev = self.ATTACK_SEVERITY_CATALOG.get(predicted_attack_type, 65.0)

        # 2. Confidence contribution
        conf_contrib = confidence * 100.0

        # 3. Persistence contribution (0 to 100): scales with recurring alerts on the same UE/gNB
        persistence_contrib = min(100.0, (recent_alert_count - 1) * 20.0)

        # 4. Traffic rate deviation contribution (0 to 100)
        deviation_contrib = min(100.0, max(0.0, (traffic_rate_ratio - 1.0) * 25.0))

        # Weighted composite score
        composite_score = (
            self.weights["base_severity"] * base_sev +
            self.weights["confidence"] * conf_contrib +
            self.weights["persistence"] * persistence_contrib +
            self.weights["traffic_deviation"] * deviation_contrib
        )
        score = round(float(min(100.0, max(0.0, composite_score))), 1)

        # Priority Level thresholds
        if score >= 80.0:
            level = "Critical"
            urgency = "Immediate Containment Required"
        elif score >= 65.0:
            level = "High"
            urgency = "Urgent Mitigation Recommended"
        elif score >= 45.0:
            level = "Medium"
            urgency = "Investigation & Monitoring Required"
        else:
            level = "Low"
            urgency = "Routine Logging"

        rationale = (
            f"Alert categorized as {level} priority (Score: {score}/100). "
            f"Driven by {predicted_attack_type} severity ({base_sev:.0f}), {confidence*100:.1f}% confidence, "
            f"persistence factor ({recent_alert_count} recent alerts), and traffic intensity."
        )

        return {
            "priority_level": level,
            "priority_score": score,
            "urgency": urgency,
            "components": {
                "base_severity": round(base_sev, 1),
                "confidence_contrib": round(conf_contrib, 1),
                "persistence_contrib": round(persistence_contrib, 1),
                "traffic_deviation_contrib": round(deviation_contrib, 1)
            },
            "rationale": rationale
        }
