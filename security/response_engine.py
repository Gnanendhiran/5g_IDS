import time
import uuid
from typing import Dict, Any, List, Optional

class DefensiveResponseEngine:
    """
    Defensive Response and Threat Containment Engine for 5G Wireless Networks.
    Provides:
      - Attack-specific mitigation recommendation catalogue.
      - Safe, simulated containment policy execution.
      - Full lifecycle state machine (Recommended -> Awaiting Approval -> Executed -> Rolled Back).
      - Audit trail tracking operator identity, timestamps, parameters, and rollback options.
    """

    POLICY_CATALOG = {
        "SlowrateDoS": {
            "recommended_action": "TERMINATE_HANGING_SESSIONS",
            "action_name": "Targeted Connection Cleanup & Rate Throttling",
            "description": "Reduce TCP idle keepalive timeout, clean lingering half-open connections, and rate-limit unestablished sessions.",
            "impact_risk": "Low",
            "requires_approval": False,
            "default_params": {"idle_timeout_sec": 5, "max_concurrent_sessions": 2},
            "what_was_detected": "Traffic behavior consistent with a SlowrateDoS pattern.",
            "evidence_to_inspect": "Connection duration, packet and byte rates, incomplete connections, and changes across the five temporal windows.",
            "prevention": "Apply appropriate connection limits, request timeouts, and rate controls at the relevant service or gateway.",
            "recommended_mitigation": "Consider targeted connection cleanup or rate limiting after confirming the affected endpoint and protocol. Avoid indiscriminately blocking an entire UE or gNB.",
            "possible_side_effects": "Legitimate long-lived low-rate connections may experience disconnection if idle timeout is set too aggressively.",
            "rollback_steps": "Restore default TCP keepalive timeouts (7200s), clear dynamic session caps, and flush temporary connection drop filters.",
            "how_to_verify_recovery": "Check whether incomplete connections and abnormal traffic rates decline, legitimate traffic recovers, and the alert stops recurring."
        },
        "UDPFlood": {
            "recommended_action": "ENFORCE_RATE_LIMIT",
            "action_name": "Protocol-Aware UDP Flow Shaping & Targeted Filtering",
            "description": "Throttle affected UE transmission bitrate to 50 kbps on serving gNB and apply protocol-aware UDP ingress filtering.",
            "impact_risk": "Moderate",
            "requires_approval": True,
            "default_params": {"max_bitrate_kbps": 50, "duration_seconds": 300},
            "what_was_detected": "An unusually high volume of UDP traffic consistent with a flooding attack.",
            "evidence_to_inspect": "UDP packet rate, destination concentration, traffic volume, and impact on the affected 5G service or radio bearer.",
            "prevention": "Use protocol-aware rate limits, traffic filtering, and upstream DDoS protection where available.",
            "recommended_mitigation": "Apply targeted filtering or rate limiting and escalate to upstream network protection if saturation is confirmed. Avoid indiscriminately blocking an entire UE or gNB.",
            "possible_side_effects": "Legitimate UDP traffic sharing the destination IP or port may experience brief packet loss or jitter during peak saturation.",
            "rollback_steps": "Remove dynamic UDP rate-limiting filter on the serving gNB/UPF and release upstream diversion routes.",
            "how_to_verify_recovery": "Monitor packet rate, service availability, legitimate packet loss, and whether the attack moves to another destination."
        },
        "SYNFlood": {
            "recommended_action": "ENABLE_SYN_COOKIES",
            "action_name": "Transport Layer SYN Cookie & Ingress Filtering",
            "description": "Activate cryptographic SYN cookies on serving gNB gateway to defend state memory tables against half-open exhaustion.",
            "impact_risk": "Low",
            "requires_approval": False,
            "default_params": {"syn_cookie_threshold": 100},
            "what_was_detected": "High-frequency TCP SYN packet burst without completing the three-way handshake, exhausting state memory.",
            "evidence_to_inspect": "TCP SYN rate, SYN/ACK ratio, half-open socket counts in connection tables, and temporal accumulation across windows.",
            "prevention": "Enable cryptographic SYN cookies at the 5G UPF/gateway, enforce per-UE embryonic connection limits, and configure adaptive TCP SYN backlog queue thresholds.",
            "recommended_mitigation": "Activate SYN cookie verification and per-flow ingress rate limiting on the serving gNB/UPF. Do not disconnect the entire UE if other sessions carry legitimate traffic.",
            "possible_side_effects": "Minor initial handshake latency overhead during cryptographic cookie hashing; slight CPU increase on gateway.",
            "rollback_steps": "Deactivate SYN cookie mode, restore standard TCP backlog buffers, and clear dynamic ingress throttling rules.",
            "how_to_verify_recovery": "Monitor TCP connection table usage, confirm half-open connections normalize, and verify legitimate TCP handshake completion times."
        },
        "ICMPFlood": {
            "recommended_action": "DROP_ICMP_BURSTS",
            "action_name": "ICMP Bandwidth Throttling & Ingress Drop",
            "description": "Enforce strict ICMP rate cap (10 pps) on serving radio unit without impacting legitimate TCP/UDP user data.",
            "impact_risk": "Low",
            "requires_approval": False,
            "default_params": {"max_icmp_pps": 10},
            "what_was_detected": "Unusually high-volume ICMP echo request (ping) stream targeting control or data planes.",
            "evidence_to_inspect": "ICMP packet-per-second (pps) rate, ICMP byte volume, temporal surge pattern, and radio link utilization.",
            "prevention": "Restrict ICMP ingress on 5G radio bearers, configure protocol-specific bandwidth caps, and drop unneeded ICMP echo reply traffic.",
            "recommended_mitigation": "Enforce strict ICMP rate cap (10 pps) or targeted flow drop on the affected IP/bearer without dropping legitimate user data.",
            "possible_side_effects": "Network diagnostic tools (ping/traceroute) from the target UE will time out or report packet loss.",
            "rollback_steps": "Remove ICMP rate cap rule and re-enable standard ICMP forwarding on the radio unit.",
            "how_to_verify_recovery": "Confirm ICMP pps drops below threshold, radio link utilization normalizes, and no alert recurrence occurs."
        },
        "HTTPFlood": {
            "recommended_action": "QUARANTINE_UE",
            "action_name": "Targeted Layer-7 Rate Limiting & Flow Quarantine",
            "description": "Detach abusive application flow to quarantine buffer for deep inspection while preserving baseline 5G signaling.",
            "impact_risk": "High",
            "requires_approval": True,
            "default_params": {"quarantine_vlan": 999, "duration_seconds": 600},
            "what_was_detected": "Volumetric HTTP/HTTPS request flood designed to deplete layer-7 web application server resources.",
            "evidence_to_inspect": "HTTP request rates, URI distribution, User-Agent patterns, response status code ratios (502/503/504), and byte volumes.",
            "prevention": "Deploy Web Application Firewall (WAF) rate controls, implement CAPTCHA/challenge-response mechanisms, and enforce per-UE HTTP request quotas.",
            "recommended_mitigation": "Apply application-layer rate limiting and temporarily isolate abusive layer-7 flows to an inspection quarantine buffer while keeping primary signaling intact.",
            "possible_side_effects": "Abusive web sessions receive HTTP 429; legitimate concurrent web requests from the same UE may experience delay.",
            "rollback_steps": "Revoke layer-7 rate limits, restore standard routing, and clear IP reputation blacklists.",
            "how_to_verify_recovery": "Verify HTTP request rates return to baseline, backend web server 5xx error rates subside, and page load times stabilize."
        },
        "TCPConnectScan": {
            "recommended_action": "BLOCK_SCANNING_FLOW",
            "action_name": "Targeted Transport Layer Port Knocking / Flow Drop",
            "description": "Block repeated SYN/ACK connection probes across multi-port ranges dynamically.",
            "impact_risk": "Low",
            "requires_approval": False,
            "default_params": {"block_duration_sec": 300},
            "what_was_detected": "Systematic sequential or randomized TCP full-connection probes mapping active service ports.",
            "evidence_to_inspect": "Rapid succession of completed/reset TCP handshakes across multiple destination ports, low payload byte counts, and temporal scanning spikes.",
            "prevention": "Implement strict ingress firewall rules, hide unused ports, deploy port-knocking or honeypot traps, and rate-limit connection initiation.",
            "recommended_mitigation": "Enforce dynamic flow drop on the scanning source IP/port range for 300 seconds. Avoid blocking the entire radio bearer.",
            "possible_side_effects": "Scanned probe packets dropped; genuine multi-port applications on the same IP may encounter temporary connection delays.",
            "rollback_steps": "Flush dynamic port-block firewall rule and restore standard port forwarding.",
            "how_to_verify_recovery": "Check that connection attempts across multiple destination ports cease, firewall drop counters decline, and normal flows resume."
        },
        "SYNScan": {
            "recommended_action": "BLOCK_SCANNING_FLOW",
            "action_name": "Targeted Transport Layer Flow Filter",
            "description": "Add dynamic firewall rule dropping scan probes from offending UE IP/Port.",
            "impact_risk": "Low",
            "requires_approval": False,
            "default_params": {"block_duration_sec": 300},
            "what_was_detected": "Stealth half-open TCP SYN scan probing network ports without completing handshakes to evade logging.",
            "evidence_to_inspect": "High ratio of SYN packets to RST/ACK responses across diverse destination ports with zero data bytes transferred.",
            "prevention": "Configure stateful firewall ingress filtering, deploy network intrusion detection rules for port scanning, and drop unsolicited SYN packets.",
            "recommended_mitigation": "Add targeted transport-layer packet filter dropping scan probes from the offending flow. Avoid cell-level teardowns.",
            "possible_side_effects": "Probing sockets dropped; potential brief delay for any new legitimate TCP handshake initiated during the scan window.",
            "rollback_steps": "Delete targeted transport packet filter rule and re-enable standard ingress evaluation.",
            "how_to_verify_recovery": "Verify scanning SYN packets drop to zero, host port exposure warnings clear, and state tables remain clean."
        },
        "UDPScan": {
            "recommended_action": "BLOCK_SCANNING_FLOW",
            "action_name": "ICMP Unreachable Suppression & Port Blacklist",
            "description": "Suppress ICMP port unreachable feedback and throttle probing UDP sockets.",
            "impact_risk": "Low",
            "requires_approval": False,
            "default_params": {"block_duration_sec": 300},
            "what_was_detected": "Rapid transmission of zero-byte UDP datagrams across multiple ports to detect open services via ICMP unreachable replies.",
            "evidence_to_inspect": "Spikes in UDP packets directed to diverse port numbers, corresponding ICMP Port Unreachable (Type 3 Code 3) response generation, and temporal burst behavior.",
            "prevention": "Rate-limit ICMP Type 3 generation at the gateway, filter unused UDP port access at boundary routers, and disable unused UDP daemons.",
            "recommended_mitigation": "Suppress ICMP unreachable feedback generation and apply dynamic socket throttling on the probing flow. Avoid wide-spectrum UDP blocking.",
            "possible_side_effects": "ICMP port unreachable error reporting is temporarily suppressed for the destination node.",
            "rollback_steps": "Re-enable ICMP unreachable feedback and remove socket throttle rule.",
            "how_to_verify_recovery": "Confirm UDP probe volume drops to zero, ICMP unreachable replies normalize, and legitimate UDP flows (DNS/VoIP) operate normally."
        },
        "Benign": {
            "recommended_action": "NONE",
            "action_name": "Normal Operation",
            "description": "No defensive action required. Traffic conforms to 5G baseline.",
            "impact_risk": "None",
            "requires_approval": False,
            "default_params": {},
            "what_was_detected": "Normal 5G operational traffic conforming to baseline statistical distributions.",
            "evidence_to_inspect": "Standard packet and byte rates, balanced bi-directional flow, expected protocol distributions, and steady temporal window energy.",
            "prevention": "Maintain existing 5G QoS profiles, routine firmware updates, and continuous baseline telemetry monitoring.",
            "recommended_mitigation": "None required. Traffic conforms to standard 5G operating parameters.",
            "possible_side_effects": "None.",
            "rollback_steps": "None.",
            "how_to_verify_recovery": "Continuous passive telemetry monitoring."
        }
    }

    def __init__(self):
        # Audit log of all initiated, executed, and rolled back actions
        self.action_history: List[Dict[str, Any]] = []
        # Active containment policies (simulated state)
        self.active_policies: Dict[str, Dict[str, Any]] = {}

    def recommend_response(
        self,
        alert_id: str,
        ue_id: Any,
        gnb_id: Any,
        predicted_attack_type: str,
        priority_level: str,
        priority_score: float
    ) -> Dict[str, Any]:
        """
        Generate a structured mitigation recommendation based on verified attack category and priority.
        """
        policy = self.POLICY_CATALOG.get(predicted_attack_type, self.POLICY_CATALOG["Benign"])
        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"

        if predicted_attack_type == "Benign":
            status = "Normal"
        elif policy["requires_approval"] or priority_level == "Critical":
            status = "Awaiting Approval"
        else:
            status = "Recommended"

        rec = {
            "action_id": action_id,
            "alert_id": alert_id,
            "target_ue": int(ue_id) if ue_id is not None else 1,
            "serving_gnb": str(gnb_id),
            "predicted_attack_type": predicted_attack_type,
            "priority_level": priority_level,
            "priority_score": float(priority_score),
            "action_type": policy["recommended_action"],
            "action_name": policy["action_name"],
            "description": policy["description"],
            "impact_risk": policy["impact_risk"],
            "requires_approval": policy["requires_approval"],
            "what_was_detected": policy.get("what_was_detected", f"Suspicious activity matching {predicted_attack_type} pattern."),
            "evidence_to_inspect": policy.get("evidence_to_inspect", "Packet rates, flow volume, and protocol distributions."),
            "prevention": policy.get("prevention", "Enforce gateway rate controls and firewall filtering."),
            "recommended_mitigation": policy.get("recommended_mitigation", policy["description"]),
            "possible_side_effects": policy.get("possible_side_effects", "Minor latency or transient packet drop."),
            "rollback_steps": policy.get("rollback_steps", "Flush dynamic filters and restore default routing."),
            "how_to_verify_recovery": policy.get("how_to_verify_recovery", "Verify packet rates normalize and alert ceases."),
            "status": status,
            "parameters": policy["default_params"].copy(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        self.action_history.append(rec)
        return rec

    def execute_containment_action(
        self,
        action_id: str,
        operator_id: str = "SOC-Analyst-Admin",
        approval_notes: str = "Authorized containment action"
    ) -> Dict[str, Any]:
        """
        Execute or approve an authorized containment action (simulated in 5G environment).
        """
        # RBAC Authorization validation
        if any(unauth in str(operator_id).lower() for unauth in ["unauthorized", "guest", "readonly"]):
            return {
                "success": False,
                "error": f"Authorization Denied: Operator '{operator_id}' lacks SOC containment mitigation privileges (Requires SOC-Lead, SOC-Analyst, or SOC-Admin role)."
            }

        action = next((a for a in self.action_history if a["action_id"] == action_id), None)
        if not action:
            return {"success": False, "error": f"Action ID '{action_id}' not found in registered containment playbooks."}

        action["status"] = "Executed"
        action["operator_id"] = operator_id
        action["approval_notes"] = approval_notes
        action["execution_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Simulated policy verification metrics
        ue_key = f"UE-{action['target_ue']}"
        self.active_policies[ue_key] = {
            "action_id": action_id,
            "policy": action["action_type"],
            "start_time": time.time(),
            "simulated_impact": {
                "packet_rate_reduction_pct": 87.5,
                "network_latency_ms": 4.2,
                "collateral_benign_impact": "None"
            }
        }

        action["execution_result"] = {
            "status": "Success",
            "containment_mode": "Simulated 5G Policy Enforcement",
            "simulated_metrics": self.active_policies[ue_key]["simulated_impact"]
        }

        return {
            "success": True,
            "action_id": action_id,
            "status": "Executed",
            "action": action
        }

    def rollback_action(
        self,
        action_id: str,
        operator_id: str = "SOC-Analyst-Admin",
        rollback_reason: str = "Investigation completed or benign false positive verification"
    ) -> Dict[str, Any]:
        """
        Safely roll back an executed defensive containment policy.
        """
        # RBAC Authorization validation
        if any(unauth in str(operator_id).lower() for unauth in ["unauthorized", "guest", "readonly"]):
            return {
                "success": False,
                "error": f"Authorization Denied: Operator '{operator_id}' lacks privileges to roll back containment policies."
            }

        action = next((a for a in self.action_history if a["action_id"] == action_id), None)
        if not action:
            return {"success": False, "error": f"Action ID '{action_id}' not found in registered containment playbooks."}

        action["status"] = "Rolled Back"
        action["rollback_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        action["rollback_operator"] = operator_id
        action["rollback_reason"] = rollback_reason

        ue_key = f"UE-{action['target_ue']}"
        if ue_key in self.active_policies:
            del self.active_policies[ue_key]

        return {
            "success": True,
            "action_id": action_id,
            "status": "Rolled Back",
            "message": f"Containment policy for UE {action['target_ue']} successfully rolled back."
        }

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Return the complete audit trail of defensive actions."""
        return self.action_history
