# Threat Prioritization Engine

## 1. Multi-Factor Prioritization Model
The Threat Prioritization Engine (`security/threat_prioritizer.py`) separates raw model confidence from operational security impact.

$$\text{ThreatScore} = w_{\text{sev}} \cdot S_{\text{base}} + w_{\text{conf}} \cdot (C \times 100) + w_{\text{pers}} \cdot P + w_{\text{dev}} \cdot D$$

Where:
- $S_{\text{base}}$: Base attack severity catalog score (0–100)
- $C$: Model prediction confidence ($0.0 \le C \le 1.0$)
- $P$: Persistence contribution (recurring alerts on same UE / gNB, 0–100)
- $D$: Traffic rate deviation index (ratio above nominal baseline, 0–100)
- Default weights: $w_{\text{sev}} = 0.45, w_{\text{conf}} = 0.25, w_{\text{pers}} = 0.15, w_{\text{dev}} = 0.15$

---

## 2. Priority Levels & Operational Urgency

| Priority Level | Score Range | Operational Urgency | Typical Triggering Scenarios |
|---|---|---|---|
| **Critical** | $\ge 80.0$ | Immediate Containment Required | High-volume HTTPFlood / UDPFlood saturated on cell endpoints |
| **High** | $65.0 - 79.9$ | Urgent Mitigation Recommended | SYNFlood, SlowrateDoS with high confidence |
| **Medium** | $45.0 - 64.9$ | Investigation & Monitoring | Reconnaissance scans (SYNScan, TCPConnectScan, UDPScan) |
| **Low** | $20.0 - 44.9$ | Routine Logging | Low-rate ICMP probes, isolated events |
| **Needs Review** | Flagged | Analyst Verification Required | Out-of-distribution calibration or confidence $< 0.50$ |
| **Benign** | $0.0$ | None | Verified nominal traffic |
