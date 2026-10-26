# Defensive Response & Containment Engine

## 1. Mitigation Policy Catalog

| Attack Category | Recommended Action | Description | Default Parameters | Approval Required |
|---|---|---|---|---|
| **UDPFlood** | `ENFORCE_RATE_LIMIT` | Throttles offending UE transmission rate on gNB radio scheduler | `max_bitrate_kbps: 50`, `duration: 300s` | **Yes** |
| **HTTPFlood** | `QUARANTINE_UE` | Isolates abusive application flow to quarantine inspection VLAN | `quarantine_vlan: 999`, `duration: 600s` | **Yes** |
| **SlowrateDoS** | `TERMINATE_HANGING_SESSIONS` | Reduces TCP keepalive timeout to 5s and flushes lingering states | `idle_timeout_sec: 5`, `max_sessions: 2` | No |
| **SYNFlood** | `ENABLE_SYN_COOKIES` | Activates cryptographic SYN cookies on serving gNB gateway | `syn_cookie_threshold: 100` | No |
| **ICMPFlood** | `DROP_ICMP_BURSTS` | Drops ICMP ingress bursts above 10 pps | `max_icmp_pps: 10` | No |
| **SYNScan** | `BLOCK_SCANNING_FLOW` | Adds dynamic packet filter rule dropping probes from source IP | `block_duration_sec: 300` | No |
| **TCPConnectScan** | `BLOCK_SCANNING_FLOW` | Blocks connection attempts across multi-port scanning ranges | `block_duration_sec: 300` | No |
| **UDPScan** | `BLOCK_SCANNING_FLOW` | Suppresses ICMP port unreachable feedback and blocks UDP probes | `block_duration_sec: 300` | No |
| **Benign** | `NONE` | Normal operation | None | No |

---

## 2. Response State Machine

```text
  [Detected] 
      │
      ▼
  [Recommended] ────── (Disruptive / Critical) ──────► [Awaiting Approval]
      │                                                         │
      │ (Non-disruptive)                                        │ (Operator Authorized)
      ▼                                                         ▼
  [Executed] ◄──────────────────────────────────────────────────┘
      │
      ▼ (Investigation Complete / False Positive)
  [Rolled Back]
```

All actions maintain an immutable audit trail (`action_history`) containing operator ID, timestamp, policy parameters, and execution outcomes.
