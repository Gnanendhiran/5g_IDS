import urllib.request
import json
import time

def run_test():
    print("[1] Fetching scenarios...")
    res = urllib.request.urlopen("http://127.0.0.1:8000/api/ids/simulated-scenarios")
    data = json.loads(res.read())
    items = data.get("scenarios", [])
    print(f"Found {len(items)} scenarios.")
    assert len(items) >= 6, "Expected at least 6 scenarios"

    filename = items[0]["filename"]
    print(f"\n[2] Loading scenario '{filename}' (10,000 flows, 400 sequences)...")
    t0 = time.time()
    req = urllib.request.Request(f"http://127.0.0.1:8000/api/ids/load-scenario/{filename}", data=b"", method="POST")
    res2 = urllib.request.urlopen(req)
    result = json.loads(res2.read())
    elapsed = time.time() - t0
    seqs = result.get("sequences", [])
    print(f"Loaded {len(seqs)} sequences in {elapsed:.2f}s!")
    assert len(seqs) == 400, f"Expected 400 sequences, got {len(seqs)}"

    # Validate High to Low priority ordering
    scores = [s.get("priority_score", 0.0) for s in seqs]
    assert all(scores[i] >= scores[i+1] for i in range(len(scores)-1)), "Sequences are not sorted High-to-Low by priority score!"
    print(" Verified: Sequences are strictly sorted High-to-Low by priority score.")

    top_seq = seqs[0]
    print(f"\n[3] Top Priority Active Threat:")
    print(f"    - Rank #1 Sequence ID: {top_seq['sequence_id']}")
    print(f"    - Attack Type: {top_seq['predicted_label']}")
    print(f"    - Priority Score: {top_seq['priority_score']} ({top_seq.get('priority_level')})")
    print(f"    - Where Detected: {top_seq.get('where_detected')}")
    print(f"    - Packet Count: {top_seq.get('packet_count')}")
    print(f"    - Duration: {top_seq.get('duration')}s")
    print(f"    - Protocol: {top_seq.get('protocol')}")
    print(f"    - Serving gNodeB: {top_seq.get('gnb_id')}")
    print(f"    - How Mitigation Performs: {top_seq.get('how_mitigated')}")
    print(f"    - Action ID: {top_seq.get('action_id')}")

    # Test Mitigation Execution
    action_id = top_seq["action_id"]
    print(f"\n[4] Triggering Attack Prevention & Mitigation for action {action_id}...")
    exec_req = urllib.request.Request(
        "http://127.0.0.1:8000/api/ids/response/execute",
        data=json.dumps({"action_id": action_id, "operator": "SOC-Lead-Admin"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    exec_res = urllib.request.urlopen(exec_req)
    exec_data = json.loads(exec_res.read())
    print("    Result:", exec_data)
    assert exec_data.get("success") is True, f"Mitigation execution failed: {exec_data}"
    print(" Mitigation successfully executed!")

    # Test Multi-Agent XAI
    print(f"\n[5] Fetching Multi-Agent Explainable AI Investigation for sequence {top_seq['sequence_id']}...")
    xai_res = urllib.request.urlopen(f"http://127.0.0.1:8000/api/ids/xai/investigate/{top_seq['sequence_id']}")
    xai_data = json.loads(xai_res.read())
    agents = list(xai_data.get("agent_findings", {}).keys())
    print(f"    Agents active: {agents}")
    assert "attack_investigator" in agents, "Missing Attack Investigator agent"
    assert "risk_analyst" in agents, "Missing Risk & Impact Analyst agent"
    assert "response_advisor" in agents, "Missing SOC Response Advisor agent"
    print("    Verified: 3 core specialized AI agents active (Attack Investigator, Risk & Impact Analyst, SOC Response Advisor).")
    print(f"    Executive Summary snippet: {xai_data.get('soc_executive_summary', '')[:120]}...")

    print("\n ALL SOC PIPELINE INTEGRATION TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    run_test()
