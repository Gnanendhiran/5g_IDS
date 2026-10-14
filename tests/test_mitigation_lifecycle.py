import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

def req(path, method="GET", body=None):
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            parsed = json.loads(content)
        except:
            parsed = {"error": content}
        return e.code, parsed

def test_mitigation_full_lifecycle():
    print(f"Connecting to live 5G IDS Backend at {BASE_URL}...")
    
    # Check health
    status, health = req("/api/health")
    assert status == 200, f"Health check failed: {health}"
    print(f" -> Backend Health: {health.get('status')}")

    # 1. Fetch default traffic sequences
    status, data = req("/api/ids/default")
    assert status == 200, f"Default traffic failed: {data}"
    sequences = data.get("sequences", [])
    assert len(sequences) > 0, "No sequences returned from default dataset"
    
    # Find an unmitigated malicious alert
    malicious = [s for s in sequences if s["prediction"] == "Malicious" and not s.get("is_mitigated")]
    assert len(malicious) > 0, "Expected at least one unmitigated malicious alert"
    target = malicious[0]
    action_id = target["action_id"]
    alert_id = target["alert_id"]
    print(f"\n[TEST 1] Testing Successful Mitigation on Alert: {alert_id}, Action: {action_id}")
    
    status, exec_res = req("/api/ids/response/execute", method="POST", body={
        "action_id": action_id,
        "alert_id": alert_id,
        "operator_id": "SOC-Lead-Admin",
        "notes": "Testing authorized containment execution"
    })
    print(f" -> Response Status: {status}, Payload: {exec_res}")
    assert status == 200, f"Expected 200, got {status}: {exec_res}"
    assert exec_res.get("success") is True
    assert exec_res.get("status") == "Executed"
    print(" -> SUCCESS: Containment mitigation successfully executed.")

    # Verify audit history reflects execution
    status, hist_res = req("/api/ids/response/history")
    assert status == 200
    history = hist_res.get("history", [])
    matching_action = next((a for a in history if a["action_id"] == action_id), None)
    assert matching_action is not None
    assert matching_action["status"] == "Executed"
    print(" -> SUCCESS: Action confirmed in SOC audit history trail.")

    # 2. Test Rollback
    print(f"\n[TEST 2] Testing Successful Rollback on Action: {action_id}")
    status, roll_res = req("/api/ids/response/rollback", method="POST", body={
        "action_id": action_id,
        "alert_id": alert_id,
        "operator_id": "SOC-Lead-Admin",
        "reason": "Operator verification complete"
    })
    print(f" -> Response Status: {status}, Payload: {roll_res}")
    assert status == 200
    assert roll_res.get("success") is True
    assert roll_res.get("status") == "Rolled Back"
    print(" -> SUCCESS: Policy rollback executed successfully.")

    # 3. Test Authorization Denial
    print("\n[TEST 3] Testing Authorization Denial with unauthorized guest operator")
    status, denied_res = req("/api/ids/response/execute", method="POST", body={
        "action_id": action_id,
        "operator_id": "Guest-Viewer",
        "notes": "Unauthorized attempt"
    })
    print(f" -> Response Status: {status}, Payload: {denied_res}")
    assert status in [400, 403], f"Expected 400 or 403 for unauthorized operator, got {status}"
    assert denied_res.get("success") is False
    assert "Authorization Denied" in (denied_res.get("error") or denied_res.get("detail", ""))
    print(" -> SUCCESS: Authorization properly rejected for unauthorized operator.")

    # 4. Test Missing Action ID & Alert ID (Input Validation)
    print("\n[TEST 4] Testing Input Validation with missing action_id and alert_id")
    status, missing_res = req("/api/ids/response/execute", method="POST", body={})
    print(f" -> Response Status: {status}, Payload: {missing_res}")
    assert status == 400
    print(" -> SUCCESS: Proper 400 rejection on missing identifiers.")

    # 5. Test Non-Existent Action ID
    print("\n[TEST 5] Testing Non-Existent Action ID error handling")
    status, notfound_res = req("/api/ids/response/execute", method="POST", body={
        "action_id": "ACT-INVALID-NONEXISTENT-9999",
        "operator_id": "SOC-Lead-Admin"
    })
    print(f" -> Response Status: {status}, Payload: {notfound_res}")
    assert status == 400
    assert notfound_res.get("success") is False
    print(" -> SUCCESS: Non-existent action cleanly rejected with error message.")

if __name__ == "__main__":
    test_mitigation_full_lifecycle()
    print("\n=======================================================")
    print("ALL 5 MITIGATION LIFECYCLE TESTS PASSED ON LIVE SERVER!")
    print("=======================================================")
