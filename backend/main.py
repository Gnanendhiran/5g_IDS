from pathlib import Path
import io
import sys
import time
import traceback
from typing import Dict, Any, Optional

# Ensure both backend dir and project root are in sys.path
backend_dir = Path(__file__).resolve().parent
project_root = backend_dir.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware

from config import DEFAULT_LIVE_CSV, UPLOAD_DIR, MAX_UPLOAD_MB
from engine import IDSEngine, ATTACK_CLASSES

app = FastAPI(
    title="5G Wireless Intrusion Detection System API",
    description="Multiclass HTSTCL-GNN with Explainable AI, Threat Prioritization, and Defensive Response",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine: IDSEngine | None = None


@app.on_event("startup")
def startup():
    global engine
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    engine = IDSEngine()
    print("=" * 60)
    print("5G WIRELESS IDS API BACKEND INITIALIZED")
    print("=" * 60)
    print(f"Device: {engine.device}")
    print(f"Checkpoint: {engine.checkpoint_name}")
    print(f"Mode: {'Multiclass (9 Classes)' if engine.is_multiclass else 'Binary Baseline'}")


def get_engine() -> IDSEngine:
    if engine is None:
        raise HTTPException(503, "IDS engine is initializing...")
    return engine


@app.get("/")
def root():
    return {
        "service": "Explainable Hierarchical Temporal GNN for 5G Wireless Intrusion Detection",
        "model": "HTSTCL-GNN Multiclass",
        "classes": ATTACK_CLASSES if 'ATTACK_CLASSES' in globals() else 9,
        "status": "online",
        "version": "3.0.0"
    }


@app.get("/api/health")
def health():
    e = get_engine()
    return {
        "status": "online",
        "model": "HTSTCL-GNN",
        "task": "multiclass_attack_detection" if e.is_multiclass else "binary_intrusion_detection",
        "checkpoint": e.checkpoint_name,
        "classes": e.attack_classes,
        "num_classes": len(e.attack_classes) if e.is_multiclass else 2,
        "device": str(e.device),
    }


@app.get("/api/ids/default")
def default_result():
    e = get_engine()
    if not DEFAULT_LIVE_CSV.exists():
        raise HTTPException(404, f"Default simulation CSV not found: {DEFAULT_LIVE_CSV}")
    try:
        df = pd.read_csv(DEFAULT_LIVE_CSV)
        return e.predict_dataframe(df)
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(400, str(exc))


@app.post("/api/ids/predict")
async def predict(file: UploadFile = File(...)):
    e = get_engine()
    filename = file.filename or "uploaded.csv"
    if not filename.lower().endswith(".csv"):
        raise HTTPException(400, "Only CSV files are supported.")

    data = await file.read()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"CSV exceeds {MAX_UPLOAD_MB} MB limit.")

    try:
        df = pd.read_csv(io.BytesIO(data), low_memory=False)
        result = e.predict_dataframe(df)
        result["input_file"] = {
            "filename": filename,
            "size_bytes": len(data),
            "rows": len(df),
            "columns": len(df.columns),
        }
        return result
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(500, f"Inference failed: {exc}")


@app.get("/api/ids/alerts")
def get_alerts():
    e = get_engine()
    return {"alerts": e.get_alerts()}


@app.get("/api/ids/analytics")
def get_analytics():
    e = get_engine()
    return e.get_analytics()


@app.get("/api/ids/federated")
def get_federated():
    e = get_engine()
    return e.get_federated_status()


@app.post("/api/ids/response/execute")
def execute_response(payload: Dict[str, Any] = Body(...)):
    e = get_engine()
    action_id = payload.get("action_id")
    alert_id = payload.get("alert_id")
    operator_id = payload.get("operator_id", "SOC-Analyst-Admin")
    notes = payload.get("notes", "Authorized containment mitigation")
    
    # Fallback: resolve action_id from alert_id if not directly specified
    if not action_id and alert_id:
        for seq in e.cached_results:
            if seq.get("alert_id") == alert_id:
                action_id = seq.get("action_id")
                break

    if not action_id:
        raise HTTPException(400, "Valid action_id or alert_id is required to execute mitigation.")
        
    try:
        res = e.response_engine.execute_containment_action(action_id, operator_id, notes)
        if not res.get("success"):
            err_msg = res.get("error", "Action execution rejected.")
            status_code = 403 if "Authorization Denied" in err_msg else 400
            return JSONResponse(status_code=status_code, content=jsonable_encoder(res))

        exec_time = res.get("action", {}).get("execution_timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")
        for seq in e.cached_results:
            if seq.get("action_id") == action_id or seq.get("alert_id") == res.get("action", {}).get("alert_id") or (alert_id and seq.get("alert_id") == alert_id):
                seq["is_mitigated"] = True
                seq["response_status"] = "Executed"
                seq["when_prevented"] = exec_time
        return jsonable_encoder(res)
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(500, f"Containment execution failed: {exc}")


@app.post("/api/ids/response/rollback")
def rollback_response(payload: Dict[str, Any] = Body(...)):
    e = get_engine()
    action_id = payload.get("action_id")
    alert_id = payload.get("alert_id")
    operator_id = payload.get("operator_id", "SOC-Analyst-Admin")
    reason = payload.get("reason", "Operator manual rollback")

    # Fallback: resolve action_id from alert_id if not directly specified
    if not action_id and alert_id:
        for seq in e.cached_results:
            if seq.get("alert_id") == alert_id:
                action_id = seq.get("action_id")
                break

    if not action_id:
        raise HTTPException(400, "Valid action_id or alert_id is required to roll back mitigation.")

    try:
        res = e.response_engine.rollback_action(action_id, operator_id, reason)
        if not res.get("success"):
            err_msg = res.get("error", "Rollback rejected.")
            status_code = 403 if "Authorization Denied" in err_msg else 400
            return JSONResponse(status_code=status_code, content=jsonable_encoder(res))

        for seq in e.cached_results:
            if seq.get("action_id") == action_id or seq.get("alert_id") == res.get("action", {}).get("alert_id") or (alert_id and seq.get("alert_id") == alert_id):
                seq["is_mitigated"] = False
                seq["response_status"] = "Rolled Back"
                seq["when_prevented"] = None
        return jsonable_encoder(res)
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(500, f"Rollback failed: {exc}")


@app.get("/api/ids/response/history")
def get_response_history():
    e = get_engine()
    return {"history": e.response_engine.get_audit_trail()}


@app.get("/api/ids/xai/investigate/{sequence_id}")
def investigate_sequence(sequence_id: int):
    e = get_engine()
    try:
        return e.get_sequence_investigation(sequence_id)
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(400, str(exc))


@app.get("/api/ids/simulated-scenarios")
def list_simulated_scenarios():
    sim_dir = project_root / "outputs" / "simulated_traffic"
    scenarios = [
        {
            "id": 1,
            "filename": "live_5g_sim_1_balanced_all_attacks.csv",
            "title": "Scenario 1: Balanced Multi-Attack Benchmark",
            "dominant_theme": "All 8 Attack Classes Asymmetrically Distributed",
            "description": "10,000 flows (400 sequences) distributing 10% Benign + all 8 genuine 5G-NIDD attack families across 45 UEs and 3 gNodeBs.",
            "classes_included": ["UDPFlood", "HTTPFlood", "SlowrateDoS", "TCPConnectScan", "SYNScan", "UDPScan", "SYNFlood", "ICMPFlood", "Benign"],
            "breakdown": {"UDPFlood": 72, "HTTPFlood": 62, "SlowrateDoS": 54, "TCPConnectScan": 48, "SYNScan": 38, "UDPScan": 34, "SYNFlood": 30, "ICMPFlood": 22, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_1_balanced_all_attacks.csv").exists()
        },
        {
            "id": 2,
            "filename": "live_5g_sim_2_volumetric_ddos_surge.csv",
            "title": "Scenario 2: Volumetric DDoS Saturation Surge",
            "dominant_theme": "Heavy Volumetric Floods (UDP/SYN/ICMP) + Background Vectors",
            "description": "10,000 flows with primary saturation surge in UDPFlood (85 seqs), SYNFlood (55 seqs), ICMPFlood (45 seqs) alongside HTTPFlood (65 seqs) and background vectors with 10% Benign.",
            "classes_included": ["UDPFlood", "HTTPFlood", "SYNFlood", "ICMPFlood", "SlowrateDoS", "TCPConnectScan", "SYNScan", "UDPScan", "Benign"],
            "breakdown": {"UDPFlood": 85, "HTTPFlood": 65, "SYNFlood": 55, "ICMPFlood": 45, "SlowrateDoS": 35, "TCPConnectScan": 28, "SYNScan": 25, "UDPScan": 22, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_2_volumetric_ddos_surge.csv").exists()
        },
        {
            "id": 3,
            "filename": "live_5g_sim_3_stealth_recon_scan.csv",
            "title": "Scenario 3: Stealth Reconnaissance Port Sweeps",
            "dominant_theme": "Heavy Persistent Reconnaissance (TCP/SYN/UDP Scans) + Background Vectors",
            "description": "10,000 flows focused on persistent scanning in TCPConnectScan (82 seqs), SYNScan (68 seqs), UDPScan (58 seqs) alongside SlowrateDoS (46 seqs) and background vectors with 10% Benign.",
            "classes_included": ["TCPConnectScan", "SYNScan", "UDPScan", "SlowrateDoS", "HTTPFlood", "UDPFlood", "SYNFlood", "ICMPFlood", "Benign"],
            "breakdown": {"TCPConnectScan": 82, "SYNScan": 68, "UDPScan": 58, "SlowrateDoS": 46, "HTTPFlood": 36, "UDPFlood": 32, "SYNFlood": 24, "ICMPFlood": 14, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_3_stealth_recon_scan.csv").exists()
        },
        {
            "id": 4,
            "filename": "live_5g_sim_4_app_layer_service_starvation.csv",
            "title": "Scenario 4: Application Layer Service Starvation",
            "dominant_theme": "Heavy MEC & SBA Service Starvation (SlowrateDoS/HTTPFlood) + Background Vectors",
            "description": "10,000 flows targeting application threads and 5G SBA REST endpoints via SlowrateDoS (90 seqs) and HTTPFlood (76 seqs) alongside SYNFlood (52 seqs) and background vectors with 10% Benign.",
            "classes_included": ["SlowrateDoS", "HTTPFlood", "SYNFlood", "TCPConnectScan", "UDPFlood", "SYNScan", "ICMPFlood", "UDPScan", "Benign"],
            "breakdown": {"SlowrateDoS": 90, "HTTPFlood": 76, "SYNFlood": 52, "TCPConnectScan": 42, "UDPFlood": 34, "SYNScan": 28, "ICMPFlood": 20, "UDPScan": 18, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_4_app_layer_service_starvation.csv").exists()
        },
        {
            "id": 5,
            "filename": "live_5g_sim_5_iot_botnet_flood.csv",
            "title": "Scenario 5: Massive IoT Botnet Surge & Micro-Burst",
            "dominant_theme": "Heavy IoT Sensor Fleet Flooding (ICMP/UDPScan/UDPFlood) + Background Vectors",
            "description": "10,000 flows simulating dense smart meter bursts in ICMPFlood (78 seqs), UDPScan (66 seqs), UDPFlood (56 seqs), SYNScan (46 seqs) alongside background vectors with 10% Benign.",
            "classes_included": ["ICMPFlood", "UDPScan", "UDPFlood", "SYNScan", "HTTPFlood", "SlowrateDoS", "SYNFlood", "TCPConnectScan", "Benign"],
            "breakdown": {"ICMPFlood": 78, "UDPScan": 66, "UDPFlood": 56, "SYNScan": 46, "HTTPFlood": 38, "SlowrateDoS": 32, "SYNFlood": 26, "TCPConnectScan": 18, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_5_iot_botnet_flood.csv").exists()
        },
        {
            "id": 6,
            "filename": "live_5g_sim_6_coordinated_apt_campaign.csv",
            "title": "Scenario 6: Coordinated Advanced Persistent Threat (APT)",
            "dominant_theme": "Coordinated Multi-Stage APT Campaign across All 8 Vectors",
            "description": "10,000 flows of a multi-stage campaign progressing from reconnaissance to volumetric saturation across all 8 attack vectors with 10% Benign across 45 UEs and 3 gNodeBs.",
            "classes_included": ["HTTPFlood", "SlowrateDoS", "TCPConnectScan", "UDPFlood", "SYNFlood", "SYNScan", "UDPScan", "ICMPFlood", "Benign"],
            "breakdown": {"HTTPFlood": 74, "SlowrateDoS": 64, "TCPConnectScan": 54, "UDPFlood": 46, "SYNFlood": 42, "SYNScan": 36, "UDPScan": 26, "ICMPFlood": 18, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_6_coordinated_apt_campaign.csv").exists()
        },
        {
            "id": 7,
            "filename": "live_5g_sim_7_four_attack_perimeter.csv",
            "title": "Scenario 7: Four-Attack Cellular Perimeter Breach",
            "dominant_theme": "Strictly 4 Attack Types (90 Seqs Each) + 10% Normal",
            "description": "10,000 flows (400 sequences) containing strictly 4 attack types (UDPFlood, SYNFlood, TCPConnectScan, SYNScan: exactly 90 seqs / 2,250 flows each) + 10% Benign baseline across 45 UEs and 3 gNodeBs.",
            "classes_included": ["UDPFlood", "SYNFlood", "TCPConnectScan", "SYNScan", "Benign"],
            "breakdown": {"UDPFlood": 90, "SYNFlood": 90, "TCPConnectScan": 90, "SYNScan": 90, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_7_four_attack_perimeter.csv").exists()
        },
        {
            "id": 8,
            "filename": "live_5g_sim_8_tri_attack_surge.csv",
            "title": "Scenario 8: Tri-Attack Volumetric Inundation",
            "dominant_theme": "Strictly 3 Attack Types (120 Seqs Each) + 10% Normal",
            "description": "10,000 flows (400 sequences) containing strictly 3 attack types (UDPFlood, SYNFlood, ICMPFlood: exactly 120 seqs / 3,000 flows each) + 10% Benign baseline across 45 UEs and 3 gNodeBs.",
            "classes_included": ["UDPFlood", "SYNFlood", "ICMPFlood", "Benign"],
            "breakdown": {"UDPFlood": 120, "SYNFlood": 120, "ICMPFlood": 120, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_8_tri_attack_surge.csv").exists()
        },
        {
            "id": 9,
            "filename": "live_5g_sim_9_six_attack_advanced.csv",
            "title": "Scenario 9: Six-Attack Advanced Persistent Vector",
            "dominant_theme": "Strictly 6 Attack Types (60 Seqs Each) + 10% Normal",
            "description": "10,000 flows (400 sequences) containing strictly 6 attack types (SlowrateDoS, TCPConnectScan, SYNScan, UDPScan, SYNFlood, ICMPFlood: exactly 60 seqs / 1,500 flows each) + 10% Benign baseline across 45 UEs and 3 gNodeBs.",
            "classes_included": ["SlowrateDoS", "TCPConnectScan", "SYNScan", "UDPScan", "SYNFlood", "ICMPFlood", "Benign"],
            "breakdown": {"SlowrateDoS": 60, "TCPConnectScan": 60, "SYNScan": 60, "UDPScan": 60, "SYNFlood": 60, "ICMPFlood": 60, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_9_six_attack_advanced.csv").exists()
        },
        {
            "id": 10,
            "filename": "live_5g_sim_10_penta_attack_telemetry.csv",
            "title": "Scenario 10: Penta-Attack Telemetry Benchmark",
            "dominant_theme": "Strictly 5 Attack Types (72 Seqs Each) + 10% Normal",
            "description": "10,000 flows (400 sequences) containing strictly 5 attack types (HTTPFlood, SlowrateDoS, UDPFlood, SYNFlood, TCPConnectScan: exactly 72 seqs / 1,800 flows each) + 10% Benign baseline across 45 UEs and 3 gNodeBs.",
            "classes_included": ["HTTPFlood", "SlowrateDoS", "UDPFlood", "SYNFlood", "TCPConnectScan", "Benign"],
            "breakdown": {"HTTPFlood": 72, "SlowrateDoS": 72, "UDPFlood": 72, "SYNFlood": 72, "TCPConnectScan": 72, "Benign": 40},
            "records": 10000,
            "sequences": 400,
            "exists": (sim_dir / "live_5g_sim_10_penta_attack_telemetry.csv").exists()
        }
    ]
    return {"scenarios": scenarios}


@app.post("/api/ids/load-scenario/{filename}")
def load_scenario(filename: str):
    e = get_engine()
    sim_dir = project_root / "outputs" / "simulated_traffic"
    file_path = sim_dir / filename
    if not file_path.exists():
        raise HTTPException(404, f"Simulation file {filename} not found.")

    try:
        df = pd.read_csv(file_path, low_memory=False)
        result = e.predict_dataframe(df)
        result["input_file"] = {
            "filename": filename,
            "size_bytes": file_path.stat().st_size,
            "rows": len(df),
            "columns": len(df.columns),
            "is_simulated_preset": True
        }
        return result
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(500, f"Failed executing scenario {filename}: {exc}")


@app.get("/api/ids/download-scenario/{filename}")
def download_scenario(filename: str):
    from fastapi.responses import FileResponse
    sim_dir = project_root / "outputs" / "simulated_traffic"
    file_path = sim_dir / filename
    if not file_path.exists():
        raise HTTPException(404, f"File {filename} not found.")
    return FileResponse(file_path, media_type="text/csv", filename=filename)


@app.get("/api/ids/topology-diagram")
def get_topology_diagram():
    from fastapi.responses import FileResponse
    png_path = project_root / "outputs" / "5g_network_topology_3gnb_45ue.png"
    if not png_path.exists():
        raise HTTPException(404, "Topology diagram PNG not found.")
    return FileResponse(png_path, media_type="image/png")


@app.get("/api/ids/topology-data")
def get_topology_data():
    import json
    coords_path = project_root / "outputs" / "ue_coordinates.json"
    ues = []
    if coords_path.exists():
        try:
            ues = json.loads(coords_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    
    return {
        "dimensions": {"width_m": 1000, "height_m": 850},
        "cell_radius_m": 280,
        "base_stations": [
            {"id": "gNB-1", "sector": "Sector A", "pos": [250, 550], "color": "#38bdf8"},
            {"id": "gNB-2", "sector": "Sector B", "pos": [750, 550], "color": "#a855f7"},
            {"id": "gNB-3", "sector": "Sector C", "pos": [500, 200], "color": "#10b981"}
        ],
        "backhaul_links": [
            {"from": "gNB-1", "to": "gNB-2", "type": "5G-Xn-Backhaul"},
            {"from": "gNB-2", "to": "gNB-3", "type": "5G-Xn-Backhaul"},
            {"from": "gNB-3", "to": "gNB-1", "type": "5G-Xn-Backhaul"}
        ],
        "ues": ues
    }
