from pathlib import Path
import io
import traceback

import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from config import DEFAULT_LIVE_CSV, UPLOAD_DIR, MAX_UPLOAD_MB
from engine import IDSEngine

app = FastAPI(title="5G IDS API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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
    print("5G IDS engine loaded successfully.")
    print(f"Device: {engine.device}")
    print("Task: Binary Benign/Malicious intrusion detection")


def get_engine() -> IDSEngine:
    if engine is None:
        raise HTTPException(503, "IDS engine is not ready yet.")
    return engine


@app.get("/")
def root():
    return {
        "service": "5G Wireless Intrusion Detection System",
        "model": "HTSTCL-GNN",
        "task": "Binary classification: Benign / Malicious",
        "status": "online",
    }


@app.get("/api/health")
def health():
    e = get_engine()
    return {
        "status": "online",
        "model": "HTSTCL-GNN",
        "task": "binary_intrusion_detection",
        "classes": ["Benign", "Malicious"],
        "decision_threshold": 0.50,
        "device": str(e.device),
    }


@app.get("/api/ids/default")
def default_result():
    e = get_engine()
    if not DEFAULT_LIVE_CSV.exists():
        raise HTTPException(404, f"Default MATLAB CSV not found: {DEFAULT_LIVE_CSV}")
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
        raise HTTPException(413, f"CSV exceeds the {MAX_UPLOAD_MB} MB upload limit.")

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
        raise HTTPException(500, f"IDS inference failed: {exc}")
