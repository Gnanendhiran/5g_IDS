from pathlib import Path

# Paths for 5G IDS deployment
BASE_DIR = Path(r"D:\5G_Wireless_IDS")
NIDD_PATH = BASE_DIR / "dataset" / "Encoded.csv"

# Scaler path
LOCAL_SCALER = BASE_DIR / "outputs" / "sequence_dataset" / "python_scaler_91.mat"
MATLAB_SCALER = Path(r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB\results\features\python_scaler_91.mat")
SCALER_PATH = LOCAL_SCALER if LOCAL_SCALER.exists() else MATLAB_SCALER

# Checkpoints
MULTICLASS_CHECKPOINT_PATH = BASE_DIR / "saved_models" / "htstcl_gnn_multiclass_best.pth"
BINARY_CHECKPOINT_PATH = BASE_DIR / "saved_models" / "htstcl_gnn_best.pth"
CHECKPOINT_PATH = MULTICLASS_CHECKPOINT_PATH if MULTICLASS_CHECKPOINT_PATH.exists() else BINARY_CHECKPOINT_PATH

# Live traffic CSV
SIM_BALANCED_CSV = BASE_DIR / "outputs" / "simulated_traffic" / "live_5g_sim_1_balanced_all_attacks.csv"
MATLAB_LIVE_CSV = Path(r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB\results\traffic\live_5g_sim_1_balanced_all_attacks.csv")
DEFAULT_LIVE_CSV = SIM_BALANCED_CSV if SIM_BALANCED_CSV.exists() else (MATLAB_LIVE_CSV if MATLAB_LIVE_CSV.exists() else (BASE_DIR / "outputs" / "flow_records.csv"))

OUTPUT_DIR = BASE_DIR / "outputs"
UPLOAD_DIR = OUTPUT_DIR / "dashboard_uploads"

ROWS_PER_SEQUENCE = 25
NODES_PER_GRAPH = 5
GRAPHS_PER_SEQUENCE = 5
EDGES_PER_GRAPH = 10
NUM_FEATURES = 91
DECISION_THRESHOLD = 0.50

MAX_UPLOAD_MB = 100

CALIBRATION_FIELDS = [
    "Duration", "PacketCount", "Bytes", "PacketRate",
    "MeanPacketSize", "MinPacketSize", "MaxPacketSize", "LossRate"
]

OPTIONAL_GROUND_TRUTH_FIELDS = ["TrafficType", "AttackType"]

CALIBRATION_REVIEW_DISTANCE = 10.0
