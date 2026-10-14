from pathlib import Path

# Windows paths for the trained 5G IDS deployment.
NIDD_PATH = Path(r"D:\5G_Wireless_IDS\dataset\Encoded.csv")
SCALER_PATH = Path(r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB\results\features\python_scaler_91.mat")
CHECKPOINT_PATH = Path(r"D:\5G_Wireless_IDS\htstcl_gnn_models\htstcl_gnn_best.pth")
DEFAULT_LIVE_CSV = Path(r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB\results\traffic\live_5g_traffic.csv")
OUTPUT_DIR = Path(r"C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB\results\final_ids")
UPLOAD_DIR = OUTPUT_DIR / "dashboard_uploads"

ROWS_PER_SEQUENCE = 25
NODES_PER_GRAPH = 5
GRAPHS_PER_SEQUENCE = 5
EDGES_PER_GRAPH = 10
NUM_FEATURES = 91
DECISION_THRESHOLD = 0.50

# A valid uploaded CSV may have any filename.
MAX_UPLOAD_MB = 100

# The 8 fields below are the actual live-to-NIDD calibration contract.
CALIBRATION_FIELDS = [
    "Duration", "PacketCount", "Bytes", "PacketRate",
    "MeanPacketSize", "MinPacketSize", "MaxPacketSize", "LossRate"
]

# These fields are optional for inference. When present, they are used only
# for ground-truth/evaluation display; they are never fed to the classifier.
OPTIONAL_GROUND_TRUTH_FIELDS = ["TrafficType", "AttackType"]

# Distance is measured in the standardized log-calibration space. This is a
# review signal, not a model prediction and not a hard classification rule.
CALIBRATION_REVIEW_DISTANCE = 10.0
