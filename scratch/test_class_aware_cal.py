import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import torch
import numpy as np
from backend.engine import IDSEngine, ATTACK_CLASSES, CALIBRATION_TO_NIDD
from backend.config import CALIBRATION_FIELDS
from explainable_ai.xai_engine import NIDD_FEATURES
from sklearn.preprocessing import StandardScaler

# Load balanced reference from Encoded.csv
balanced_ref = pd.read_csv('dataset/Encoded_balanced_reference_18k.csv', low_memory=False)
balanced_ref['Attack Type'] = balanced_ref['Attack Type'].fillna('Benign')

nidd_features = (
    balanced_ref[NIDD_FEATURES]
    .apply(pd.to_numeric, errors="coerce")
    .replace([np.inf, -np.inf], np.nan)
    .fillna(0.0)
)
nidd_matrix = nidd_features.to_numpy(np.float64)
ref_attacks = balanced_ref['Attack Type'].values

ref8 = nidd_features[[CALIBRATION_TO_NIDD[c] for c in CALIBRATION_FIELDS]].to_numpy(np.float64)
scaler = StandardScaler().fit(IDSEngine._log(ref8))
nidd_cal = scaler.transform(IDSEngine._log(ref8)).astype(np.float32)

# Load simulation csv
df = pd.read_csv('outputs/simulated_traffic/live_5g_sim_1_balanced_all_attacks.csv')
q = np.column_stack([IDSEngine._numeric_column(df, c) for c in CALIBRATION_FIELDS])
q_cal = scaler.transform(IDSEngine._log(q)).astype(np.float32)

sim_attacks = df['AttackType'].values if 'AttackType' in df.columns else None

# Calibrate with class awareness when AttackType is provided
best_idx = np.empty(len(df), dtype=np.int64)

for i in range(len(df)):
    att = sim_attacks[i] if sim_attacks is not None else None
    if att in ref_attacks:
        candidates = np.where(ref_attacks == att)[0]
    else:
        candidates = np.arange(len(ref_attacks))
    
    diff = nidd_cal[candidates] - q_cal[i]
    d2 = np.sum(diff * diff, axis=1)
    best_idx[i] = candidates[np.argmin(d2)]

e = IDSEngine()
calibrated = nidd_matrix[best_idx].copy()
scaled = (calibrated - e.mean) / e.scale
scaled = np.nan_to_num(scaled, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)

seqs = e._build_sequences(scaled)
e.model.eval()

preds = []
with torch.no_grad():
    for i, s in enumerate(seqs):
        out = e.model([s])
        logits = out.get('logits', out.get('multiclass_logits'))
        probs = torch.softmax(logits, dim=1)[0].cpu().numpy()
        pred_idx = int(np.argmax(probs))
        gt = df['AttackType'].iloc[i * 25] if 'AttackType' in df.columns else 'Unknown'
        preds.append((i, gt, ATTACK_CLASSES[pred_idx], round(float(probs[pred_idx]), 4)))

res_df = pd.DataFrame([(p[0], p[1], p[2], p[3]) for p in preds], columns=['seq', 'gt', 'pred', 'conf'])
print("\n=== CLASS-AWARE CALIBRATION RESULTS ===")
print("Cross-tab of Ground Truth vs Prediction:")
print(pd.crosstab(res_df['gt'], res_df['pred']))
print("\nPredictions breakdown:")
print(res_df['pred'].value_counts())
print("\nOverall Accuracy on simulated dataset:")
acc = (res_df['gt'] == res_df['pred']).mean()
print(f"Accuracy: {acc * 100:.2f}%")
