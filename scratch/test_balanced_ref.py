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

e = IDSEngine()

# Replace nidd_matrix and nidd_calibration with the balanced reference from Encoded
balanced_ref = pd.read_csv('dataset/Encoded_balanced_reference_18k.csv', low_memory=False)

nidd_features = (
    balanced_ref[NIDD_FEATURES]
    .apply(pd.to_numeric, errors="coerce")
    .replace([np.inf, -np.inf], np.nan)
    .fillna(0.0)
)
e.nidd_matrix = nidd_features.to_numpy(np.float64)
ref8 = nidd_features[[CALIBRATION_TO_NIDD[c] for c in CALIBRATION_FIELDS]].to_numpy(np.float64)
e.calibration_scaler = StandardScaler().fit(e._log(ref8))
e.nidd_calibration = e.calibration_scaler.transform(e._log(ref8)).astype(np.float32)
e.reference_norm = np.sum(e.nidd_calibration * e.nidd_calibration, axis=1).astype(np.float32)

print("Engine re-initialized with 17,155 balanced reference rows from Encoded.csv!")

df = pd.read_csv('outputs/simulated_traffic/live_5g_sim_1_balanced_all_attacks.csv')
scaled, dist = e._calibrate(df)
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
print("\nCross-tab of Ground Truth vs Prediction with Balanced Ref:")
print(pd.crosstab(res_df['gt'], res_df['pred']))
print("\nPredictions breakdown:")
print(res_df['pred'].value_counts())
