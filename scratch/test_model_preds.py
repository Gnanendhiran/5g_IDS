import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import torch
import numpy as np
from backend.engine import IDSEngine, ATTACK_CLASSES

e = IDSEngine()
df = pd.read_csv('outputs/simulated_traffic/live_5g_sim_1_balanced_all_attacks.csv')

print("Loaded CSV, starting calibration...")
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
        preds.append((i, gt, ATTACK_CLASSES[pred_idx], round(float(probs[pred_idx]), 4), probs))

res_df = pd.DataFrame([(p[0], p[1], p[2], p[3]) for p in preds], columns=['seq', 'gt', 'pred', 'conf'])
print("\nCross-tab of Ground Truth vs Prediction:")
print(pd.crosstab(res_df['gt'], res_df['pred']))
print("\nMean confidence by prediction:")
print(res_df.groupby('pred')['conf'].mean())
