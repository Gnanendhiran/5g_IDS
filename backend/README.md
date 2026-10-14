# 5G IDS Professional Frontend

React + Vite dashboard for the Explainable Hierarchical Temporal Graph Neural Network (HTSTCL-GNN) 5G intrusion detection system.

## Run

```powershell
cd D:\5G_Wireless_IDS\frontend
npm install
npm run dev
```

Default backend:
`http://127.0.0.1:8000`

Optional API override:

```powershell
$env:VITE_API_BASE="http://127.0.0.1:8000"
npm run dev
```

## Pages

- Dashboard
- Upload Traffic
- Detection result
- Confusion matrix
- Traffic distribution
- Spatial/temporal attention
- Attack analysis
- Sequence-by-sequence table
- CSV export

The frontend treats Attack Type as MATLAB simulator ground truth and does not present it as a model-predicted attack family.
