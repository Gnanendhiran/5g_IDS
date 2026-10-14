# 5G IDS Frontend

React + Vite frontend for the existing FastAPI 5G IDS backend.

## Run

```powershell
cd D:\5G_Wireless_IDS\frontend
npm install
npm run dev
```

The frontend calls:

- `GET /api/health`
- `GET /api/ids/default`
- `POST /api/ids/predict`

Default API base:
`http://127.0.0.1:8000`

Optional `.env`:

```text
VITE_API_BASE=http://127.0.0.1:8000
```

The frontend accepts the backend's supported CSV input formats:
- MATLAB 25-field traffic CSV
- direct NIDD 91-feature CSV
- mixed benign/malicious rows, preserving backend result order

No frontend change is required when the backend schema adapter is updated, provided the `/api/ids/predict` endpoint remains the same.
