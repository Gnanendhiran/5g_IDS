# 5G Wireless Intrusion Detection System (HTSTCL-GNN)
# Bug Fix & Engineering Resolution Log

This document records the specific functional issues, edge cases, and discrepancies identified, investigated, fixed, and retested across the repository.

---

### Issue 1: Investigation Sequence 1-Indexing vs 0-Indexing Boundary Error
- **Severity:** Medium
- **Location:** `backend/main.py` (`/api/ids/xai/investigate/{sequence_id}`) and `backend/engine.py`
- **Symptom:** Querying sequence index `0` produced `HTTP 400: Sequence ID 0 is out of bounds (1 to 400)`.
- **Root Cause:** In the frontend, table rows displayed sequence indices starting from 1 to $N$, whereas certain API callers assumed standard Python 0-based indexing.
- **Fix Implemented:** Updated sequence boundary validation in `backend/engine.py` to support 1-based indexing uniformly and provide explicit error messaging when index is $< 1$ or $> \text{len}(\text{cached\_results})$.
- **Verification:** Tested `GET /api/ids/xai/investigate/1`, which returned `HTTP 200` with 30.5 KB of multi-agent investigation telemetry.

---

### Issue 2: Mitigation Action ID Resolution from Alert ID in API Endpoints
- **Severity:** High
- **Location:** `backend/main.py` (`/api/ids/response/execute` and `/api/ids/response/rollback`)
- **Symptom:** When operators clicked "Mitigate" or "Rollback" on the alert stream using only the alert reference (`alert_id`) without providing `action_id`, the endpoint previously rejected the call with `HTTP 400: Valid action_id or alert_id is required`.
- **Root Cause:** The handler strictly required `action_id` in early revisions and did not search `cached_results` for matching `alert_id`.
- **Fix Implemented:** Added automatic fallback lookup in `backend/main.py`:
  ```python
  if not action_id and alert_id:
      for seq in e.cached_results:
          if seq.get("alert_id") == alert_id:
              action_id = seq.get("action_id")
              break
  ```
- **Verification:** Verified executing and rolling back containment via both `action_id` and `alert_id`. Both returned `HTTP 200 (success: True)`.

---

### Issue 3: Ingestion Edge Cases on Uploaded CSVs (Row Length & Data Types)
- **Severity:** High
- **Location:** `backend/main.py` (`/api/ids/predict`)
- **Symptom:** Uploading a CSV file with an arbitrary row count (e.g., 23 rows or empty files) resulted in an unhandled exception or 500 error in graph windowing.
- **Root Cause:** Spatio-temporal graph construction requires batches of 25 rows (5 nodes $\times$ 5 temporal snapshots). When `len(df) % 25 != 0`, tensor reshaping failed.
- **Fix Implemented:** Added upfront validation in `predict_dataframe`:
  - Checked that the file is not empty.
  - Verified `len(df) % 25 == 0`, returning a clear error: `CSV must contain a multiple of 25 rows. Received {len(df)} rows.`
  - Handled non-CSV file uploads by returning HTTP 400 instead of a server crash.
- **Verification:** Tested with:
  1. Text file: returned `HTTP 400: Only CSV files are supported`.
  2. Empty file: returned `HTTP 400: No columns to parse from file`.
  3. 1-row file: returned `HTTP 400: CSV must contain a multiple of 25 rows. Received 1 rows`.
  4. 50-row file (2 sequences): returned `HTTP 200: Sequences: 2`.

---

### Issue 4: Zero-Variance Division in Feature Scaling
- **Severity:** Critical
- **Location:** `backend/engine.py`, `inference/inference_service.py`, `outputs/sequence_dataset/python_scaler_91.mat`
- **Symptom:** Features with zero variance across the training set had `scale = 0.0`, resulting in `inf` or `nan` inputs after `(x - mean) / scale`.
- **Root Cause:** Standard scalar estimators produce `0.0` for invariant columns unless minimum scale thresholding is enforced.
- **Fix Implemented:** Implemented a non-zero guard contract in inference loaders:
  ```python
  self.scale = np.where(self.scale == 0, 1.0, self.scale)
  ```
- **Verification:** Invariant test `test_01_feature_schema_integrity` confirmed finite normalized outputs across all 91 features.

---

### Issue 5: Dual-Head Multiclass Architecture Backward Compatibility
- **Severity:** Critical
- **Location:** `models/htstcl_gnn.py` and `models/htstcl_gnn_multiclass.py`
- **Symptom:** Upgrading from binary detection to 9-class attack classification could invalidate existing binary checkpoints.
- **Root Cause:** Hard replacing the binary classification head broke legacy evaluation scripts and checkpoints (`htstcl_gnn_best.pth`).
- **Fix Implemented:** Maintained strict modularity:
  1. Preserved `HTSTCL_GNN` with original binary head.
  2. Created `HTSTCL_GNN_Multiclass` with dual heads (`out_binary` for binary screening and `out_multiclass` for 9-class attack identification).
  3. Added auto-detection in `IDSEngine` to seamlessly load either checkpoint without code modification.
- **Verification:** Unit tests `test_03_binary_baseline_checkpoint_preservation` and `test_04_model_multiclass_forward_pass` both passed.
