from __future__ import annotations

import time
from typing import Any

import numpy as np
import pandas as pd
import scipy.io as sio
import torch
from sklearn.preprocessing import StandardScaler

from config import *
from model import HTSTCLGNN, load_checkpoint

NIDD_FEATURES = [
    "Dur","RunTime","Mean","Sum","Min","Max","sTos","dTos","sTtl","dTtl",
    "sHops","dHops","TotPkts","SrcPkts","DstPkts","TotBytes","SrcBytes","DstBytes",
    "Offset","sMeanPktSz","dMeanPktSz","Load","SrcLoad","DstLoad","Loss","SrcLoss",
    "DstLoss","pLoss","SrcGap","DstGap","Rate","SrcRate","DstRate","SrcWin","DstWin",
    "sVid","dVid","SrcTCPBase","DstTCPBase","TcpRtt","SynAck","AckDat"," *        ",
    " *    V   "," *    f   "," e        "," e    f   "," e &      "," e *      "," e d      ",
    " e g      "," e i      "," e r      "," e s      "," eU       ","e        ","arp","icmp",
    "ipv6-icmp","llc","lldp","sctp","tcp","udp","ACC","CON","ECO","FIN","INT","NRS",
    "REQ","RSP","RST","TST","URP","Shutdown","Start","Status","39","4","52","54",
    "af11","af12","af41","cs0","cs4","cs6","cs7","ef","nan"
]

CALIBRATION_TO_NIDD = {
    "Duration": "Dur",
    "PacketCount": "TotPkts",
    "Bytes": "TotBytes",
    "PacketRate": "Rate",
    "MeanPacketSize": "sMeanPktSz",
    "MinPacketSize": "Min",
    "MaxPacketSize": "Max",
    "LossRate": "pLoss",
}


def _clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.columns = [str(c).strip() for c in out.columns]
    return out


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        x = float(value)
        return x if np.isfinite(x) else default
    except Exception:
        return default


class IDSEngine:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        if not NIDD_PATH.exists():
            raise RuntimeError(f"NIDD dataset not found: {NIDD_PATH}")
        if not SCALER_PATH.exists():
            raise RuntimeError(f"Python scaler not found: {SCALER_PATH}")
        if not CHECKPOINT_PATH.exists():
            raise RuntimeError(f"Model checkpoint not found: {CHECKPOINT_PATH}")

        self.nidd = pd.read_csv(NIDD_PATH, low_memory=False)
        unnamed = [c for c in self.nidd.columns if str(c).startswith("Unnamed")]
        if unnamed:
            self.nidd = self.nidd.drop(columns=unnamed)

        missing = [c for c in NIDD_FEATURES if c not in self.nidd.columns]
        if missing:
            raise RuntimeError(f"NIDD missing model features: {missing}")

        self.nidd_features = (
            self.nidd[NIDD_FEATURES]
            .apply(pd.to_numeric, errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
        )
        self.nidd_matrix = self.nidd_features.to_numpy(np.float64)

        mat = sio.loadmat(SCALER_PATH)
        self.mean = np.asarray(mat["mean_"]).reshape(-1).astype(np.float64)
        self.scale = np.asarray(mat["scale_"]).reshape(-1).astype(np.float64)
        self.scale = np.where(self.scale == 0, 1.0, self.scale)
        if len(self.mean) != NUM_FEATURES or len(self.scale) != NUM_FEATURES:
            raise RuntimeError("Scaler does not contain exactly 91 features.")

        ref8 = self.nidd_features[[CALIBRATION_TO_NIDD[c] for c in CALIBRATION_FIELDS]].to_numpy(np.float64)
        self.calibration_scaler = StandardScaler().fit(self._log(ref8))
        self.nidd_calibration = self.calibration_scaler.transform(self._log(ref8)).astype(np.float32)
        self.reference_norm = np.sum(self.nidd_calibration * self.nidd_calibration, axis=1).astype(np.float32)

        self.model = load_checkpoint(HTSTCLGNN(), CHECKPOINT_PATH, self.device).to(self.device).eval()

    @staticmethod
    def _log(x: np.ndarray) -> np.ndarray:
        return np.sign(x) * np.log1p(np.abs(x))

    @staticmethod
    def _numeric_column(df: pd.DataFrame, column: str) -> np.ndarray:
        return (
            pd.to_numeric(df[column], errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
            .to_numpy(np.float64)
        )

    def validate_input(self, live: pd.DataFrame) -> dict[str, Any]:
        live = _clean_columns(live)
        if live.empty:
            raise ValueError("CSV contains no data rows.")
        if len(live) % ROWS_PER_SEQUENCE != 0:
            raise ValueError(
                f"CSV must contain a multiple of {ROWS_PER_SEQUENCE} rows. "
                f"Received {len(live)} rows."
            )

        missing = [c for c in CALIBRATION_FIELDS if c not in live.columns]
        if missing:
            raise ValueError(
                "Missing model-input fields: " + ", ".join(missing) + ". "
                "These 8 numeric fields are required for inference."
            )

        invalid_counts = {}
        for col in CALIBRATION_FIELDS:
            numeric = pd.to_numeric(live[col], errors="coerce")
            invalid = int(numeric.isna().sum())
            if invalid:
                invalid_counts[col] = invalid
        # Non-numeric values are tolerated because the preprocessing converts
        # them to zero, but the response exposes how many were sanitized.

        optional_present = [c for c in OPTIONAL_GROUND_TRUTH_FIELDS if c in live.columns]
        return {
            "rows": int(len(live)),
            "sequences": int(len(live) // ROWS_PER_SEQUENCE),
            "filename_independent": True,
            "required_model_fields": CALIBRATION_FIELDS,
            "optional_ground_truth_fields_present": optional_present,
            "ground_truth_available": "TrafficType" in live.columns,
            "attack_type_available": "AttackType" in live.columns,
            "sanitized_numeric_values": invalid_counts,
        }

    def _calibrate(self, live: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        q = np.column_stack([self._numeric_column(live, c) for c in CALIBRATION_FIELDS])
        q = self.calibration_scaler.transform(self._log(q)).astype(np.float32)

        # Exact nearest-reference search without allocating a huge
        # query-by-1.2M distance matrix. The result is the same nearest-NIDD
        # row, but memory use stays bounded.
        n_query = len(q)
        best_idx = np.empty(n_query, dtype=np.int64)
        best_dist2 = np.full(n_query, np.inf, dtype=np.float32)
        query_chunk = 32
        reference_chunk = 8192

        for qs in range(0, n_query, query_chunk):
            qe = min(qs + query_chunk, n_query)
            qq = q[qs:qe]
            qq_norm = np.sum(qq * qq, axis=1, keepdims=True)

            local_best_idx = np.zeros(qe - qs, dtype=np.int64)
            local_best = np.full(qe - qs, np.inf, dtype=np.float32)

            for rs in range(0, len(self.nidd_calibration), reference_chunk):
                re = min(rs + reference_chunk, len(self.nidd_calibration))
                ref = self.nidd_calibration[rs:re]
                d2 = qq_norm + self.reference_norm[rs:re][None, :] - 2.0 * (qq @ ref.T)
                d2 = np.maximum(d2, 0.0)
                pos = np.argmin(d2, axis=1)
                values = d2[np.arange(qe - qs), pos]
                improved = values < local_best
                local_best[improved] = values[improved]
                local_best_idx[improved] = rs + pos[improved]

            best_idx[qs:qe] = local_best_idx
            best_dist2[qs:qe] = local_best

        calibrated = self.nidd_matrix[best_idx].copy()
        scaled = (calibrated - self.mean) / self.scale
        scaled = np.nan_to_num(scaled, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        distances = np.sqrt(np.maximum(best_dist2, 0.0)).astype(np.float32)
        return scaled, distances

    @staticmethod
    def _edges(x: np.ndarray) -> np.ndarray:
        d = x[:, None, :] - x[None, :, :]
        d = np.sqrt(np.sum(d * d, axis=2))
        edges = []
        for src in range(NODES_PER_GRAPH):
            candidates = [dst for dst in range(NODES_PER_GRAPH) if dst != src]
            candidates.sort(key=lambda dst: (d[src, dst], dst))
            edges += [[src, candidates[0]], [src, candidates[1]]]
        return np.asarray(edges, dtype=np.int64).T

    def _build_sequences(self, scaled: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        n = len(scaled) // ROWS_PER_SEQUENCE
        xs = np.zeros((n, GRAPHS_PER_SEQUENCE, NODES_PER_GRAPH, NUM_FEATURES), np.float32)
        es = np.zeros((n, GRAPHS_PER_SEQUENCE, 2, EDGES_PER_GRAPH), np.int64)
        for sid in range(n):
            base = sid * ROWS_PER_SEQUENCE
            for t in range(GRAPHS_PER_SEQUENCE):
                x = scaled[base + t * NODES_PER_GRAPH: base + (t + 1) * NODES_PER_GRAPH]
                xs[sid, t] = x
                es[sid, t] = self._edges(x)
        return xs, es

    @staticmethod
    def _ground_truth(block: pd.DataFrame) -> str | None:
        if "TrafficType" not in block.columns:
            return None
        values = block["TrafficType"].fillna("").astype(str).str.strip().str.lower()
        if values.empty:
            return None
        return "Malicious" if values.eq("malicious").any() else "Benign"

    @staticmethod
    def _attack_types(block: pd.DataFrame) -> list[str]:
        if "AttackType" not in block.columns:
            return []
        out = []
        for value in block["AttackType"].tolist():
            if pd.isna(value):
                continue
            value = str(value).strip()
            if value and value.lower() not in {"nan", "none", "benign"} and value not in out:
                out.append(value)
        return out

    @staticmethod
    def _risk(probability: float) -> str:
        if probability >= 0.70:
            return "High"
        if probability >= 0.40:
            return "Medium"
        return "Low"

    def predict_dataframe(self, live: pd.DataFrame) -> dict[str, Any]:
        started = time.perf_counter()
        live = _clean_columns(live)
        validation = self.validate_input(live)

        scaled, distances = self._calibrate(live)
        xs, es = self._build_sequences(scaled)

        with torch.no_grad():
            x_tensor = torch.from_numpy(xs).to(self.device)
            e_tensor = torch.from_numpy(es).to(self.device)
            logits, _, _, _, _, spatial_weight, temporal_weight = self.model(x_tensor, e_tensor)

        probs = torch.softmax(logits, dim=1).detach().cpu().numpy()
        sw = spatial_weight.detach().cpu().numpy().reshape(-1)
        tw = temporal_weight.detach().cpu().numpy().reshape(-1)

        rows = []
        y_true = []
        y_pred = []

        for sid in range(len(xs)):
            block = live.iloc[sid * ROWS_PER_SEQUENCE:(sid + 1) * ROWS_PER_SEQUENCE]
            ground_truth = self._ground_truth(block)
            attacks = self._attack_types(block)

            p_benign = float(probs[sid, 0])
            p_malicious = float(probs[sid, 1])
            prediction = "Malicious" if p_malicious >= DECISION_THRESHOLD else "Benign"
            confidence = max(p_benign, p_malicious)
            mean_distance = float(np.mean(distances[sid * ROWS_PER_SEQUENCE:(sid + 1) * ROWS_PER_SEQUENCE]))

            rows.append({
                "sequence_id": sid + 1,
                "prediction": prediction,
                "ground_truth": ground_truth,
                "ground_truth_available": ground_truth is not None,
                "attack_type": attacks,
                "benign_probability": p_benign * 100.0,
                "malicious_probability": p_malicious * 100.0,
                "confidence": confidence * 100.0,
                "risk_level": self._risk(p_malicious),
                "spatial_attention": float(sw[sid]) * 100.0,
                "temporal_attention": float(tw[sid]) * 100.0,
                "borderline": bool(abs(p_malicious - DECISION_THRESHOLD) < 0.10),
                "mean_calibration_distance": mean_distance,
                "distribution_review": bool(mean_distance >= CALIBRATION_REVIEW_DISTANCE),
            })

            if ground_truth is not None:
                y_true.append(1 if ground_truth == "Malicious" else 0)
                y_pred.append(1 if prediction == "Malicious" else 0)

        evaluation_available = len(y_true) == len(rows)
        if evaluation_available and y_true:
            yt = np.asarray(y_true, dtype=np.int8)
            yp = np.asarray(y_pred, dtype=np.int8)
            tp = int(((yt == 1) & (yp == 1)).sum())
            tn = int(((yt == 0) & (yp == 0)).sum())
            fp = int(((yt == 0) & (yp == 1)).sum())
            fn = int(((yt == 1) & (yp == 0)).sum())
            total = len(yt)
            accuracy = (tp + tn) / total
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            specificity = tn / (tn + fp) if tn + fp else 0.0
            fpr = fp / (fp + tn) if fp + tn else 0.0
            fnr = fn / (fn + tp) if fn + tp else 0.0
            denom = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
            mcc = ((tp * tn - fp * fn) / denom) if denom else 0.0
            summary = {
                "total_sequences": total,
                "sequences": total,
                "benign_sequences": int((yt == 0).sum()),
                "malicious_sequences": int((yt == 1).sum()),
                "predicted_benign": int((yp == 0).sum()),
                "predicted_malicious": int((yp == 1).sum()),
                "accuracy": accuracy * 100.0,
                "precision": precision * 100.0,
                "recall": recall * 100.0,
                "f1": f1 * 100.0,
                "specificity": specificity * 100.0,
                "fpr": fpr * 100.0,
                "fnr": fnr * 100.0,
                "false_positive_rate": fpr * 100.0,
                "false_negative_rate": fnr * 100.0,
                "mcc": mcc,
                "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            }
        else:
            # For unlabeled real traffic, prediction is still returned but
            # accuracy/precision/recall are intentionally not fabricated.
            pred = np.asarray([1 if r["prediction"] == "Malicious" else 0 for r in rows])
            summary = {
                "total_sequences": len(rows),
                "sequences": len(rows),
                "benign_sequences": None,
                "malicious_sequences": None,
                "predicted_benign": int((pred == 0).sum()),
                "predicted_malicious": int((pred == 1).sum()),
                "accuracy": None, "precision": None, "recall": None,
                "f1": None, "specificity": None, "fpr": None, "fnr": None,
                "false_positive_rate": None, "false_negative_rate": None,
                "mcc": None, "tp": None, "tn": None, "fp": None, "fn": None,
            }

        # Attack-family analysis is an evaluation view only. The classifier
        # remains binary Benign/Malicious.
        attack_analysis = []
        if evaluation_available:
            attack_map: dict[str, dict[str, int]] = {}
            for row in rows:
                if row["ground_truth"] != "Malicious":
                    continue
                for attack in row["attack_type"]:
                    item = attack_map.setdefault(attack, {"total": 0, "detected": 0, "missed": 0})
                    item["total"] += 1
                    if row["prediction"] == "Malicious":
                        item["detected"] += 1
                    else:
                        item["missed"] += 1
            for name, item in sorted(attack_map.items()):
                item["name"] = name
                item["recall"] = (item["detected"] / item["total"] * 100.0) if item["total"] else 0.0
                attack_analysis.append(item)

        elapsed = time.perf_counter() - started
        mean_distance = float(np.mean(distances)) if len(distances) else 0.0
        median_distance = float(np.median(distances)) if len(distances) else 0.0
        max_distance = float(np.max(distances)) if len(distances) else 0.0
        summary["mean_spatial_attention"] = float(np.mean(sw) * 100.0)
        summary["mean_temporal_attention"] = float(np.mean(tw) * 100.0)
        summary["inference_time_seconds"] = elapsed
        summary["throughput_sequences_per_second"] = len(rows) / elapsed if elapsed else 0.0

        review_sequences = [r["sequence_id"] for r in rows if r["distribution_review"]]
        latest = rows[-1] if rows else None
        false_negatives = [r for r in rows if r["ground_truth"] == "Malicious" and r["prediction"] == "Benign"] if evaluation_available else []
        false_positives = [r for r in rows if r["ground_truth"] == "Benign" and r["prediction"] == "Malicious"] if evaluation_available else []

        return {
            "filename_independent": True,
            "model": "HTSTCL-GNN",
            "model_task": "Binary intrusion detection: Benign / Malicious",
            "decision_threshold": DECISION_THRESHOLD,
            "input_contract": validation,
            "calibration": {
                "method": "Exact nearest-NIDD-row calibration using 8 live traffic features",
                "mean_distance": mean_distance,
                "median_distance": median_distance,
                "max_distance": max_distance,
                "review_threshold": CALIBRATION_REVIEW_DISTANCE,
                "review_sequences": review_sequences,
                "warning": bool(max_distance >= CALIBRATION_REVIEW_DISTANCE),
            },
            "summary": summary,
            "latest": latest,
            "sequences": rows,
            "attack_analysis": attack_analysis,
            "false_negatives": false_negatives,
            "false_positives": false_positives,
        }
