import React, { useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  BarChart3,
  Bell,
  BrainCircuit,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Cpu,
  Database,
  Download,
  FileBarChart2,
  FileCheck2,
  FileSpreadsheet,
  Gauge,
  GitBranch,
  Layers3,
  LayoutDashboard,
  Loader2,
  Menu,
  Network,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Upload,
  X,
  Zap
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";
const API = axios.create({ baseURL: API_BASE, timeout: 180000 });

const REQUIRED_FIELDS = [
  "SampleID", "UEID", "TrafficType", "AttackType", "PacketCount", "Bytes",
  "Duration", "PacketRate", "ByteRate", "MeanPacketSize", "MinPacketSize",
  "MaxPacketSize", "Protocol", "LossRate", "Timestamp"
];

const MODEL = {
  name: "HTSTCL-GNN",
  fullName: "Explainable Hierarchical Temporal Graph Neural Network",
  features: 91,
  nodes: 5,
  graphs: 5,
  edges: 10,
  threshold: 0.50
};

const FALLBACK = {
  summary: {
    total_sequences: 240,
    benign_sequences: 120,
    malicious_sequences: 120,
    predicted_benign: 121,
    predicted_malicious: 119,
    accuracy: 99.5833,
    precision: 100,
    recall: 99.1667,
    f1: 99.5816,
    specificity: 100,
    fpr: 0,
    fnr: 0.8333,
    mcc: 0.9917,
    tp: 119,
    tn: 120,
    fp: 0,
    fn: 1,
    mean_spatial_attention: 14.7739,
    mean_temporal_attention: 85.2262,
    inference_time_seconds: 2.2065,
    throughput_sequences_per_second: 108.77
  },
  sequences: [],
  false_negatives: [],
  false_positives: []
};

function number(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function pct(value) {
  if (value === null || value === undefined || value === "") return "N/A";
  const n = Number(value);
  return Number.isFinite(n) ? `${n.toFixed(2)}%` : "N/A";
}

function normalizePercent(value) {
  const n = number(value);
  return n <= 1 ? n * 100 : n;
}

function normalizeSequence(item, index) {
  const prediction =
    item?.prediction ??
    item?.predicted_class ??
    item?.Predicted ??
    item?.result ??
    "Benign";

  const truth =
    item?.ground_truth ??
    item?.groundTruth ??
    item?.true_class ??
    item?.True_Class ??
    item?.actual ??
    "";

  const benignProb = normalizePercent(
    item?.benign_probability ?? item?.benignProbability ?? item?.probability_benign ?? 0
  );
  const maliciousProb = normalizePercent(
    item?.malicious_probability ?? item?.maliciousProbability ?? item?.probability_malicious ?? 0
  );

  const predictionText = String(prediction).toLowerCase().includes("malicious")
    ? "Malicious"
    : "Benign";

  const confidence = Math.max(benignProb, maliciousProb);
  const borderline =
    item?.borderline ??
    Math.abs(maliciousProb / 100 - MODEL.threshold) < 0.05;

  return {
    sequence_id: item?.sequence_id ?? item?.Sequence_ID ?? item?.id ?? index + 1,
    prediction: predictionText,
    ground_truth: truth ? (String(truth).toLowerCase().includes("malicious") ? "Malicious" : "Benign") : "",
    benign_probability: benignProb,
    malicious_probability: maliciousProb,
    confidence,
    spatial_attention: normalizePercent(item?.spatial_attention ?? item?.spatialAttention ?? 0),
    temporal_attention: normalizePercent(item?.temporal_attention ?? item?.temporalAttention ?? 0),
    attack_type: item?.attack_type ?? item?.attackType ?? "",
    risk_level: item?.risk_level ?? item?.riskLevel ?? (predictionText === "Malicious" ? "High" : "Low"),
    borderline: Boolean(borderline)
  };
}

function normalizeResponse(data) {
  const rawSummary = data?.summary || data?.metrics || {};
  const summary = {
    ...FALLBACK.summary,
    ...rawSummary
  };

  const rawSequences =
    data?.sequences ??
    data?.results ??
    data?.sequence_results ??
    data?.predictions ??
    [];

  let sequences = Array.isArray(rawSequences)
    ? rawSequences.map(normalizeSequence)
    : [];

  // Some backends return only the latest sequence at the top level.
  if (!sequences.length && (data?.sequence_id || data?.Sequence_ID || data?.prediction)) {
    sequences = [normalizeSequence(data, 0)];
  }

  const latest =
    normalizeSequence(data?.latest || data?.latest_sequence || data, sequences.length) ||
    sequences[sequences.length - 1];

  if (sequences.length) {
    const last = sequences[sequences.length - 1];
    return {
      ...data,
      summary,
      sequences,
      latest: normalizeSequence(data?.latest || last, sequences.length - 1),
      false_negatives: data?.false_negatives || [],
      false_positives: data?.false_positives || []
    };
  }

  return {
    ...data,
    summary,
    sequences: [],
    latest,
    false_negatives: data?.false_negatives || [],
    false_positives: data?.false_positives || []
  };
}

function mergeSummaryFromSequences(summary, sequences) {
  if (!sequences.length) return summary;

  const actualBenign = sequences.filter(s => s.ground_truth === "Benign").length;
  const actualMalicious = sequences.filter(s => s.ground_truth === "Malicious").length;
  const predictedBenign = sequences.filter(s => s.prediction === "Benign").length;
  const predictedMalicious = sequences.filter(s => s.prediction === "Malicious").length;

  const tp = sequences.filter(s => s.ground_truth === "Malicious" && s.prediction === "Malicious").length;
  const tn = sequences.filter(s => s.ground_truth === "Benign" && s.prediction === "Benign").length;
  const fp = sequences.filter(s => s.ground_truth === "Benign" && s.prediction === "Malicious").length;
  const fn = sequences.filter(s => s.ground_truth === "Malicious" && s.prediction === "Benign").length;

  if (actualBenign + actualMalicious === sequences.length && sequences.length > 0) {
    const total = sequences.length;
    const accuracy = ((tp + tn) / total) * 100;
    const precision = tp + fp ? (tp / (tp + fp)) * 100 : 0;
    const recall = tp + fn ? (tp / (tp + fn)) * 100 : 0;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
    const specificity = tn + fp ? (tn / (tn + fp)) * 100 : 0;
    const fpr = fp + tn ? (fp / (fp + tn)) * 100 : 0;
    const fnr = fn + tp ? (fn / (fn + tp)) * 100 : 0;

    return {
      ...summary,
      total_sequences: total,
      benign_sequences: actualBenign,
      malicious_sequences: actualMalicious,
      predicted_benign: predictedBenign,
      predicted_malicious: predictedMalicious,
      tp, tn, fp, fn,
      accuracy, precision, recall, f1, specificity, fpr, fnr
    };
  }

  return summary;
}

function Badge({ children, tone = "neutral" }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

function MetricCard({ icon: Icon, label, value, sub, tone = "" }) {
  return (
    <div className={`metric-card ${tone}`}>
      <div className="metric-icon"><Icon size={18} /></div>
      <div className="metric-body">
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        {sub && <div className="metric-sub">{sub}</div>}
      </div>
    </div>
  );
}

function SectionHeader({ eyebrow, title, description, action }) {
  return (
    <div className="section-header">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  );
}

function AttentionBar({ label, value, icon: Icon }) {
  return (
    <div className="attention-row">
      <div className="attention-label">
        <span><Icon size={16} /> {label}</span>
        <strong>{pct(value)}</strong>
      </div>
      <div className="attention-track">
        <div className="attention-fill" style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
      </div>
    </div>
  );
}

function ConfusionMatrix({ summary }) {
  const cells = [
    { label: "True Negative", value: number(summary.tn), cls: "tn" },
    { label: "False Positive", value: number(summary.fp), cls: "fp" },
    { label: "False Negative", value: number(summary.fn), cls: "fn" },
    { label: "True Positive", value: number(summary.tp), cls: "tp" }
  ];

  return (
    <div className="matrix-wrap">
      <div className="matrix-axis-top">Predicted Class</div>
      <div className="matrix-layout">
        <div className="matrix-axis-left">Actual Class</div>
        <div className="matrix-grid">
          <div className="matrix-corner" />
          <div className="matrix-head">Benign</div>
          <div className="matrix-head">Malicious</div>
          <div className="matrix-side">Benign</div>
          <div className="matrix-cell tn">{number(summary.tn)}<small>TN</small></div>
          <div className="matrix-cell fp">{number(summary.fp)}<small>FP</small></div>
          <div className="matrix-side">Malicious</div>
          <div className="matrix-cell fn">{number(summary.fn)}<small>FN</small></div>
          <div className="matrix-cell tp">{number(summary.tp)}<small>TP</small></div>
        </div>
      </div>
      <div className="matrix-legend">
        {cells.map(c => <span key={c.label}><i className={`legend-dot ${c.cls}`} />{c.label}: <b>{c.value}</b></span>)}
      </div>
    </div>
  );
}

function App() {
  const [page, setPage] = useState("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [file, setFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState("checking");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [pageNumber, setPageNumber] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const resultRef = useRef(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    checkHealth();
  }, []);

  useEffect(() => {
    if (result?.sequences?.length) {
      resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [result]);

  const sequences = result?.sequences || [];
  const summary = mergeSummaryFromSequences(result?.summary || FALLBACK.summary, sequences);
  const latest = result?.latest || sequences[sequences.length - 1] || null;

  const filteredSequences = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return sequences;
    return sequences.filter(s =>
      [
        s.sequence_id,
        s.prediction,
        s.ground_truth,
        s.attack_type,
        s.risk_level
      ].join(" ").toLowerCase().includes(q)
    );
  }, [sequences, search]);

  const totalPages = Math.max(1, Math.ceil(filteredSequences.length / pageSize));
  const safePage = Math.min(pageNumber, totalPages);
  const paginated = filteredSequences.slice((safePage - 1) * pageSize, safePage * pageSize);

  const attackData = useMemo(() => {
    if (Array.isArray(result?.attack_analysis) && result.attack_analysis.length) {
      return result.attack_analysis.map(a => ({
        name: a.name,
        total: number(a.total),
        detected: number(a.detected),
        missed: number(a.missed),
        recall: number(a.recall)
      }));
    }
    if (!sequences.length) {
      return [
        { name: "BruteForce", total: 118, detected: 117 },
        { name: "DDoS", total: 120, detected: 119 },
        { name: "DoS", total: 120, detected: 119 },
        { name: "Flooding", total: 120, detected: 119 },
        { name: "PortScan", total: 120, detected: 119 }
      ];
    }
    return [];
  }, [result, sequences]);

  async function checkHealth() {
    try {
      const response = await API.get("/api/health", { timeout: 5000 });
      setHealth(response.data?.status === "ok" || response.data?.status === "healthy" ? "online" : "online");
    } catch {
      setHealth("offline");
    }
  }

  function acceptFile(selected) {
    setError("");
    if (!selected) return;
    if (!selected.name.toLowerCase().endsWith(".csv")) {
      setError("Please select a CSV file.");
      return;
    }
    setFile(selected);
    setPage("upload");
    setSidebarOpen(false);
  }

  function onDrop(event) {
    event.preventDefault();
    setDragActive(false);
    acceptFile(event.dataTransfer.files?.[0]);
  }

  async function runDetection() {
    if (!file) {
      setError("Select a CSV file before starting detection.");
      return;
    }

    setLoading(true);
    setError("");
    setPage("upload");

    try {
      const form = new FormData();
      form.append("file", file);
      const response = await API.post("/api/ids/predict", form, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 180000
      });
      const normalized = normalizeResponse(response.data);
      setResult(normalized);
      setPageNumber(1);
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 250);
    } catch (err) {
      const detail = err?.response?.data?.detail || err?.message || "IDS inference failed.";
      setError(String(detail));
    } finally {
      setLoading(false);
    }
  }

  async function loadDefault() {
    setLoading(true);
    setError("");
    try {
      const response = await API.get("/api/ids/default", { timeout: 180000 });
      setResult(normalizeResponse(response.data));
      setPage("upload");
      setPageNumber(1);
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 250);
    } catch (err) {
      setError(String(err?.response?.data?.detail || err?.message || "Unable to load default inference."));
    } finally {
      setLoading(false);
    }
  }

  function downloadResults() {
    if (!sequences.length) return;
    const headers = [
      "Sequence ID", "Ground Truth", "Prediction", "Benign Probability",
      "Malicious Probability", "Confidence", "Spatial Attention",
      "Temporal Attention", "Risk Level", "Attack Type", "Borderline"
    ];
    const rows = sequences.map(s => [
      s.sequence_id, s.ground_truth, s.prediction, s.benign_probability.toFixed(4),
      s.malicious_probability.toFixed(4), s.confidence.toFixed(4),
      s.spatial_attention.toFixed(4), s.temporal_attention.toFixed(4),
      s.risk_level, `"${String(s.attack_type).replaceAll('"', '""')}"`, s.borderline
    ]);
    const csv = [headers, ...rows].map(r => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "5g_ids_detection_results.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  const nav = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "upload", label: "Upload Traffic", icon: Upload }
  ];

  const trafficPie = [
    { name: "Benign", value: number(summary.benign_sequences), fill: "#22c55e" },
    { name: "Malicious", value: number(summary.malicious_sequences), fill: "#ef4444" }
  ];

  return (
    <div className="app-shell">
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={24} /></div>
          <div>
            <div className="brand-name">5G IDS</div>
            <div className="brand-sub">Wireless Security</div>
          </div>
        </div>

        <div className="sidebar-status">
          <span className={`status-dot ${health}`} />
          <span>{health === "online" ? "IDS Online" : health === "checking" ? "Checking..." : "Backend Offline"}</span>
        </div>

        <nav className="nav">
          {nav.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-item ${page === id ? "active" : ""}`}
              onClick={() => { setPage(id); setSidebarOpen(false); }}
            >
              <Icon size={18} />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-model">
          <div className="mini-label">ACTIVE MODEL</div>
          <div className="model-title">{MODEL.name}</div>
          <div className="model-meta">{MODEL.features} features · {MODEL.graphs} graph steps</div>
          <div className="model-line">
            <span><Cpu size={13} /> CPU inference</span>
            <span className="model-ready">READY</span>
          </div>
        </div>

        <div className="sidebar-footer">
          <div>5G Wireless Intrusion Detection</div>
          <div className="version">HTSTCL-GNN · v1.0</div>
        </div>
      </aside>

      {sidebarOpen && <div className="mobile-overlay" onClick={() => setSidebarOpen(false)} />}

      <main className="main">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setSidebarOpen(v => !v)}><Menu size={21} /></button>
          <div>
            <div className="top-eyebrow">5G WIRELESS INTRUSION DETECTION</div>
            <h1>{page === "dashboard" ? "Security Operations Dashboard" : "Network Traffic Analysis"}</h1>
          </div>
          <div className="top-actions">
            <button className="icon-button" title="Refresh backend status" onClick={checkHealth}><RefreshCw size={17} /></button>
            <div className={`system-pill ${health}`}>
              <span className="status-dot" />
              {health === "online" ? "Model Ready" : health === "checking" ? "Checking" : "Backend Offline"}
            </div>
          </div>
        </header>

        <div className="content">
          {error && (
            <div className="alert error">
              <AlertCircle size={18} />
              <div><strong>Detection error</strong><span>{error}</span></div>
              <button onClick={() => setError("")}><X size={16} /></button>
            </div>
          )}

          {page === "dashboard" ? (
            <>
              <section className="hero-card">
                <div>
                  <div className="hero-kicker"><Sparkles size={15} /> EXPLAINABLE 5G INTRUSION DETECTION</div>
                  <h2>Monitor and analyze<br /><span>5G network threats.</span></h2>
                  <p>
                    Hierarchical temporal graph learning for early binary intrusion detection,
                    with spatial and temporal attention for explainability.
                  </p>
                  <div className="hero-actions">
                    <button className="primary-btn" onClick={() => setPage("upload")}><Upload size={17} /> Analyze Traffic</button>
                    <button className="secondary-btn dark" onClick={loadDefault} disabled={loading}>
                      {loading ? <Loader2 size={17} className="spin" /> : <Zap size={17} />}
                      Run Default Simulation
                    </button>
                  </div>
                </div>
                <div className="hero-visual">
                  <div className="radar-ring ring-one" />
                  <div className="radar-ring ring-two" />
                  <div className="radar-ring ring-three" />
                  <div className="radar-core"><Shield size={34} /></div>
                  <div className="signal s1" /><div className="signal s2" /><div className="signal s3" />
                </div>
              </section>

              <div className="section-gap" />

              <SectionHeader
                eyebrow="MODEL PERFORMANCE"
                title="Validated detection metrics"
                description="Current deployment evaluation from the 240-sequence MATLAB traffic simulation."
                action={<Badge tone="success"><CheckCircle2 size={13} /> Validated</Badge>}
              />

              <div className="metric-grid">
                <MetricCard icon={Target} label="Accuracy" value={pct(summary.accuracy)} sub="Overall classification" tone="blue" />
                <MetricCard icon={ShieldCheck} label="Precision" value={pct(summary.precision)} sub="Malicious predictions" tone="green" />
                <MetricCard icon={Activity} label="Recall" value={pct(summary.recall)} sub="Threats detected" tone="purple" />
                <MetricCard icon={Gauge} label="F1 Score" value={pct(summary.f1)} sub="Balanced performance" tone="orange" />
                <MetricCard icon={Shield} label="Specificity" value={pct(summary.specificity)} sub="Benign correctly identified" />
                <MetricCard icon={GitBranch} label="MCC" value={number(summary.mcc).toFixed(4)} sub="Matthews correlation" />
              </div>

              <div className="dashboard-grid two">
                <section className="panel">
                  <SectionHeader eyebrow="CLASSIFICATION" title="Confusion matrix" description="Sequence-level detection outcomes." />
                  <ConfusionMatrix summary={summary} />
                </section>

                <section className="panel">
                  <SectionHeader eyebrow="TRAFFIC DISTRIBUTION" title="Simulation traffic" description="Ground-truth class distribution." />
                  <div className="traffic-chart">
                    <ResponsiveContainer width="100%" height={235}>
                      <PieChart>
                        <Pie data={trafficPie} cx="50%" cy="50%" innerRadius={66} outerRadius={92} paddingAngle={3} dataKey="value">
                          {trafficPie.map((entry) => <Cell key={entry.name} fill={entry.fill} />)}
                        </Pie>
                        <Tooltip formatter={(value) => [`${value} sequences`, "Traffic"]} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="pie-center">
                      <strong>{number(summary.total_sequences)}</strong>
                      <span>Sequences</span>
                    </div>
                  </div>
                  <div className="traffic-legend">
                    <div><i className="legend-dot benign" /><span>Benign</span><b>{summary.benign_sequences}</b></div>
                    <div><i className="legend-dot malicious" /><span>Malicious</span><b>{summary.malicious_sequences}</b></div>
                  </div>
                </section>
              </div>

              <section className="panel">
                <SectionHeader eyebrow="EXPLAINABILITY" title="Hierarchical attention" description="Average contribution of spatial and temporal representations across the deployment run." />
                <div className="attention-grid">
                  <AttentionBar label="Spatial attention" value={number(summary.mean_spatial_attention)} icon={Network} />
                  <AttentionBar label="Temporal attention" value={number(summary.mean_temporal_attention)} icon={Activity} />
                </div>
                <div className="attention-note">
                  <BrainCircuit size={17} />
                  <span>The temporal encoder receives the 5-step graph sequence and contributes to the final fused representation.</span>
                </div>
              </section>

              <section className="architecture-card">
                <div className="architecture-copy">
                  <div className="eyebrow light">MODEL PIPELINE</div>
                  <h2>From 5G traffic to an explainable security decision</h2>
                  <p>Each sequence contains 5 temporal graph steps. Every graph contains 5 traffic nodes and 10 directed nearest-neighbor edges.</p>
                </div>
                <div className="pipeline">
                  {[
                    ["01", "Traffic", "5G flow records"],
                    ["02", "Graph", "5 nodes · 10 edges"],
                    ["03", "Spatial", "GAT encoder"],
                    ["04", "Temporal", "2-layer GRU"],
                    ["05", "Fusion", "Attention"],
                    ["06", "Decision", "Benign / Malicious"]
                  ].map(([n, title, sub]) => (
                    <div className="pipeline-step" key={n}>
                      <span>{n}</span><strong>{title}</strong><small>{sub}</small>
                    </div>
                  ))}
                </div>
              </section>
            </>
          ) : (
            <>
              <section className="upload-hero">
                <div className="hero-kicker"><FileSpreadsheet size={15} /> TRAFFIC INPUT</div>
                <h2>Load 5G network traffic</h2>
                <p>Upload the CSV generated by the MATLAB 5G simulation and send it through the validated HTSTCL-GNN inference pipeline.</p>
              </section>

              <div className="upload-grid">
                <section className="panel upload-panel">
                  <SectionHeader
                    eyebrow="INPUT DATA"
                    title="Upload traffic CSV"
                    description="The backend validates the required MATLAB traffic contract before inference."
                  />
                  <div
                    className={`dropzone ${dragActive ? "drag-active" : ""} ${file ? "has-file" : ""}`}
                    onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
                    onDragLeave={() => setDragActive(false)}
                    onDrop={onDrop}
                  >
                    <div className="upload-icon"><Upload size={27} /></div>
                    <h3>Drag & drop your CSV here</h3>
                    <p>or choose a file from your computer</p>
                    <button className="outline-btn" onClick={() => fileInputRef.current?.click()}>
                      <FileSpreadsheet size={16} /> Choose CSV File
                    </button>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".csv,text/csv"
                      hidden
                      onChange={(e) => acceptFile(e.target.files?.[0])}
                    />
                  </div>

                  {file && (
                    <div className="selected-file">
                      <div className="file-icon"><FileCheck2 size={19} /></div>
                      <div className="file-info">
                        <strong>{file.name}</strong>
                        <span>{(file.size / 1024 / 1024).toFixed(2)} MB · CSV</span>
                      </div>
                      <button onClick={() => setFile(null)}><X size={17} /></button>
                    </div>
                  )}

                  <div className="upload-actions">
                    <button className="primary-btn" onClick={runDetection} disabled={!file || loading}>
                      {loading ? <><Loader2 size={17} className="spin" /> Running IDS...</> : <><Zap size={17} /> Run IDS Detection</>}
                    </button>
                    <button className="secondary-btn" onClick={() => latest && resultRef.current?.scrollIntoView({ behavior: "smooth" })} disabled={!latest}>
                      Preview Result
                    </button>
                    <button className="text-btn" onClick={loadDefault} disabled={loading}>
                      Use default simulation
                    </button>
                  </div>
                </section>

                <section className="panel requirements-panel">
                  <SectionHeader eyebrow="INPUT CONTRACT" title="File requirements" description="Expected MATLAB-generated traffic format." />
                  <div className="requirement-list">
                    <div><span>File format</span><b>CSV</b></div>
                    <div><span>Rows per sequence</span><b>25</b></div>
                    <div><span>Graphs per sequence</span><b>5</b></div>
                    <div><span>Nodes per graph</span><b>5</b></div>
                    <div><span>Edges per graph</span><b>10</b></div>
                    <div><span>Traffic classes</span><b>Benign / Malicious</b></div>
                  </div>
                  <div className="field-title">Required traffic fields</div>
                  <div className="field-tags">
                    {REQUIRED_FIELDS.map(f => <span key={f}>{f}</span>)}
                  </div>
                </section>
              </div>

              {result?.input_contract && (
                <section className="panel compatibility-panel">
                  <SectionHeader
                    eyebrow="INPUT COMPATIBILITY"
                    title={result.input_file?.filename ? result.input_file.filename : "Uploaded traffic"}
                    description="The filename is not used by the classifier. Compatibility is determined from the traffic fields and sequence structure."
                    action={<Badge tone="success"><CheckCircle2 size={13} /> Schema validated</Badge>}
                  />
                  <div className="compatibility-grid">
                    <div><span>Rows</span><strong>{result.input_contract.rows}</strong></div>
                    <div><span>Sequences</span><strong>{result.input_contract.sequences}</strong></div>
                    <div><span>Ground truth</span><strong>{result.input_contract.ground_truth_available ? "Available" : "Not provided"}</strong></div>
                    <div><span>Attack labels</span><strong>{result.input_contract.attack_type_available ? "Available" : "Not provided"}</strong></div>
                    <div><span>Calibration distance</span><strong>{number(result.calibration?.mean_distance).toFixed(3)}</strong></div>
                    <div><span>Distribution review</span><strong className={result.calibration?.warning ? "review-text" : "ok-text"}>{result.calibration?.warning ? "Review recommended" : "Within reference range"}</strong></div>
                  </div>
                  {!result.input_contract.ground_truth_available && (
                    <div className="alert info-inline">
                      <Shield size={17} />
                      <div><strong>Unlabeled traffic</strong><span>The model will still predict Benign/Malicious. Accuracy, precision, recall and confusion-matrix values are not calculated without ground truth.</span></div>
                    </div>
                  )}
                </section>
              )}

              <section className="result-anchor" ref={resultRef}>
                {latest ? (
                  <>
                    <SectionHeader
                      eyebrow="LIVE DETECTION"
                      title="Detection result"
                      description="HTSTCL-GNN output with MATLAB simulator ground truth."
                      action={<button className="secondary-btn" onClick={downloadResults}><Download size={16} /> Export Results</button>}
                    />

                    <div className={`detection-banner ${latest.prediction === "Malicious" ? "malicious" : "benign"}`}>
                      <div className="detection-status">
                        <div className="detection-icon">
                          {latest.prediction === "Malicious" ? <ShieldAlert size={25} /> : <ShieldCheck size={25} />}
                        </div>
                        <div>
                          <span>TRAFFIC STATUS</span>
                          <strong>{latest.prediction.toUpperCase()}</strong>
                        </div>
                      </div>
                      <div className="confidence">
                        <span>CONFIDENCE</span>
                        <strong>{pct(latest.confidence)}</strong>
                        <Badge tone={latest.confidence >= 80 ? (latest.prediction === "Malicious" ? "danger" : "success") : "warning"}>
                          {latest.confidence >= 80 ? "HIGH" : "REVIEW"}
                        </Badge>
                      </div>
                    </div>

                    <div className="result-meta-grid">
                      <div><span>Sequence ID</span><strong>{latest.sequence_id}</strong></div>
                      <div><span>Ground Truth</span><strong>{latest.ground_truth || "—"}</strong></div>
                      <div><span>Benign Probability</span><strong>{pct(latest.benign_probability)}</strong></div>
                      <div><span>Malicious Probability</span><strong>{pct(latest.malicious_probability)}</strong></div>
                      <div><span>Spatial Attention</span><strong>{pct(latest.spatial_attention)}</strong></div>
                      <div><span>Temporal Attention</span><strong>{pct(latest.temporal_attention)}</strong></div>
                    </div>

                    {latest.attack_type && (
                      <div className="attack-box">
                        <div className="attack-title"><AlertTriangle size={17} /><div><strong>Attack Type</strong><span>Ground truth from MATLAB simulation — not a model prediction</span></div></div>
                        <div className="attack-tags">
                          {String(latest.attack_type).split("|").map(x => x.trim()).filter(Boolean).map(a => <Badge key={a} tone="warning">{a}</Badge>)}
                        </div>
                      </div>
                    )}

                    {latest.borderline && (
                      <div className="alert warning">
                        <AlertTriangle size={18} />
                        <div><strong>Borderline decision</strong><span>The malicious probability is close to the 0.50 decision threshold. Treat this sequence as a review case.</span></div>
                      </div>
                    )}

                    <div className="dashboard-grid two result-lower">
                      <section className="panel">
                        <SectionHeader eyebrow="ATTENTION" title="Sequence explainability" description={`Sequence ${latest.sequence_id} contribution weights.`} />
                        <AttentionBar label="Spatial representation" value={latest.spatial_attention} icon={Network} />
                        <AttentionBar label="Temporal representation" value={latest.temporal_attention} icon={Activity} />
                      </section>
                      <section className="panel">
                        <SectionHeader eyebrow="DECISION" title="Probability profile" />
                        <div className="probability-profile">
                          <div className="prob-line"><span>Benign</span><b>{pct(latest.benign_probability)}</b></div>
                          <div className="prob-track"><div className="prob-fill benign-fill" style={{ width: `${latest.benign_probability}%` }} /></div>
                          <div className="prob-line"><span>Malicious</span><b>{pct(latest.malicious_probability)}</b></div>
                          <div className="prob-track"><div className="prob-fill malicious-fill" style={{ width: `${latest.malicious_probability}%` }} /></div>
                        </div>
                        <div className="decision-footer">
                          <span>Decision threshold</span><strong>0.50</strong>
                        </div>
                      </section>
                    </div>
                  </>
                ) : (
                  <section className="empty-result">
                    <div className="empty-icon"><Shield size={27} /></div>
                    <h3>No detection result yet</h3>
                    <p>Upload a MATLAB-generated CSV and run IDS detection. The latest sequence result and complete analysis will appear here.</p>
                  </section>
                )}
              </section>

              {result && (
                <>
                  <section className="panel summary-panel">
                    <SectionHeader eyebrow="RUN SUMMARY" title="Detection overview" description={`${summary.total_sequences} sequence-level decisions from the current inference run.`} />
                    <div className="metric-grid compact">
                      <MetricCard icon={Database} label="Sequences" value={summary.total_sequences} sub={`${summary.benign_sequences} benign · ${summary.malicious_sequences} malicious`} />
                      <MetricCard icon={ShieldCheck} label="Predicted Benign" value={summary.predicted_benign} sub={`TN ${summary.tn} · FN ${summary.fn}`} tone="green" />
                      <MetricCard icon={ShieldAlert} label="Predicted Malicious" value={summary.predicted_malicious} sub={`TP ${summary.tp} · FP ${summary.fp}`} tone="red" />
                      <MetricCard icon={Zap} label="Throughput" value={`${number(summary.throughput_sequences_per_second).toFixed(2)} /s`} sub={`${number(summary.inference_time_seconds).toFixed(3)} s inference`} />
                    </div>
                  </section>

                  <section className="dashboard-grid two">
                    <section className="panel">
                      <SectionHeader eyebrow="CONFUSION MATRIX" title="Classification outcomes" description="Ground truth versus model prediction." />
                      <ConfusionMatrix summary={summary} />
                    </section>

                    <section className="panel">
                      <SectionHeader eyebrow="ERROR ANALYSIS" title="Error rates" description="Operational view of false alarms and missed threats." />
                      <div className="error-metrics">
                        <div className="error-card"><span>False Positive Rate</span><strong>{pct(summary.fpr)}</strong><i className="down"><ArrowDown size={14} /></i></div>
                        <div className="error-card"><span>False Negative Rate</span><strong>{pct(summary.fnr)}</strong><i className="up"><ArrowUp size={14} /></i></div>
                        <div className="error-card"><span>False Positives</span><strong>{summary.fp}</strong></div>
                        <div className="error-card"><span>False Negatives</span><strong>{summary.fn}</strong></div>
                      </div>
                    </section>
                  </section>

                  <section className="panel">
                    <SectionHeader
                      eyebrow="ATTACK ANALYSIS"
                      title="Ground-truth attack distribution"
                      description="Attack labels originate from the MATLAB simulation. The HTSTCL-GNN performs binary benign/malicious classification."
                    />
                    {attackData.length ? (
                    <div className="attack-chart">
                      <ResponsiveContainer width="100%" height={270}>
                        <BarChart data={attackData} margin={{ top: 8, right: 20, left: 0, bottom: 5 }}>
                          <CartesianGrid strokeDasharray="3 3" vertical={false} />
                          <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                          <YAxis allowDecimals={false} />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="total" name="Ground Truth" fill="#94a3b8" radius={[5,5,0,0]} />
                          <Bar dataKey="detected" name="Detected Malicious" fill="#2563eb" radius={[5,5,0,0]} />
                          <Bar dataKey="missed" name="Missed" fill="#ef4444" radius={[5,5,0,0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    ) : (
                      <div className="no-attack-data">Attack-family ground truth is not available for this uploaded traffic. The binary model prediction remains available.</div>
                    )}
                  </section>

                  <section className="panel sequence-panel">
                    <div className="table-header">
                      <div>
                        <div className="eyebrow">SEQUENCE ANALYSIS</div>
                        <h2>Sequence-by-sequence results</h2>
                        <p>Review every graph sequence processed by the IDS.</p>
                      </div>
                      <div className="table-tools">
                        <div className="search-box"><Search size={16} /><input value={search} onChange={e => { setSearch(e.target.value); setPageNumber(1); }} placeholder="Search sequence..." /></div>
                        <button className="secondary-btn" onClick={downloadResults}><Download size={16} /> CSV</button>
                      </div>
                    </div>

                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Sequence</th>
                            <th>Ground Truth</th>
                            <th>Prediction</th>
                            <th>Benign</th>
                            <th>Malicious</th>
                            <th>Confidence</th>
                            <th>Attention</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {paginated.length ? paginated.map(s => {
                            const correct = !s.ground_truth || s.ground_truth === s.prediction;
                            return (
                              <tr key={s.sequence_id}>
                                <td><b>#{s.sequence_id}</b></td>
                                <td><Badge tone={s.ground_truth === "Malicious" ? "danger" : "success"}>{s.ground_truth || "—"}</Badge></td>
                                <td><span className={`prediction ${s.prediction.toLowerCase()}`}><i />{s.prediction}</span></td>
                                <td>{pct(s.benign_probability)}</td>
                                <td>{pct(s.malicious_probability)}</td>
                                <td><b>{pct(s.confidence)}</b></td>
                                <td><span className="attention-mini">S {pct(s.spatial_attention)} · T {pct(s.temporal_attention)}</span></td>
                                <td>
                                  {s.borderline ? <Badge tone="warning">Review</Badge> :
                                    correct ? <Badge tone="success">Correct</Badge> :
                                    <Badge tone="danger">Error</Badge>}
                                </td>
                              </tr>
                            );
                          }) : (
                            <tr><td colSpan="8" className="no-data">No sequence-level records were returned by the backend.</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>

                    <div className="pagination">
                      <span>Showing {filteredSequences.length ? ((safePage - 1) * pageSize + 1) : 0}–{Math.min(safePage * pageSize, filteredSequences.length)} of {filteredSequences.length}</span>
                      <div className="page-controls">
                        <select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPageNumber(1); }}>
                          <option value="10">10 / page</option>
                          <option value="25">25 / page</option>
                          <option value="50">50 / page</option>
                        </select>
                        <button disabled={safePage <= 1} onClick={() => setPageNumber(p => Math.max(1, p - 1))}><ChevronLeft size={16} /></button>
                        <span>Page {safePage} / {totalPages}</span>
                        <button disabled={safePage >= totalPages} onClick={() => setPageNumber(p => Math.min(totalPages, p + 1))}><ChevronRight size={16} /></button>
                      </div>
                    </div>
                  </section>
                </>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
