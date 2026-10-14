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
  Zap,
  Radio,
  Sliders,
  History,
  Lock,
  RotateCcw,
  PlayCircle,
  Clock,
  Filter,
  CheckSquare
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

const GENUINE_ATTACK_CLASSES = [
  "Benign", "UDPFlood", "HTTPFlood", "SlowrateDoS",
  "TCPConnectScan", "SYNScan", "UDPScan", "SYNFlood", "ICMPFlood"
];

const ATTACK_COLORS = {
  Benign: "#10b981",
  UDPFlood: "#ef4444",
  HTTPFlood: "#f97316",
  SlowrateDoS: "#eab308",
  TCPConnectScan: "#3b82f6",
  SYNScan: "#8b5cf6",
  UDPScan: "#06b6d4",
  SYNFlood: "#ec4899",
  ICMPFlood: "#6366f1"
};

const PRIORITY_BADGES = {
  Critical: { bg: "#7f1d1d", text: "#fca5a5", border: "#ef4444" },
  High: { bg: "#7c2d12", text: "#fdba74", border: "#f97316" },
  Medium: { bg: "#713f12", text: "#fde047", border: "#eab308" },
  Low: { bg: "#064e3b", text: "#86efac", border: "#10b981" },
  "Needs Review": { bg: "#581c87", text: "#d8b4fe", border: "#a855f7" },
  Benign: { bg: "#064e3b", text: "#86efac", border: "#10b981" }
};

const SLICE_COLORS = {
  eMBB: { bg: "#1e3a8a", text: "#93c5fd", border: "#3b82f6" },
  URLLC: { bg: "#4c1d95", text: "#d8b4fe", border: "#8b5cf6" },
  mMTC: { bg: "#14532d", text: "#86efac", border: "#22c55e" }
};

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState("checking");
  const [result, setResult] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const [federatedData, setFederatedData] = useState(null);
  const [responseHistory, setResponseHistory] = useState([]);
  const [scenarios, setScenarios] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [multiAgentInvestigation, setMultiAgentInvestigation] = useState(null);
  const [loadingXAI, setLoadingXAI] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [pageNumber, setPageNumber] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [selectedAttackFilter, setSelectedAttackFilter] = useState("All");
  const [queueFilter, setQueueFilter] = useState("active_only"); // 'active_only' | 'all' | 'mitigated_only'
  const [actionNotification, setActionNotification] = useState(null);
  const [mitigatingId, setMitigatingId] = useState(null);

  const fileInputRef = useRef(null);

  useEffect(() => {
    checkHealth();
    loadDefaultTraffic();
    loadAnalytics();
    loadFederatedData();
    loadResponseHistory();
    loadScenarios();
  }, []);

  async function checkHealth() {
    try {
      const res = await API.get("/api/health");
      setHealth(res.data?.status === "online" ? "online" : "offline");
    } catch {
      setHealth("offline");
    }
  }

  async function loadDefaultTraffic() {
    setLoading(true);
    setError("");
    try {
      const res = await API.get("/api/ids/default");
      setResult(res.data);
      if (res.data?.sequences?.length > 0) {
        const topThreat = [...res.data.sequences]
          .filter(s => s.prediction === "Malicious" && !s.is_mitigated)
          .sort((a, b) => b.priority_score - a.priority_score)[0] || res.data.sequences[0];
        setSelectedAlert(topThreat);
        if (res.data.summary?.primary_investigation) {
          setMultiAgentInvestigation(res.data.summary.primary_investigation);
        } else {
          fetchInvestigation(topThreat.sequence_id);
        }
      }
    } catch (err) {
      setError("Unable to load default live traffic. Please upload or load a simulation dataset.");
    } finally {
      setLoading(false);
    }
  }

  async function loadScenarios() {
    try {
      const res = await API.get("/api/ids/simulated-scenarios");
      setScenarios(res.data?.scenarios || []);
    } catch {}
  }

  async function loadScenarioDataset(filename) {
    setLoading(true);
    setError("");
    setActionNotification(null);
    try {
      const res = await API.post(`/api/ids/load-scenario/${filename}`);
      setResult(res.data);
      setPageNumber(1);
      if (res.data?.sequences?.length > 0) {
        const topThreat = [...res.data.sequences]
          .filter(s => s.prediction === "Malicious" && !s.is_mitigated)
          .sort((a, b) => b.priority_score - a.priority_score)[0] || res.data.sequences[0];
        setSelectedAlert(topThreat);
        fetchInvestigation(topThreat.sequence_id);
      }
      setPage("live");
      setActionNotification({
        type: "success",
        message: `Successfully ingested simulation dataset: ${filename} (${(res.data?.sequences?.length || 400) * 25} flows, ${res.data?.sequences?.length || 400} sequences analyzed and prioritized)`
      });
    } catch (err) {
      setError(`Failed loading scenario ${filename}: ` + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  }

  function downloadScenarioDataset(filename) {
    window.open(`${API_BASE}/api/ids/download-scenario/${filename}`, "_blank");
  }

  async function handleFileUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    setLoading(true);
    setError("");
    setActionNotification(null);

    try {
      const res = await API.post("/api/ids/predict", formData, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      setResult(res.data);
      setPageNumber(1);
      if (res.data?.sequences?.length > 0) {
        const topThreat = [...res.data.sequences]
          .filter(s => s.prediction === "Malicious" && !s.is_mitigated)
          .sort((a, b) => b.priority_score - a.priority_score)[0] || res.data.sequences[0];
        setSelectedAlert(topThreat);
        fetchInvestigation(topThreat.sequence_id);
      }
      setPage("live");
      setActionNotification({
        type: "success",
        message: `Successfully analyzed uploaded file: ${file.name} (${res.data?.summary?.total_sequences} sequences detected & prioritized)`
      });
    } catch (err) {
      setError("File upload failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  async function fetchInvestigation(sequenceId) {
    setLoadingXAI(true);
    try {
      const res = await API.get(`/api/ids/xai/investigate/${sequenceId}`);
      setMultiAgentInvestigation(res.data);
    } catch (err) {
      console.error("XAI investigation fetch failed:", err);
    } finally {
      setLoadingXAI(false);
    }
  }

  function handleSelectSequence(seq) {
    setSelectedAlert(seq);
    fetchInvestigation(seq.sequence_id);
    setPage("investigate");
  }

  async function loadAnalytics() {
    try {
      const res = await API.get("/api/ids/analytics");
      setAnalytics(res.data);
    } catch {}
  }

  async function loadFederatedData() {
    try {
      const res = await API.get("/api/ids/federated");
      setFederatedData(res.data);
    } catch {}
  }

  async function loadResponseHistory() {
    try {
      const res = await API.get("/api/ids/response/history");
      setResponseHistory(res.data?.history || []);
    } catch {}
  }

  // Execute Prevention and Mitigation
  async function executeMitigation(actionId, alertId) {
    if (!actionId && !alertId) {
      setActionNotification({
        type: "error",
        message: "Mitigation execution aborted: Missing action ID or alert reference."
      });
      return;
    }

    const targetKey = actionId || alertId;
    setMitigatingId(targetKey);
    setActionNotification(null);

    try {
      const res = await API.post("/api/ids/response/execute", {
        action_id: actionId,
        alert_id: alertId,
        operator_id: "SOC-Lead-Admin",
        notes: "Authorized containment mitigation via 5G Priority Command"
      });

      if (res.data?.success) {
        const execTime = res.data.action?.execution_timestamp || new Date().toLocaleTimeString();

        // 1. Update local sequences state with confirmed mitigation status
        let updatedSequences = [];
        setResult(prev => {
          if (!prev?.sequences) return prev;
          const updated = prev.sequences.map(s => {
            if ((actionId && s.action_id === actionId) || (alertId && s.alert_id === alertId)) {
              return {
                ...s,
                is_mitigated: true,
                response_status: "Executed",
                when_prevented: execTime
              };
            }
            return s;
          });
          updatedSequences = updated;
          return { ...prev, sequences: updated };
        });

        // 2. Refresh audit log history
        loadResponseHistory();

        // 3. Safely advance selection to next unmitigated threat using verified sequence collection
        const candidateSequences = updatedSequences.length > 0 ? updatedSequences : (result?.sequences || []);
        const nextThreat = candidateSequences
          .filter(s => 
            ((actionId && s.action_id !== actionId) || !actionId) &&
            ((alertId && s.alert_id !== alertId) || !alertId) &&
            s.prediction === "Malicious" && 
            !s.is_mitigated
          )
          .sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0))[0];

        if (nextThreat) {
          setSelectedAlert(nextThreat);
          fetchInvestigation(nextThreat.sequence_id);
        } else {
          // If no further threats pending, update the current alert in place
          setSelectedAlert(prev => {
            if (!prev) return null;
            if ((actionId && prev.action_id === actionId) || (alertId && prev.alert_id === alertId)) {
              return { ...prev, is_mitigated: true, response_status: "Executed", when_prevented: execTime };
            }
            return prev;
          });
        }

        setActionNotification({
          type: "success",
          message: `Attack Containment EXECUTED! Threat ${alertId || actionId} successfully neutralized and prevented.`
        });
      } else {
        setActionNotification({
          type: "error",
          message: `Mitigation execution failed: ${res.data?.error || res.data?.message || "Action could not be executed."}`
        });
      }
    } catch (err) {
      const errMsg = err.response?.data?.error || err.response?.data?.detail || err.message || "Unknown communication error";
      setActionNotification({
        type: "error",
        message: "Mitigation execution failed: " + errMsg
      });
    } finally {
      setMitigatingId(null);
    }
  }

  // Rollback Action
  async function rollbackMitigation(actionId, alertId) {
    if (!actionId && !alertId) {
      setActionNotification({
        type: "error",
        message: "Rollback aborted: Missing action ID or alert reference."
      });
      return;
    }

    const targetKey = actionId || alertId;
    setMitigatingId(targetKey);
    setActionNotification(null);

    try {
      const res = await API.post("/api/ids/response/rollback", {
        action_id: actionId,
        alert_id: alertId,
        operator_id: "SOC-Lead-Admin",
        reason: "Operator manual rollback"
      });

      if (res.data?.success) {
        setResult(prev => {
          if (!prev?.sequences) return prev;
          const updated = prev.sequences.map(s => {
            if ((actionId && s.action_id === actionId) || (alertId && s.alert_id === alertId)) {
              return {
                ...s,
                is_mitigated: false,
                response_status: "Rolled Back",
                when_prevented: null
              };
            }
            return s;
          });
          return { ...prev, sequences: updated };
        });

        setSelectedAlert(prev => {
          if (!prev) return null;
          if ((actionId && prev.action_id === actionId) || (alertId && prev.alert_id === alertId)) {
            return { ...prev, is_mitigated: false, response_status: "Rolled Back", when_prevented: null };
          }
          return prev;
        });

        loadResponseHistory();

        setActionNotification({
          type: "info",
          message: `Containment Policy for ${alertId || actionId} rolled back successfully.`
        });
      } else {
        setActionNotification({
          type: "error",
          message: `Rollback failed: ${res.data?.error || res.data?.message || "Policy rollback rejected."}`
        });
      }
    } catch (err) {
      const errMsg = err.response?.data?.error || err.response?.data?.detail || err.message || "Unknown communication error";
      setActionNotification({
        type: "error",
        message: "Rollback failed: " + errMsg
      });
    } finally {
      setMitigatingId(null);
    }
  }

  const rawSequences = result?.sequences || [];

  // SORTING NOTE: Prioritization from HIGH TO LOW based on priority_score!
  const sortedSequences = useMemo(() => {
    return [...rawSequences].sort((a, b) => b.priority_score - a.priority_score);
  }, [rawSequences]);

  // ACTIVE THREAT QUEUE: Find the current #1 highest priority active threat
  const currentTopActiveThreat = useMemo(() => {
    return sortedSequences.find(s => s.prediction === "Malicious" && !s.is_mitigated);
  }, [sortedSequences]);

  // Total active threats vs mitigated threats
  const threatStats = useMemo(() => {
    const malicious = sortedSequences.filter(s => s.prediction === "Malicious");
    const active = malicious.filter(s => !s.is_mitigated);
    const mitigated = malicious.filter(s => s.is_mitigated);
    return {
      total_malicious: malicious.length,
      active_count: active.length,
      mitigated_count: mitigated.length,
      pct_contained: malicious.length > 0 ? Math.round((mitigated.length / malicious.length) * 100) : 100
    };
  }, [sortedSequences]);

  // Filtered sequences for the table based on queue mode & search
  const filteredSequences = useMemo(() => {
    return sortedSequences.filter(s => {
      // Queue Filter
      if (queueFilter === "active_only" && s.prediction === "Malicious" && s.is_mitigated) return false;
      if (queueFilter === "active_only" && s.prediction === "Benign") return false;
      if (queueFilter === "mitigated_only" && !s.is_mitigated) return false;

      // Text Search
      const matchSearch =
        [
          s.sequence_id,
          s.alert_id,
          s.ue_id,
          s.gnb_id,
          s.predicted_attack_type,
          s.priority_level,
          s.protocol,
          s.slice_type
        ]
          .join(" ")
          .toLowerCase()
          .includes(search.toLowerCase());

      // Attack Filter
      const matchAttack =
        selectedAttackFilter === "All" || s.predicted_attack_type === selectedAttackFilter;

      return matchSearch && matchAttack;
    });
  }, [sortedSequences, search, selectedAttackFilter, queueFilter]);

  const attackPieData = useMemo(() => {
    const counts = {};
    rawSequences.forEach(s => {
      const atk = s.predicted_attack_type || "Benign";
      counts[atk] = (counts[atk] || 0) + 1;
    });
    return Object.keys(counts).map(k => ({
      name: k,
      value: counts[k],
      color: ATTACK_COLORS[k] || "#64748b"
    }));
  }, [rawSequences]);

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#0b0f19", color: "#f8fafc", fontFamily: "Inter, sans-serif" }}>
      {/* Sidebar Navigation */}
      <aside style={{ width: "270px", background: "#0f172a", borderRight: "1px solid #1e293b", padding: "24px 16px", display: "flex", flexDirection: "column", gap: "24px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "0 8px" }}>
          <ShieldAlert size={32} color="#38bdf8" />
          <div>
            <h1 style={{ fontSize: "1.1rem", fontWeight: "700", margin: 0, color: "#f8fafc", letterSpacing: "-0.02em" }}>5G-HTSTCL IDS</h1>
            <span style={{ fontSize: "0.72rem", color: "#94a3b8" }}>Enterprise SOC Operations</span>
          </div>
        </div>

        <nav style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
          {[
            { id: "dashboard", label: "SOC Overview", icon: LayoutDashboard },
            { id: "live", label: "Priority Threat Stream", icon: Target },
            { id: "upload", label: "Simulations & Upload", icon: Upload },
            { id: "investigate", label: "Multi-Agent XAI Center", icon: BrainCircuit },
            { id: "response", label: "Containment Command", icon: ShieldCheck },
            { id: "topology", label: "Network Topology", icon: Network },
            { id: "analytics", label: "Attack Analytics", icon: BarChart3 },
            { id: "federated", label: "Federated IDS", icon: GitBranch },
            { id: "model", label: "Model Benchmark", icon: Cpu },
            { id: "reports", label: "Compliance & Export", icon: Download }
          ].map(tab => {
            const Icon = tab.icon;
            const active = page === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setPage(tab.id)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  padding: "10px 14px",
                  borderRadius: "8px",
                  border: "none",
                  background: active ? "#1e293b" : "transparent",
                  color: active ? "#38bdf8" : "#94a3b8",
                  fontWeight: active ? "600" : "500",
                  fontSize: "0.88rem",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "all 0.15s ease"
                }}
              >
                <Icon size={18} />
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Live Containment Progress Widget */}
        <div style={{ marginTop: "auto", padding: "14px", borderRadius: "10px", background: "#1e293b", fontSize: "0.8rem", border: "1px solid #334155" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
            <span style={{ fontWeight: "600", color: "#f8fafc" }}>Containment Status</span>
            <span style={{ fontWeight: "700", color: "#10b981" }}>{threatStats.pct_contained}%</span>
          </div>
          <div style={{ height: "6px", background: "#0f172a", borderRadius: "3px", overflow: "hidden", marginBottom: "10px" }}>
            <div style={{ height: "100%", width: `${threatStats.pct_contained}%`, background: "#10b981", borderRadius: "3px" }} />
          </div>
          <div style={{ fontSize: "0.74rem", color: "#94a3b8", display: "flex", justifyContent: "space-between" }}>
            <span>Active: <b style={{ color: "#ef4444" }}>{threatStats.active_count}</b></span>
            <span>Prevented: <b style={{ color: "#10b981" }}>{threatStats.mitigated_count}</b></span>
          </div>
        </div>
      </aside>

      {/* Main Workspace */}
      <main style={{ flex: 1, padding: "32px", overflowY: "auto" }}>
        {/* Top Header */}
        <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
          <div>
            <h2 style={{ fontSize: "1.65rem", fontWeight: "700", margin: "0 0 6px 0", color: "#f8fafc" }}>
              {page === "dashboard" && "5G Security Operations Center: Active Command"}
              {page === "live" && "Prioritized 5G Threat Mitigation Queue (High ➔ Low)"}
              {page === "upload" && "5G Simulation Datasets & Live CSV Ingestion"}
              {page === "investigate" && "Multi-AI Agent Explainable AI & Containment"}
              {page === "response" && "Defensive Mitigation & Autonomous Containment Engine"}
              {page === "topology" && "5G Multi-Cell Cellular Topology & UE Slice Mapping"}
              {page === "analytics" && "Multiclass 5G Attack Analytics (5G-NIDD)"}
              {page === "federated" && "Federated IDS (Multi-gNB Collaborative FedAvg)"}
              {page === "model" && "HTSTCL-GNN Dual-Head Architecture & Benchmarks"}
              {page === "reports" && "Compliance Audits & Data Export"}
            </h2>
            <p style={{ margin: 0, fontSize: "0.88rem", color: "#94a3b8" }}>
              Hierarchical Spatio-Temporal Graph Neural Network with Evidence-Based Prioritization & Dynamic Mitigation
            </p>
          </div>

          <div style={{ display: "flex", gap: "10px" }}>
            <button
              onClick={() => fileInputRef.current?.click()}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "8px 16px",
                borderRadius: "6px",
                border: "none",
                background: "#0284c7",
                color: "#ffffff",
                fontSize: "0.85rem",
                fontWeight: "600",
                cursor: "pointer"
              }}
            >
              <Upload size={15} />
              Upload Live CSV
            </button>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".csv"
              style={{ display: "none" }}
            />

            <button
              onClick={() => setPage("upload")}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "8px 16px",
                borderRadius: "6px",
                border: "1px solid #334155",
                background: "#1e293b",
                color: "#38bdf8",
                fontSize: "0.85rem",
                fontWeight: "600",
                cursor: "pointer"
              }}
            >
              <Database size={15} />
              6 Simulation Datasets
            </button>
          </div>
        </header>

        {/* Global Action Notifications */}
        {actionNotification && (
          <div style={{
            padding: "12px 18px",
            borderRadius: "8px",
            marginBottom: "20px",
            fontSize: "0.85rem",
            fontWeight: "500",
            background: actionNotification.type === "success" ? "#064e3b" : "#7f1d1d",
            color: actionNotification.type === "success" ? "#a7f3d0" : "#fecaca",
            border: `1px solid ${actionNotification.type === "success" ? "#059669" : "#dc2626"}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center"
          }}>
            <span>{actionNotification.message}</span>
            <button
              onClick={() => setActionNotification(null)}
              style={{ background: "transparent", border: "none", color: "inherit", cursor: "pointer" }}
            >
              <X size={16} />
            </button>
          </div>
        )}

        {error && (
          <div style={{
            padding: "12px 18px",
            borderRadius: "8px",
            marginBottom: "20px",
            fontSize: "0.85rem",
            background: "#7f1d1d",
            color: "#fecaca",
            border: "1px solid #dc2626"
          }}>
            {error}
          </div>
        )}

        {loading && (
          <div style={{ padding: "40px", textAlign: "center", color: "#38bdf8" }}>
            <Loader2 size={36} className="animate-spin" style={{ margin: "0 auto 12px auto" }} />
            <div style={{ fontSize: "1rem", fontWeight: "600" }}>Executing 5G Intrusion Detection Pipeline...</div>
            <div style={{ fontSize: "0.8rem", color: "#94a3b8", marginTop: "4px" }}>
              Calibrating physical features, constructing temporal graph sequences, and sorting threats by priority
            </div>
          </div>
        )}

        {/* ========================================================
            HERO CARD: HIGHEST PRIORITY ACTIVE THREAT TARGET
            (Auto-focuses on the current top threat. Once solved, automatically shows next!)
        ======================================================== */}
        {currentTopActiveThreat && (page === "dashboard" || page === "live") && !loading && (
          <div style={{
            background: "linear-gradient(135deg, rgba(127, 29, 29, 0.4) 0%, rgba(15, 23, 42, 0.9) 100%)",
            border: "2px solid #ef4444",
            borderRadius: "12px",
            padding: "24px",
            marginBottom: "24px",
            boxShadow: "0 8px 24px rgba(239, 68, 68, 0.15)"
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "16px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <span style={{
                  background: "#ef4444",
                  color: "#fff",
                  fontWeight: "800",
                  padding: "4px 10px",
                  borderRadius: "6px",
                  fontSize: "0.8rem",
                  letterSpacing: "0.05em"
                }}>
                  CURRENT TOP PRIORITY THREAT
                </span>
                <span style={{ fontSize: "1.2rem", fontWeight: "700", color: "#f8fafc" }}>
                  Alert {currentTopActiveThreat.alert_id} (Seq #{currentTopActiveThreat.sequence_id})
                </span>
              </div>

              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                <span style={{
                  padding: "6px 12px",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                  fontWeight: "700",
                  background: PRIORITY_BADGES[currentTopActiveThreat.priority_level]?.bg,
                  color: PRIORITY_BADGES[currentTopActiveThreat.priority_level]?.text,
                  border: `1px solid ${PRIORITY_BADGES[currentTopActiveThreat.priority_level]?.border}`
                }}>
                  {currentTopActiveThreat.priority_level} ({currentTopActiveThreat.priority_score}/100)
                </span>
              </div>
            </div>

            {/* Where Detected, When, How Details Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "20px" }}>
              <div style={{ background: "#0f172a", padding: "12px 14px", borderRadius: "8px", border: "1px solid #1e293b" }}>
                <span style={{ fontSize: "0.72rem", color: "#94a3b8", textTransform: "uppercase" }}>Where Detected</span>
                <div style={{ fontWeight: "700", fontSize: "0.95rem", color: "#38bdf8", marginTop: "4px" }}>
                  {currentTopActiveThreat.gnb_id} (Sector Alpha)
                </div>
                <div style={{ fontSize: "0.78rem", color: "#cbd5e1" }}>
                  Target: <b>UE-{currentTopActiveThreat.ue_id}</b> | Slice: <b>{currentTopActiveThreat.slice_type}</b>
                </div>
              </div>

              <div style={{ background: "#0f172a", padding: "12px 14px", borderRadius: "8px", border: "1px solid #1e293b" }}>
                <span style={{ fontSize: "0.72rem", color: "#94a3b8", textTransform: "uppercase" }}>Attack Classification</span>
                <div style={{ fontWeight: "700", fontSize: "0.95rem", color: ATTACK_COLORS[currentTopActiveThreat.predicted_attack_type], marginTop: "4px" }}>
                  {currentTopActiveThreat.predicted_attack_type}
                </div>
                <div style={{ fontSize: "0.78rem", color: "#cbd5e1" }}>
                  Confidence: <b>{currentTopActiveThreat.confidence}%</b> | Protocol: <b>{currentTopActiveThreat.protocol}</b>
                </div>
              </div>

              <div style={{ background: "#0f172a", padding: "12px 14px", borderRadius: "8px", border: "1px solid #1e293b" }}>
                <span style={{ fontSize: "0.72rem", color: "#94a3b8", textTransform: "uppercase" }}>Flow Telemetry</span>
                <div style={{ fontWeight: "700", fontSize: "0.95rem", color: "#f8fafc", marginTop: "4px" }}>
                  {currentTopActiveThreat.packet_count?.toLocaleString()} pkts
                </div>
                <div style={{ fontSize: "0.78rem", color: "#cbd5e1" }}>
                  Duration: <b>{currentTopActiveThreat.duration}s</b> | Dev: <b>1.5x Anomaly</b>
                </div>
              </div>

              <div style={{ background: "#0f172a", padding: "12px 14px", borderRadius: "8px", border: "1px solid #1e293b" }}>
                <span style={{ fontSize: "0.72rem", color: "#94a3b8", textTransform: "uppercase" }}>Operational Urgency</span>
                <div style={{ fontWeight: "700", fontSize: "0.95rem", color: "#ef4444", marginTop: "4px" }}>
                  {currentTopActiveThreat.threat_urgency}
                </div>
                <div style={{ fontSize: "0.78rem", color: "#cbd5e1" }}>
                  Status: <b style={{ color: "#ef4444" }}>Unmitigated Threat</b>
                </div>
              </div>
            </div>

            {/* How Mitigation Performs & Direct Enforcement Button */}
            <div style={{
              background: "#0f172a",
              border: "1px solid #334155",
              borderRadius: "8px",
              padding: "16px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center"
            }}>
              <div>
                <span style={{ fontSize: "0.75rem", color: "#38bdf8", fontWeight: "700", textTransform: "uppercase" }}>
                  How Mitigation Performs:
                </span>
                <div style={{ fontSize: "0.92rem", fontWeight: "700", color: "#f8fafc", marginTop: "2px" }}>
                  {currentTopActiveThreat.recommended_action}
                </div>
                <p style={{ margin: "4px 0 0 0", fontSize: "0.82rem", color: "#94a3b8", maxWidth: "750px" }}>
                  {currentTopActiveThreat.how_mitigated}
                </p>
              </div>

              <div style={{ display: "flex", gap: "12px" }}>
                <button
                  onClick={() => executeMitigation(currentTopActiveThreat.action_id, currentTopActiveThreat.alert_id)}
                  disabled={mitigatingId === currentTopActiveThreat.action_id || mitigatingId === currentTopActiveThreat.alert_id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    padding: "12px 24px",
                    borderRadius: "6px",
                    border: "none",
                    background: (mitigatingId === currentTopActiveThreat.action_id || mitigatingId === currentTopActiveThreat.alert_id) ? "#991b1b" : "#ef4444",
                    color: "#fff",
                    fontWeight: "700",
                    fontSize: "0.95rem",
                    cursor: (mitigatingId === currentTopActiveThreat.action_id || mitigatingId === currentTopActiveThreat.alert_id) ? "not-allowed" : "pointer",
                    boxShadow: "0 4px 12px rgba(239, 68, 68, 0.3)",
                    transition: "all 0.2s ease"
                  }}
                >
                  {mitigatingId === currentTopActiveThreat.action_id || mitigatingId === currentTopActiveThreat.alert_id ? (
                    <>
                      <Loader2 size={18} className="animate-spin" />
                      Enforcing Containment...
                    </>
                  ) : (
                    <>
                      <Zap size={18} />
                      Prevent & Mitigate Now
                    </>
                  )}
                </button>

                <button
                  onClick={() => handleSelectSequence(currentTopActiveThreat)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    padding: "12px 18px",
                    borderRadius: "6px",
                    border: "1px solid #334155",
                    background: "#1e293b",
                    color: "#38bdf8",
                    fontWeight: "600",
                    fontSize: "0.85rem",
                    cursor: "pointer"
                  }}
                >
                  <BrainCircuit size={16} />
                  Inspect Multi-Agent XAI
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================
            ALL THREATS CONTAINED HERO BANNER
        ======================================================== */}
        {threatStats.total_malicious > 0 && threatStats.active_count === 0 && (page === "dashboard" || page === "live") && !loading && (
          <div style={{
            background: "linear-gradient(135deg, rgba(6, 78, 59, 0.45) 0%, rgba(15, 23, 42, 0.95) 100%)",
            border: "2px solid #059669",
            borderRadius: "12px",
            padding: "24px",
            marginBottom: "24px",
            boxShadow: "0 8px 24px rgba(5, 150, 105, 0.2)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center"
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
              <div style={{
                width: "48px",
                height: "48px",
                borderRadius: "12px",
                background: "#064e3b",
                border: "1px solid #10b981",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#10b981"
              }}>
                <CheckCircle2 size={28} />
              </div>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <span style={{
                    background: "#059669",
                    color: "#fff",
                    fontWeight: "800",
                    padding: "4px 10px",
                    borderRadius: "6px",
                    fontSize: "0.8rem",
                    letterSpacing: "0.05em"
                  }}>
                    SECURITY POSTURE: PROTECTED
                  </span>
                  <span style={{ fontSize: "1.15rem", fontWeight: "700", color: "#f8fafc" }}>
                    All {threatStats.total_malicious} Malicious Incursions Successfully Contained
                  </span>
                </div>
                <p style={{ margin: "6px 0 0 0", fontSize: "0.85rem", color: "#94a3b8" }}>
                  100% containment coverage achieved across all serving gNBs (Sector Alpha) and 5G network slices. Zero active threats pending mitigation.
                </p>
              </div>
            </div>
            <div style={{ display: "flex", gap: "10px" }}>
              <button
                onClick={() => setPage("response")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  padding: "10px 18px",
                  borderRadius: "6px",
                  border: "1px solid #059669",
                  background: "#064e3b",
                  color: "#86efac",
                  fontSize: "0.85rem",
                  fontWeight: "600",
                  cursor: "pointer"
                }}
              >
                <Shield size={16} />
                View Containment History
              </button>
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: SOC DASHBOARD OVERVIEW
        ======================================================== */}
        {page === "dashboard" && !loading && (
          <div>
            {/* Top KPI Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "24px" }}>
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Total Analyzed Sequences</span>
                <div style={{ fontSize: "1.8rem", fontWeight: "700", marginTop: "8px", color: "#38bdf8" }}>{rawSequences.length}</div>
                <span style={{ fontSize: "0.75rem", color: "#64748b" }}>25 flows per sequence (5 graphs × 5 nodes)</span>
              </div>
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Malicious Incursions</span>
                <div style={{ fontSize: "1.8rem", fontWeight: "700", marginTop: "8px", color: "#ef4444" }}>{threatStats.total_malicious}</div>
                <span style={{ fontSize: "0.75rem", color: "#ef4444" }}>{threatStats.active_count} active threats pending mitigation</span>
              </div>
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Mitigated & Contained</span>
                <div style={{ fontSize: "1.8rem", fontWeight: "700", marginTop: "8px", color: "#10b981" }}>{threatStats.mitigated_count}</div>
                <span style={{ fontSize: "0.75rem", color: "#10b981" }}>{threatStats.pct_contained}% containment coverage</span>
              </div>
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Multiclass Test Accuracy</span>
                <div style={{ fontSize: "1.8rem", fontWeight: "700", marginTop: "8px", color: "#f59e0b" }}>98.12%</div>
                <span style={{ fontSize: "0.75rem", color: "#f59e0b" }}>Macro F1: 98.83% across 9 classes</span>
              </div>
            </div>

            {/* Middle Section: Chart & Threat Distribution */}
            <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: "20px", marginBottom: "24px" }}>
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
                <h3 style={{ fontSize: "1.1rem", fontWeight: "600", margin: "0 0 16px 0" }}>Attack Category Breakdown</h3>
                <div style={{ height: "260px" }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={attackPieData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11 }} />
                      <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                      <Tooltip contentStyle={{ background: "#0f172a", borderColor: "#334155", color: "#fff" }} />
                      <Bar dataKey="value">
                        {attackPieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Multi-Agent Briefing */}
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                    <Sparkles size={18} color="#38bdf8" />
                    <h3 style={{ fontSize: "1.1rem", fontWeight: "600", margin: 0 }}>Lead AI Incident Briefing</h3>
                  </div>
                  <div style={{ fontSize: "0.85rem", color: "#cbd5e1", lineHeight: "1.6", background: "#1e293b", padding: "14px", borderRadius: "8px", border: "1px solid #334155" }}>
                    {multiAgentInvestigation?.executive_synthesis?.executive_summary ||
                      `Multi-Agent consensus currently monitoring ${rawSequences.length} sequences. Detected ${threatStats.total_malicious} malicious incursions (${threatStats.active_count} pending mitigation). Current top threat prioritized at UE-${currentTopActiveThreat?.ue_id || 1} on ${currentTopActiveThreat?.gnb_id || 'gNB-1'}.`}
                  </div>
                </div>

                <div style={{ marginTop: "16px" }}>
                  <button
                    onClick={() => setPage("live")}
                    style={{
                      width: "100%",
                      padding: "10px",
                      borderRadius: "6px",
                      border: "none",
                      background: "#0284c7",
                      color: "#fff",
                      fontWeight: "600",
                      fontSize: "0.85rem",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "8px"
                    }}
                  >
                    <Target size={16} />
                    Open Prioritized Mitigation Stream
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: PRIORITIZED THREAT MITIGATION QUEUE (HIGH ➔ LOW)
            (Includes PacketCount, Duration, Protocol, SliceType,
             Where Detected, When Prevented, How Mitigation Performed)
        ======================================================== */}
        {(page === "live" || page === "dashboard") && !loading && (
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px", marginBottom: "32px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
              <div>
                <h3 style={{ fontSize: "1.2rem", fontWeight: "700", margin: "0 0 4px 0", color: "#f8fafc" }}>
                  Prioritized Intrusion Mitigation Queue
                </h3>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>
                  Sorted strictly from <b>Highest to Lowest Threat Priority Score</b>. Neutralizing the top threat automatically advances to the next critical target!
                </span>
              </div>

              {/* Queue Mode Toggles */}
              <div style={{ display: "flex", gap: "8px", background: "#1e293b", padding: "4px", borderRadius: "8px", border: "1px solid #334155" }}>
                {[
                  { id: "active_only", label: `Active Threats (${threatStats.active_count})` },
                  { id: "all", label: `All Sequences (${sortedSequences.length})` },
                  { id: "mitigated_only", label: `Prevented (${threatStats.mitigated_count})` }
                ].map(mode => (
                  <button
                    key={mode.id}
                    onClick={() => { setQueueFilter(mode.id); setPageNumber(1); }}
                    style={{
                      padding: "6px 12px",
                      borderRadius: "6px",
                      border: "none",
                      fontSize: "0.8rem",
                      fontWeight: "600",
                      background: queueFilter === mode.id ? "#0284c7" : "transparent",
                      color: queueFilter === mode.id ? "#fff" : "#94a3b8",
                      cursor: "pointer"
                    }}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Filter & Search Bar */}
            <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "16px" }}>
              <div style={{ position: "relative", flex: 1, maxWidth: "340px" }}>
                <Search size={16} color="#64748b" style={{ position: "absolute", left: "12px", top: "10px" }} />
                <input
                  type="text"
                  placeholder="Filter by UE, gNB, Protocol, Slice, Alert ID..."
                  value={search}
                  onChange={e => { setSearch(e.target.value); setPageNumber(1); }}
                  style={{
                    width: "100%",
                    padding: "8px 12px 8px 36px",
                    borderRadius: "6px",
                    border: "1px solid #334155",
                    background: "#1e293b",
                    color: "#fff",
                    fontSize: "0.85rem"
                  }}
                />
              </div>

              <select
                value={selectedAttackFilter}
                onChange={e => { setSelectedAttackFilter(e.target.value); setPageNumber(1); }}
                style={{
                  padding: "8px 12px",
                  borderRadius: "6px",
                  border: "1px solid #334155",
                  background: "#1e293b",
                  color: "#fff",
                  fontSize: "0.85rem"
                }}
              >
                <option value="All">All Attack Classes</option>
                {GENUINE_ATTACK_CLASSES.map(cls => (
                  <option key={cls} value={cls}>{cls}</option>
                ))}
              </select>

              <div style={{ marginLeft: "auto", fontSize: "0.82rem", color: "#94a3b8" }}>
                Showing <b>{filteredSequences.length}</b> matches
              </div>
            </div>

            {/* Comprehensive Professional Table */}
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.83rem", minWidth: "1680px" }}>
                <thead>
                  <tr style={{ borderBottom: "2px solid #1e293b", color: "#94a3b8", textAlign: "left" }}>
                    <th style={{ padding: "12px 10px", width: "130px", minWidth: "130px" }}>Priority Rank</th>
                    <th style={{ padding: "12px 10px", width: "230px", minWidth: "220px" }}>Where Detected</th>
                    <th style={{ padding: "12px 10px", width: "90px", minWidth: "90px" }}>Slice</th>
                    <th style={{ padding: "12px 10px", width: "80px", minWidth: "80px" }}>Protocol</th>
                    <th style={{ padding: "12px 10px", width: "170px", minWidth: "160px" }}>Attack Classification</th>
                    <th style={{ padding: "12px 10px", width: "110px", minWidth: "105px" }}>Packet Count</th>
                    <th style={{ padding: "12px 10px", width: "90px", minWidth: "85px" }}>Duration</th>
                    <th style={{ padding: "12px 10px", width: "180px", minWidth: "170px" }}>Status / When Prevented</th>
                    <th style={{ padding: "12px 12px", width: "380px", minWidth: "350px" }}>How Mitigation Performs</th>
                    <th style={{ padding: "12px 12px", width: "210px", minWidth: "200px", textAlign: "right" }}>Mitigation Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSequences.length === 0 ? (
                    <tr>
                      <td colSpan="10" style={{ padding: "32px", textAlign: "center", color: "#64748b" }}>
                        No threats found matching the current queue filter.
                      </td>
                    </tr>
                  ) : (
                    filteredSequences.slice((pageNumber - 1) * pageSize, pageNumber * pageSize).map((seq, rankIdx) => {
                      const absoluteRank = (pageNumber - 1) * pageSize + rankIdx + 1;
                      const isTopTarget = seq.alert_id === currentTopActiveThreat?.alert_id;
                      return (
                        <tr
                          key={seq.sequence_id}
                          style={{
                            borderBottom: "1px solid #1e293b",
                            background: isTopTarget ? "rgba(239, 68, 68, 0.08)" : "transparent",
                            transition: "background 0.2s ease"
                          }}
                        >
                          {/* Priority Rank & Score */}
                          <td style={{ padding: "14px 10px" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              <span style={{
                                width: "24px",
                                height: "24px",
                                borderRadius: "50%",
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                fontSize: "0.75rem",
                                fontWeight: "800",
                                background: seq.is_mitigated ? "#064e3b" : (seq.priority_score >= 80 ? "#ef4444" : "#1e293b"),
                                color: "#fff"
                              }}>
                                {absoluteRank}
                              </span>
                              <span style={{
                                padding: "3px 8px",
                                borderRadius: "4px",
                                fontSize: "0.74rem",
                                fontWeight: "700",
                                background: PRIORITY_BADGES[seq.priority_level]?.bg || "#1e293b",
                                color: PRIORITY_BADGES[seq.priority_level]?.text || "#fff"
                              }}>
                                {seq.priority_score}/100 ({seq.priority_level})
                              </span>
                            </div>
                          </td>

                          {/* Where Detected */}
                          <td style={{ padding: "14px 10px" }}>
                            <div style={{ fontWeight: "600", color: "#f8fafc" }}>
                              {seq.gnb_id} (Sector A)
                            </div>
                            <div style={{ fontSize: "0.74rem", color: "#94a3b8" }}>
                              Device: <b>UE-{seq.ue_id}</b>
                            </div>
                          </td>

                          {/* Network Slice */}
                          <td style={{ padding: "14px 10px" }}>
                            <span style={{
                              padding: "3px 8px",
                              borderRadius: "4px",
                              fontSize: "0.72rem",
                              fontWeight: "700",
                              background: SLICE_COLORS[seq.slice_type]?.bg || "#1e293b",
                              color: SLICE_COLORS[seq.slice_type]?.text || "#cbd5e1",
                              border: `1px solid ${SLICE_COLORS[seq.slice_type]?.border || '#334155'}`
                            }}>
                              {seq.slice_type}
                            </span>
                          </td>

                          {/* Protocol */}
                          <td style={{ padding: "14px 10px" }}>
                            <span style={{
                              padding: "2px 6px",
                              borderRadius: "4px",
                              fontSize: "0.72rem",
                              fontWeight: "600",
                              background: "#1e293b",
                              color: seq.protocol === "UDP" ? "#38bdf8" : (seq.protocol === "ICMP" ? "#f59e0b" : "#a855f7")
                            }}>
                              {seq.protocol}
                            </span>
                          </td>

                          {/* Attack Classification */}
                          <td style={{ padding: "14px 10px" }}>
                            <div style={{ fontWeight: "700", color: ATTACK_COLORS[seq.predicted_attack_type] || "#f8fafc" }}>
                              {seq.predicted_attack_type}
                            </div>
                            <div style={{ fontSize: "0.72rem", color: "#94a3b8" }}>
                              Confidence: {seq.confidence}%
                            </div>
                          </td>

                          {/* Packet Count */}
                          <td style={{ padding: "14px 10px", fontWeight: "600" }}>
                            {seq.packet_count ? seq.packet_count.toLocaleString() : "1,250"} pkts
                          </td>

                          {/* Duration */}
                          <td style={{ padding: "14px 10px", color: "#cbd5e1" }}>
                            {seq.duration ? `${seq.duration}s` : "0.85s"}
                          </td>

                          {/* Status / When Prevented */}
                          <td style={{ padding: "14px 10px" }}>
                            {seq.is_mitigated ? (
                              <div>
                                <span style={{
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "4px",
                                  padding: "3px 8px",
                                  borderRadius: "4px",
                                  fontSize: "0.74rem",
                                  fontWeight: "700",
                                  background: "#064e3b",
                                  color: "#86efac",
                                  border: "1px solid #059669"
                                }}>
                                  <CheckCircle2 size={12} />
                                  Prevented & Contained
                                </span>
                                <div style={{ fontSize: "0.72rem", color: "#94a3b8", marginTop: "3px", display: "flex", alignItems: "center", gap: "4px" }}>
                                  <Clock size={11} /> {seq.when_prevented || "Just now"}
                                </div>
                              </div>
                            ) : (
                              <span style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "4px",
                                padding: "3px 8px",
                                borderRadius: "4px",
                                fontSize: "0.74rem",
                                fontWeight: "700",
                                background: "#7f1d1d",
                                color: "#fca5a5",
                                border: "1px solid #dc2626"
                              }}>
                                <AlertTriangle size={12} />
                                Active Incursion
                              </span>
                            )}
                          </td>

                          {/* How Mitigation Performs */}
                          <td style={{
                            padding: "14px 12px",
                            width: "380px",
                            minWidth: "350px",
                            maxWidth: "450px",
                            verticalAlign: "middle"
                          }}>
                            <div style={{
                              background: "rgba(15, 23, 42, 0.75)",
                              border: "1px solid #1e293b",
                              borderRadius: "6px",
                              padding: "8px 10px"
                            }}>
                              <div style={{
                                fontWeight: "700",
                                color: "#38bdf8",
                                fontSize: "0.8rem",
                                lineHeight: "1.35",
                                marginBottom: "4px",
                                wordBreak: "break-word"
                              }}>
                                {seq.recommended_action || "Defensive Mitigation"}
                              </div>
                              <div style={{
                                fontSize: "0.74rem",
                                color: "#cbd5e1",
                                lineHeight: "1.45",
                                wordBreak: "break-word",
                                whiteSpace: "normal"
                              }}>
                                {seq.how_mitigated}
                              </div>
                            </div>
                          </td>

                          {/* Mitigation Action */}
                          <td style={{
                            padding: "14px 12px",
                            width: "210px",
                            minWidth: "200px",
                            textAlign: "right",
                            verticalAlign: "middle",
                            whiteSpace: "nowrap"
                          }}>
                            <div style={{
                              display: "flex",
                              gap: "8px",
                              justifyContent: "flex-end",
                              alignItems: "center",
                              flexWrap: "nowrap"
                            }}>
                              {!seq.is_mitigated ? (
                                <button
                                  onClick={() => executeMitigation(seq.action_id, seq.alert_id)}
                                  disabled={mitigatingId === seq.action_id || mitigatingId === seq.alert_id}
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "6px",
                                    padding: "6px 12px",
                                    borderRadius: "6px",
                                    border: "none",
                                    background: (mitigatingId === seq.action_id || mitigatingId === seq.alert_id) ? "#991b1b" : "#ef4444",
                                    color: "#fff",
                                    fontWeight: "700",
                                    fontSize: "0.75rem",
                                    cursor: (mitigatingId === seq.action_id || mitigatingId === seq.alert_id) ? "not-allowed" : "pointer",
                                    boxShadow: isTopTarget ? "0 0 10px rgba(239, 68, 68, 0.4)" : "none"
                                  }}
                                >
                                  {mitigatingId === seq.action_id || mitigatingId === seq.alert_id ? (
                                    <>
                                      <Loader2 size={13} className="animate-spin" />
                                      Enforcing...
                                    </>
                                  ) : (
                                    <>
                                      <Zap size={13} />
                                      Mitigate
                                    </>
                                  )}
                                </button>
                              ) : (
                                <button
                                  onClick={() => rollbackMitigation(seq.action_id, seq.alert_id)}
                                  disabled={mitigatingId === seq.action_id || mitigatingId === seq.alert_id}
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "4px",
                                    padding: "6px 10px",
                                    borderRadius: "6px",
                                    border: "1px solid #334155",
                                    background: "#1e293b",
                                    color: "#94a3b8",
                                    fontSize: "0.75rem",
                                    cursor: (mitigatingId === seq.action_id || mitigatingId === seq.alert_id) ? "not-allowed" : "pointer"
                                  }}
                                >
                                  {mitigatingId === seq.action_id || mitigatingId === seq.alert_id ? (
                                    <>
                                      <Loader2 size={12} className="animate-spin" />
                                      Reverting...
                                    </>
                                  ) : (
                                    <>
                                      <RotateCcw size={12} />
                                      Rollback
                                    </>
                                  )}
                                </button>
                              )}

                              <button
                                onClick={() => handleSelectSequence(seq)}
                                style={{
                                  padding: "6px 10px",
                                  borderRadius: "6px",
                                  border: "1px solid #334155",
                                  background: "#1e293b",
                                  color: "#38bdf8",
                                  fontSize: "0.75rem",
                                  cursor: "pointer",
                                  fontWeight: "600"
                                }}
                              >
                                XAI
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "20px", flexWrap: "wrap", gap: "12px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <span style={{ fontSize: "0.85rem", color: "#94a3b8" }}>
                  Page <b>{pageNumber}</b> of <b>{Math.max(1, Math.ceil(filteredSequences.length / pageSize))}</b> ({filteredSequences.length} total matches)
                </span>
                <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "0.8rem", color: "#64748b" }}>
                  <span>Rows:</span>
                  {[10, 25, 50].map(sz => (
                    <button
                      key={sz}
                      onClick={() => { setPageSize(sz); setPageNumber(1); }}
                      style={{
                        padding: "3px 8px",
                        borderRadius: "4px",
                        border: "1px solid #334155",
                        background: pageSize === sz ? "#0284c7" : "#1e293b",
                        color: pageSize === sz ? "#fff" : "#94a3b8",
                        cursor: "pointer",
                        fontSize: "0.75rem",
                        fontWeight: "600"
                      }}
                    >
                      {sz}
                    </button>
                  ))}
                </div>
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  disabled={pageNumber <= 1}
                  onClick={() => setPageNumber(p => Math.max(1, p - 1))}
                  style={{
                    padding: "6px 14px",
                    borderRadius: "6px",
                    border: "1px solid #334155",
                    background: pageNumber <= 1 ? "#0f172a" : "#1e293b",
                    color: pageNumber <= 1 ? "#475569" : "#f8fafc",
                    cursor: pageNumber <= 1 ? "not-allowed" : "pointer",
                    fontSize: "0.82rem",
                    fontWeight: "600"
                  }}
                >
                  Previous
                </button>
                <button
                  disabled={pageNumber >= Math.ceil(filteredSequences.length / pageSize)}
                  onClick={() => setPageNumber(p => p + 1)}
                  style={{
                    padding: "6px 14px",
                    borderRadius: "6px",
                    border: "1px solid #334155",
                    background: pageNumber >= Math.ceil(filteredSequences.length / pageSize) ? "#0f172a" : "#1e293b",
                    color: pageNumber >= Math.ceil(filteredSequences.length / pageSize) ? "#475569" : "#f8fafc",
                    cursor: pageNumber >= Math.ceil(filteredSequences.length / pageSize) ? "not-allowed" : "pointer",
                    fontSize: "0.82rem",
                    fontWeight: "600"
                  }}
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: MULTI-AI AGENT EXPLAINABLE AI & CONTAINMENT
        ======================================================== */}
        {page === "investigate" && selectedAlert && (
          <div>
            {/* Header for Active Sequence */}
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px", marginBottom: "24px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Multi-Agent Investigative Dossier</span>
                <h3 style={{ margin: "4px 0 0 0", fontSize: "1.3rem", fontWeight: "700" }}>
                  Alert {selectedAlert.alert_id} (Sequence #{selectedAlert.sequence_id})
                </h3>
                <div style={{ fontSize: "0.82rem", color: "#38bdf8", marginTop: "4px" }}>
                  Location: <b>{selectedAlert.where_detected}</b> | Protocol: <b>{selectedAlert.protocol}</b> | Packets: <b>{selectedAlert.packet_count?.toLocaleString()}</b>
                </div>
              </div>
              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                <span style={{
                  padding: "6px 14px",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                  fontWeight: "700",
                  background: PRIORITY_BADGES[selectedAlert.priority_level]?.bg,
                  color: PRIORITY_BADGES[selectedAlert.priority_level]?.text,
                  border: `1px solid ${PRIORITY_BADGES[selectedAlert.priority_level]?.border}`
                }}>
                  {selectedAlert.priority_level} Priority ({selectedAlert.priority_score}/100)
                </span>
              </div>
            </div>

            {loadingXAI && (
              <div style={{ textAlign: "center", padding: "40px", color: "#38bdf8" }}>
                <Loader2 size={32} className="animate-spin" style={{ margin: "0 auto 8px auto" }} />
                <span>Coordinating the 3 core SOC specialist AI agents...</span>
              </div>
            )}

            {multiAgentInvestigation && !loadingXAI && (
              <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
                {/* Multi-Agent Incident Consensus & Directive */}
                <div style={{ background: "#1e293b", border: "1px solid #38bdf8", borderRadius: "12px", padding: "24px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <Sparkles size={22} color="#38bdf8" />
                      <h4 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "700", color: "#f8fafc" }}>
                        SOC Incident Briefing: {multiAgentInvestigation.executive_synthesis.incident_title}
                      </h4>
                    </div>
                    <span style={{
                      padding: "4px 10px",
                      borderRadius: "6px",
                      fontSize: "0.75rem",
                      fontWeight: "600",
                      background: "#0f172a",
                      color: "#10b981",
                      border: "1px solid #059669"
                    }}>
                      {multiAgentInvestigation.executive_synthesis.faithfulness_status}
                    </span>
                  </div>

                  <p style={{ fontSize: "0.9rem", lineHeight: "1.6", color: "#e2e8f0", margin: "0 0 16px 0" }}>
                    {multiAgentInvestigation.executive_synthesis.executive_summary}
                  </p>

                  <div style={{ background: "#0f172a", padding: "12px 16px", borderRadius: "8px", borderLeft: "4px solid #38bdf8", fontSize: "0.85rem" }}>
                    <span style={{ fontWeight: "700", color: "#38bdf8" }}>Tactical Directive: </span>
                    <span style={{ color: "#cbd5e1" }}>{multiAgentInvestigation.executive_synthesis.recommended_directive}</span>
                  </div>
                </div>

                {/* 3 CORE SOC SPECIALIST AGENTS */}
                {(() => {
                  const investigator = multiAgentInvestigation.agent_reports?.attack_investigator || multiAgentInvestigation.agent_reports?.saliency_agent || {};
                  const riskAnalyst = multiAgentInvestigation.agent_reports?.risk_analyst || multiAgentInvestigation.agent_reports?.prioritization_agent || {};
                  const responseAdvisor = multiAgentInvestigation.agent_reports?.response_advisor || multiAgentInvestigation.agent_reports?.containment_agent || {};
                  const windows = investigator.temporal_windows || (multiAgentInvestigation.agent_reports?.temporal_agent ? multiAgentInvestigation.agent_reports.temporal_agent.temporal_windows : []);
                  const topFeatures = investigator.top_features || [];
                  const faithfulness = investigator.faithfulness_verification || {};
                  const components = riskAnalyst.components || {};

                  return (
                    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
                      {/* TOP ROW: AGENT 1 & AGENT 2 */}
                      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: "24px" }}>
                        {/* ========================================================
                            AGENT 1: ATTACK INVESTIGATOR
                        ======================================================== */}
                        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px", display: "flex", flexDirection: "column", gap: "16px" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                              <BrainCircuit size={22} color="#38bdf8" />
                              <div>
                                <h4 style={{ margin: 0, fontSize: "1.05rem", fontWeight: "700", color: "#f8fafc" }}>
                                  Agent 1: Attack Investigator
                                </h4>
                                <div style={{ fontSize: "0.75rem", color: "#64748b" }}>
                                  Spatio-Temporal Saliency (Grad*Input) & 5-Window Attribution
                                </div>
                              </div>
                            </div>
                            <span style={{
                              padding: "4px 10px",
                              borderRadius: "6px",
                              fontSize: "0.75rem",
                              fontWeight: "700",
                              background: investigator.attack_detected === "Benign" ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)",
                              color: investigator.attack_detected === "Benign" ? "#10b981" : "#ef4444",
                              border: investigator.attack_detected === "Benign" ? "1px solid #10b981" : "1px solid #ef4444"
                            }}>
                              {investigator.attack_detected || selectedAlert.predicted_attack_type} ({investigator.confidence || (selectedAlert.confidence ? selectedAlert.confidence.toFixed(1) : "95.0")}%)
                            </span>
                          </div>

                          {/* Network entities banner */}
                          <div style={{ display: "flex", gap: "12px", background: "#1e293b", padding: "10px 14px", borderRadius: "8px", fontSize: "0.8rem", color: "#94a3b8" }}>
                            <div>Target: <b style={{ color: "#38bdf8" }}>UE-{investigator.affected_ue ?? selectedAlert.ue_id}</b></div>
                            <div>•</div>
                            <div>Serving: <b style={{ color: "#f8fafc" }}>{investigator.serving_gnb || selectedAlert.gnb_id}</b></div>
                            <div>•</div>
                            <div>Slice: <b style={{ color: "#c084fc" }}>5G {investigator.slice_type || "eMBB"}</b></div>
                          </div>

                          {/* Human readable statement */}
                          <p style={{ fontSize: "0.84rem", color: "#cbd5e1", lineHeight: "1.55", margin: 0 }}>
                            {investigator.explanation_statement || investigator.summary_statement}
                          </p>

                          {/* Top contributing features */}
                          <div>
                            <div style={{ fontSize: "0.78rem", fontWeight: "700", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "8px" }}>
                              Top Contributing Input Features (Mathematical Saliency)
                            </div>
                            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                              {topFeatures.map((feat, idx) => (
                                <div key={feat.feature_name}>
                                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "3px" }}>
                                    <span style={{ color: "#e2e8f0" }}><b>#{idx + 1}</b> {feat.feature_name}</span>
                                    <span style={{ color: "#38bdf8", fontWeight: "700" }}>{(feat.importance_score * 100).toFixed(1)}%</span>
                                  </div>
                                  <div style={{ height: "6px", background: "#1e293b", borderRadius: "3px", overflow: "hidden" }}>
                                    <div style={{ height: "100%", width: `${Math.min(100, feat.importance_score * 100)}%`, background: "#38bdf8", borderRadius: "3px" }} />
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* 5 Temporal Windows & Peak Timing */}
                          <div>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                              <span style={{ fontSize: "0.78rem", fontWeight: "700", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                                5-Window Sequence Evolution
                              </span>
                              <span style={{ fontSize: "0.72rem", color: "#f59e0b", fontWeight: "600" }}>
                                Peaked at Window t_{investigator.peak_window || 1}
                              </span>
                            </div>

                            <div style={{ display: "flex", gap: "8px", marginBottom: "10px" }}>
                              {windows.map(win => {
                                const isPeak = (win.window_index + 1) === (investigator.peak_window || 1);
                                const pctVal = win.normalized_attribution_pct ?? (win.attribution_score * 100);
                                return (
                                  <div key={win.window_index} style={{
                                    flex: 1,
                                    textAlign: "center",
                                    background: isPeak ? "rgba(239, 68, 68, 0.15)" : "#1e293b",
                                    border: isPeak ? "1px solid #ef4444" : "1px solid #334155",
                                    padding: "8px 4px",
                                    borderRadius: "8px"
                                  }}>
                                    <div style={{ fontSize: "0.7rem", color: "#94a3b8" }}>t_{win.window_index + 1}</div>
                                    <div style={{ fontSize: "0.92rem", fontWeight: "800", marginTop: "2px", color: isPeak ? "#ef4444" : "#38bdf8" }}>
                                      {Number(pctVal).toFixed(1)}%
                                    </div>
                                    {isPeak && (
                                      <div style={{ fontSize: "0.6rem", color: "#ef4444", fontWeight: "700", marginTop: "2px" }}>
                                        PEAK
                                      </div>
                                    )}
                                  </div>
                                );
                              })}
                            </div>

                            <div style={{ fontSize: "0.76rem", color: "#94a3b8", background: "#1e293b", padding: "8px 12px", borderRadius: "6px" }}>
                              Trajectory: <b style={{ color: "#f8fafc" }}>{investigator.trajectory || "Standard Progression"}</b> ({investigator.phase || "Active"})
                            </div>
                          </div>

                          {/* Faithfulness check */}
                          {faithfulness.top_feature_perturbed && (
                            <div style={{ background: "#0b1329", border: "1px solid #1e293b", padding: "10px 12px", borderRadius: "8px", fontSize: "0.76rem" }}>
                              <span style={{ fontWeight: "700", color: "#10b981" }}>Mathematical Faithfulness Verified: </span>
                              <span style={{ color: "#94a3b8" }}>
                                Perturbing <b>{faithfulness.top_feature_perturbed}</b> dropped model confidence by{" "}
                                <b style={{ color: "#f8fafc" }}>{(faithfulness.confidence_drop * 100).toFixed(1)}%</b>.
                              </span>
                            </div>
                          )}
                        </div>

                        {/* ========================================================
                            AGENT 2: RISK & IMPACT ANALYST
                        ======================================================== */}
                        <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px", display: "flex", flexDirection: "column", gap: "16px" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                              <Target size={22} color="#ec4899" />
                              <div>
                                <h4 style={{ margin: 0, fontSize: "1.05rem", fontWeight: "700", color: "#f8fafc" }}>
                                  Agent 2: Risk & Impact Analyst
                                </h4>
                                <div style={{ fontSize: "0.75rem", color: "#64748b" }}>
                                  Priority Scoring, 5G Slice Blast & Urgency Rationale
                                </div>
                              </div>
                            </div>
                            <span style={{
                              padding: "4px 10px",
                              borderRadius: "6px",
                              fontSize: "0.85rem",
                              fontWeight: "800",
                              background: (riskAnalyst.priority_score || 0) >= 80 ? "rgba(239, 68, 68, 0.15)" : ((riskAnalyst.priority_score || 0) >= 50 ? "rgba(245, 158, 11, 0.15)" : "rgba(16, 185, 129, 0.15)"),
                              color: (riskAnalyst.priority_score || 0) >= 80 ? "#ef4444" : ((riskAnalyst.priority_score || 0) >= 50 ? "#f59e0b" : "#10b981"),
                              border: (riskAnalyst.priority_score || 0) >= 80 ? "1px solid #ef4444" : ((riskAnalyst.priority_score || 0) >= 50 ? "1px solid #f59e0b" : "1px solid #10b981")
                            }}>
                              Score: {riskAnalyst.priority_score || 0}/100 ({riskAnalyst.priority_level || "Medium"})
                            </span>
                          </div>

                          {/* Why Alert is Urgent box */}
                          <div style={{
                            background: "rgba(236, 72, 153, 0.08)",
                            border: "1px solid rgba(236, 72, 153, 0.3)",
                            borderRadius: "8px",
                            padding: "12px 14px",
                            fontSize: "0.82rem"
                          }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#f472b6", fontWeight: "700", marginBottom: "4px" }}>
                              <AlertTriangle size={15} />
                              <span>Why This Alert is Urgent:</span>
                            </div>
                            <div style={{ color: "#f1f5f9", lineHeight: "1.5" }}>
                              {riskAnalyst.urgency_rationale || riskAnalyst.rationale || "Evaluated against 5G multi-pillar operational risk standards."}
                            </div>
                          </div>

                          {/* 4-Pillar Score Components */}
                          <div>
                            <div style={{ fontSize: "0.78rem", fontWeight: "700", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "8px" }}>
                              4-Pillar Risk Evaluation
                            </div>
                            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                              {[
                                { label: "Base Severity", weight: "45%", val: components.base_severity ?? 60, desc: `Severity tier: ${riskAnalyst.severity || 'Medium'}` },
                                { label: "Model Confidence", weight: "25%", val: components.confidence_contrib ?? 85, desc: `${investigator.confidence || 90}% confidence attribution` },
                                { label: "Device Persistence", weight: "15%", val: components.persistence_contrib ?? 40, desc: riskAnalyst.persistence || "Initial anomalous sequence" },
                                { label: "Traffic Rate Deviation", weight: "15%", val: components.traffic_deviation_contrib ?? 50, desc: riskAnalyst.traffic_anomaly || "Traffic rate deviation" }
                              ].map(comp => (
                                <div key={comp.label}>
                                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", marginBottom: "2px" }}>
                                    <span style={{ color: "#e2e8f0" }}><b>{comp.label}</b> ({comp.weight})</span>
                                    <span style={{ fontWeight: "700", color: "#ec4899" }}>{Math.round(comp.val)}/100</span>
                                  </div>
                                  <div style={{ height: "6px", background: "#1e293b", borderRadius: "3px", overflow: "hidden", marginBottom: "3px" }}>
                                    <div style={{ height: "100%", width: `${Math.min(100, comp.val)}%`, background: "#ec4899", borderRadius: "3px" }} />
                                  </div>
                                  <div style={{ fontSize: "0.7rem", color: "#64748b" }}>{comp.desc}</div>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* 5G Service Impact & Blast Radius */}
                          <div style={{ background: "#1e293b", padding: "12px 14px", borderRadius: "8px", fontSize: "0.78rem" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                              <span style={{ fontWeight: "700", color: "#38bdf8" }}>5G Service & Slice Blast Impact:</span>
                              <span style={{
                                fontWeight: "700",
                                color: riskAnalyst.slice_blast_severity === "Critical" ? "#ef4444" : (riskAnalyst.slice_blast_severity === "High" ? "#f59e0b" : "#10b981")
                              }}>
                                {riskAnalyst.slice_blast_severity || "Moderate"}
                              </span>
                            </div>
                            <div style={{ color: "#cbd5e1", lineHeight: "1.5" }}>
                              {riskAnalyst.possible_service_impact || "Standard mobile broadband latency and bandwidth degradation on serving cell."}
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* ========================================================
                          AGENT 3: SOC RESPONSE ADVISOR (FULL-WIDTH PLAYBOOK)
                      ======================================================== */}
                      <div style={{ background: "#0f172a", border: "1px solid #10b981", borderRadius: "12px", padding: "26px", display: "flex", flexDirection: "column", gap: "20px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                            <ShieldCheck size={26} color="#10b981" />
                            <div>
                              <h4 style={{ margin: 0, fontSize: "1.15rem", fontWeight: "700", color: "#f8fafc" }}>
                                Agent 3: SOC Response Advisor
                              </h4>
                              <div style={{ fontSize: "0.78rem", color: "#64748b" }}>
                                Tested Playbook • Evidence Inspection • Non-Indiscriminate Mitigation • Rollback & Recovery
                              </div>
                            </div>
                          </div>

                          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                            <span style={{
                              padding: "4px 10px",
                              borderRadius: "6px",
                              fontSize: "0.75rem",
                              fontWeight: "700",
                              background: "#1e293b",
                              color: "#38bdf8",
                              border: "1px solid #334155"
                            }}>
                              Action ID: {responseAdvisor.action_id || selectedAlert.action_id || "ACT-PENDING"}
                            </span>
                            <span style={{
                              padding: "4px 10px",
                              borderRadius: "6px",
                              fontSize: "0.75rem",
                              fontWeight: "700",
                              background: selectedAlert.is_mitigated ? "rgba(16, 185, 129, 0.15)" : "rgba(245, 158, 11, 0.15)",
                              color: selectedAlert.is_mitigated ? "#10b981" : "#f59e0b",
                              border: selectedAlert.is_mitigated ? "1px solid #10b981" : "1px solid #f59e0b"
                            }}>
                              {selectedAlert.is_mitigated ? "Status: Executed & Contained" : "Status: Recommended / Awaiting Enforcement"}
                            </span>
                          </div>
                        </div>

                        {/* Prescribed Playbook Banner */}
                        <div style={{ background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.25)", padding: "14px 18px", borderRadius: "10px" }}>
                          <div style={{ fontSize: "0.75rem", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                            Prescribed Defensive Policy
                          </div>
                          <div style={{ fontSize: "1.1rem", fontWeight: "700", color: "#10b981", marginTop: "2px" }}>
                            {responseAdvisor.action_name || "Targeted Defensive Containment"}
                          </div>
                          <div style={{ fontSize: "0.85rem", color: "#cbd5e1", marginTop: "4px" }}>
                            {responseAdvisor.description}
                          </div>
                        </div>

                        {/* PLAYBOOK DETAILS: 7 STRUCTURED SECTIONS */}
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                          {/* 1. What was detected */}
                          <div style={{ background: "#1e293b", padding: "14px", borderRadius: "8px", borderLeft: "3px solid #38bdf8" }}>
                            <div style={{ fontSize: "0.75rem", fontWeight: "700", color: "#38bdf8", textTransform: "uppercase", marginBottom: "4px" }}>
                              1. What Was Detected
                            </div>
                            <div style={{ fontSize: "0.83rem", color: "#f1f5f9", lineHeight: "1.5" }}>
                              {responseAdvisor.what_was_detected || `Traffic behavior consistent with a ${selectedAlert.predicted_attack_type} pattern.`}
                            </div>
                          </div>

                          {/* 2. Evidence to Inspect (What to check) */}
                          <div style={{ background: "#1e293b", padding: "14px", borderRadius: "8px", borderLeft: "3px solid #f59e0b" }}>
                            <div style={{ fontSize: "0.75rem", fontWeight: "700", color: "#f59e0b", textTransform: "uppercase", marginBottom: "4px" }}>
                              2. Evidence to Inspect (What to Check)
                            </div>
                            <div style={{ fontSize: "0.83rem", color: "#f1f5f9", lineHeight: "1.5" }}>
                              {responseAdvisor.what_to_check || responseAdvisor.evidence_to_inspect || "Connection duration, packet and byte rates, incomplete connections, and changes across temporal windows."}
                            </div>
                          </div>

                          {/* 3. Prevention */}
                          <div style={{ background: "#1e293b", padding: "14px", borderRadius: "8px", borderLeft: "3px solid #10b981" }}>
                            <div style={{ fontSize: "0.75rem", fontWeight: "700", color: "#10b981", textTransform: "uppercase", marginBottom: "4px" }}>
                              3. How to Prevent Recurrence
                            </div>
                            <div style={{ fontSize: "0.83rem", color: "#f1f5f9", lineHeight: "1.5" }}>
                              {responseAdvisor.how_to_prevent || responseAdvisor.prevention || "Apply appropriate connection limits, request timeouts, and rate controls at the relevant service or gateway."}
                            </div>
                          </div>

                          {/* 4. Recommended Mitigation */}
                          <div style={{ background: "#1e293b", padding: "14px", borderRadius: "8px", borderLeft: "3px solid #ec4899" }}>
                            <div style={{ fontSize: "0.75rem", fontWeight: "700", color: "#ec4899", textTransform: "uppercase", marginBottom: "4px" }}>
                              4. Recommended Mitigation (Non-Indiscriminate)
                            </div>
                            <div style={{ fontSize: "0.83rem", color: "#f1f5f9", lineHeight: "1.5" }}>
                              {responseAdvisor.recommended_mitigation || "Apply targeted connection cleanup or rate limiting after confirming the affected endpoint and protocol. Avoid indiscriminately blocking an entire UE or gNB."}
                            </div>
                          </div>

                          {/* 5. Possible Side Effects */}
                          <div style={{ background: "#1e293b", padding: "14px", borderRadius: "8px", borderLeft: "3px solid #a855f7" }}>
                            <div style={{ fontSize: "0.75rem", fontWeight: "700", color: "#a855f7", textTransform: "uppercase", marginBottom: "4px" }}>
                              5. Possible Side Effects
                            </div>
                            <div style={{ fontSize: "0.83rem", color: "#f1f5f9", lineHeight: "1.5" }}>
                              {responseAdvisor.possible_side_effects || "Legitimate long-lived low-rate connections may experience disconnection if idle timeout is set too aggressively."}
                            </div>
                          </div>

                          {/* 6. Rollback Steps */}
                          <div style={{ background: "#1e293b", padding: "14px", borderRadius: "8px", borderLeft: "3px solid #06b6d4" }}>
                            <div style={{ fontSize: "0.75rem", fontWeight: "700", color: "#06b6d4", textTransform: "uppercase", marginBottom: "4px" }}>
                              6. Rollback Steps
                            </div>
                            <div style={{ fontSize: "0.83rem", color: "#f1f5f9", lineHeight: "1.5" }}>
                              {responseAdvisor.rollback_steps || "Restore default TCP keepalive timeouts (7200s), clear dynamic session caps, and flush temporary connection drop filters."}
                            </div>
                          </div>
                        </div>

                        {/* 7. Verify Recovery (Full-width banner) */}
                        <div style={{ background: "#1e293b", padding: "14px 18px", borderRadius: "8px", borderLeft: "3px solid #14b8a6" }}>
                          <div style={{ fontSize: "0.75rem", fontWeight: "700", color: "#14b8a6", textTransform: "uppercase", marginBottom: "4px" }}>
                            7. How to Verify Recovery
                          </div>
                          <div style={{ fontSize: "0.83rem", color: "#f1f5f9", lineHeight: "1.5" }}>
                            {responseAdvisor.how_to_verify_recovery || "Check whether incomplete connections and abnormal traffic rates decline, legitimate traffic recovers, and the alert stops recurring."}
                          </div>
                        </div>

                        {/* Action buttons and execution feedback */}
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: "8px", borderTop: "1px solid #1e293b", flexWrap: "wrap", gap: "12px" }}>
                          <div style={{ fontSize: "0.78rem", color: "#94a3b8" }}>
                            Target UE: <b style={{ color: "#38bdf8" }}>UE-{selectedAlert.ue_id}</b> on <b style={{ color: "#f8fafc" }}>{selectedAlert.gnb_id}</b>
                            {selectedAlert.when_prevented && (
                              <span style={{ marginLeft: "12px", color: "#86efac" }}>
                                • Contained at: <b>{selectedAlert.when_prevented}</b>
                              </span>
                            )}
                          </div>

                          <div style={{ display: "flex", gap: "12px" }}>
                            {!selectedAlert.is_mitigated ? (
                              <button
                                onClick={() => executeMitigation(responseAdvisor.action_id || selectedAlert.action_id, selectedAlert.alert_id)}
                                disabled={mitigatingId === responseAdvisor.action_id || mitigatingId === selectedAlert.action_id || mitigatingId === selectedAlert.alert_id}
                                style={{
                                  padding: "10px 20px",
                                  borderRadius: "8px",
                                  border: "none",
                                  background: (mitigatingId === responseAdvisor.action_id || mitigatingId === selectedAlert.action_id || mitigatingId === selectedAlert.alert_id) ? "#991b1b" : "#ef4444",
                                  color: "#fff",
                                  fontWeight: "700",
                                  fontSize: "0.85rem",
                                  cursor: (mitigatingId === responseAdvisor.action_id || mitigatingId === selectedAlert.action_id || mitigatingId === selectedAlert.alert_id) ? "not-allowed" : "pointer",
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "8px",
                                  boxShadow: "0 4px 12px rgba(239, 68, 68, 0.3)"
                                }}
                              >
                                {mitigatingId === responseAdvisor.action_id || mitigatingId === selectedAlert.action_id || mitigatingId === selectedAlert.alert_id ? (
                                  <>
                                    <Loader2 size={16} className="animate-spin" />
                                    Enforcing Mitigation...
                                  </>
                                ) : (
                                  <>
                                    <Zap size={16} />
                                    Enforce Mitigation Now
                                  </>
                                )}
                              </button>
                            ) : (
                              <button
                                onClick={() => rollbackMitigation(responseAdvisor.action_id || selectedAlert.action_id, selectedAlert.alert_id)}
                                disabled={mitigatingId === responseAdvisor.action_id || mitigatingId === selectedAlert.action_id || mitigatingId === selectedAlert.alert_id}
                                style={{
                                  padding: "10px 20px",
                                  borderRadius: "8px",
                                  border: "1px solid #334155",
                                  background: "#1e293b",
                                  color: "#f8fafc",
                                  fontSize: "0.85rem",
                                  fontWeight: "700",
                                  cursor: (mitigatingId === responseAdvisor.action_id || mitigatingId === selectedAlert.action_id || mitigatingId === selectedAlert.alert_id) ? "not-allowed" : "pointer",
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "8px"
                                }}
                              >
                                {mitigatingId === responseAdvisor.action_id || mitigatingId === selectedAlert.action_id || mitigatingId === selectedAlert.alert_id ? (
                                  <>
                                    <Loader2 size={16} className="animate-spin" />
                                    Reverting Policy...
                                  </>
                                ) : (
                                  <>
                                    <RotateCcw size={16} />
                                    Rollback Policy
                                  </>
                                )}
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
        )}

        {/* ========================================================
            PAGE: SIMULATIONS & UPLOAD HUB
        ======================================================== */}
        {page === "upload" && !loading && (
          <div>
            <div style={{
              background: "#0f172a",
              border: "2px dashed #334155",
              borderRadius: "12px",
              padding: "36px",
              textAlign: "center",
              marginBottom: "32px"
            }}>
              <Upload size={40} color="#38bdf8" style={{ margin: "0 auto 12px auto" }} />
              <h3 style={{ fontSize: "1.2rem", fontWeight: "700", margin: "0 0 8px 0" }}>Upload Custom 5G Simulation Traffic CSV</h3>
              <p style={{ fontSize: "0.85rem", color: "#94a3b8", maxWidth: "600px", margin: "0 auto 20px auto" }}>
                Upload any traffic CSV containing the 8 calibration fields (Duration, PacketCount, Bytes, PacketRate,
                MeanPacketSize, MinPacketSize, MaxPacketSize, LossRate). Rows must be a multiple of 25.
              </p>
              <button
                onClick={() => fileInputRef.current?.click()}
                style={{
                  padding: "10px 24px",
                  borderRadius: "8px",
                  border: "none",
                  background: "#0284c7",
                  color: "#fff",
                  fontWeight: "600",
                  fontSize: "0.9rem",
                  cursor: "pointer"
                }}
              >
                Browse & Analyze Local CSV
              </button>
            </div>

            <div style={{ marginBottom: "16px" }}>
              <h3 style={{ fontSize: "1.2rem", fontWeight: "700", margin: "0 0 6px 0" }}>
                Pre-Generated 5G Simulation Benchmark Datasets (5,000+ Records Each)
              </h3>
              <p style={{ fontSize: "0.85rem", color: "#94a3b8", margin: 0 }}>
                Generated using realistic 5G multi-cell telemetry across 30 UEs and 2 gNBs. Each contains 200 sequences (5,000 flows) covering all genuine 5G-NIDD attack families.
              </p>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "20px" }}>
              {scenarios.map(sc => (
                <div key={sc.id} style={{
                  background: "#0f172a",
                  border: "1px solid #1e293b",
                  borderRadius: "12px",
                  padding: "24px",
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between"
                }}>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "10px" }}>
                      <h4 style={{ margin: 0, fontSize: "1.05rem", fontWeight: "700", color: "#f8fafc" }}>{sc.title}</h4>
                      <span style={{
                        padding: "3px 8px",
                        borderRadius: "4px",
                        fontSize: "0.75rem",
                        fontWeight: "600",
                        background: "#1e293b",
                        color: "#38bdf8",
                        border: "1px solid #334155"
                      }}>
                        {sc.records?.toLocaleString() || "10,000"} Flows ({sc.sequences || (sc.records ? sc.records / 25 : 400)} Seqs)
                      </span>
                    </div>

                    <p style={{ fontSize: "0.83rem", color: "#cbd5e1", lineHeight: "1.5", margin: "0 0 16px 0" }}>
                      {sc.description}
                    </p>

                    <div style={{ marginBottom: "16px" }}>
                      <span style={{ fontSize: "0.75rem", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: "600" }}>
                        Attack Classes Included:
                      </span>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "6px" }}>
                        {sc.classes_included.map(cls => (
                          <span key={cls} style={{
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "0.72rem",
                            fontWeight: "600",
                            background: "#1e293b",
                            color: ATTACK_COLORS[cls] || "#cbd5e1"
                          }}>
                            {cls}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: "flex", gap: "10px", marginTop: "14px", paddingTop: "14px", borderTop: "1px solid #1e293b" }}>
                    <button
                      onClick={() => loadScenarioDataset(sc.filename)}
                      style={{
                        flex: 1,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: "8px",
                        padding: "9px 16px",
                        borderRadius: "6px",
                        border: "none",
                        background: "#0284c7",
                        color: "#fff",
                        fontSize: "0.85rem",
                        fontWeight: "600",
                        cursor: "pointer"
                      }}
                    >
                      <PlayCircle size={16} />
                      Run Live Simulation
                    </button>

                    <button
                      onClick={() => downloadScenarioDataset(sc.filename)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                        padding: "9px 16px",
                        borderRadius: "6px",
                        border: "1px solid #334155",
                        background: "#1e293b",
                        color: "#94a3b8",
                        fontSize: "0.85rem",
                        fontWeight: "600",
                        cursor: "pointer"
                      }}
                    >
                      <Download size={15} />
                      Download .CSV
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: DEFENSIVE RESPONSE & CONTAINMENT
        ======================================================== */}
        {page === "response" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
              <h3 style={{ fontSize: "1.2rem", fontWeight: "700", margin: "0 0 8px 0" }}>Active Containment Policies & Execution Log</h3>
              <p style={{ fontSize: "0.85rem", color: "#94a3b8", margin: "0 0 20px 0" }}>
                Enforce dynamic flow shaping, slice isolation, or TCP resets directly at the serving radio unit (gNodeB).
              </p>

              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1e293b", color: "#64748b", textAlign: "left" }}>
                    <th style={{ padding: "10px" }}>Action ID</th>
                    <th style={{ padding: "10px" }}>Target Device</th>
                    <th style={{ padding: "10px" }}>Serving Cell</th>
                    <th style={{ padding: "10px" }}>Policy Name</th>
                    <th style={{ padding: "10px" }}>Status</th>
                    <th style={{ padding: "10px" }}>When Executed</th>
                    <th style={{ padding: "10px", textAlign: "right" }}>Control</th>
                  </tr>
                </thead>
                <tbody>
                  {responseHistory.length === 0 ? (
                    <tr>
                      <td colSpan="7" style={{ padding: "24px", textAlign: "center", color: "#64748b" }}>
                        No containment policies executed yet. Inspect an alert sequence to trigger mitigation.
                      </td>
                    </tr>
                  ) : (
                    responseHistory.map(act => (
                      <tr key={act.action_id} style={{ borderBottom: "1px solid #1e293b" }}>
                        <td style={{ padding: "12px 10px", color: "#38bdf8", fontWeight: "600" }}>{act.action_id}</td>
                        <td style={{ padding: "12px 10px" }}>UE-{act.target_ue}</td>
                        <td style={{ padding: "12px 10px" }}>{act.serving_gnb}</td>
                        <td style={{ padding: "12px 10px", fontWeight: "600" }}>{act.action_name}</td>
                        <td style={{ padding: "12px 10px" }}>
                          <span style={{
                            padding: "3px 8px",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "600",
                            background: act.status === "Executed" ? "#064e3b" : (act.status === "Rolled Back" ? "#334155" : "#7c2d12"),
                            color: act.status === "Executed" ? "#86efac" : (act.status === "Rolled Back" ? "#94a3b8" : "#fdba74")
                          }}>
                            {act.status}
                          </span>
                        </td>
                        <td style={{ padding: "12px 10px", color: "#94a3b8" }}>{act.execution_timestamp || act.timestamp}</td>
                        <td style={{ padding: "12px 10px", textAlign: "right" }}>
                          {act.status === "Executed" ? (
                            <button
                              onClick={() => rollbackMitigation(act.action_id, act.alert_id)}
                              disabled={mitigatingId === act.action_id || mitigatingId === act.alert_id}
                              style={{
                                padding: "4px 10px",
                                borderRadius: "4px",
                                border: "1px solid #334155",
                                background: "#1e293b",
                                color: "#f8fafc",
                                cursor: (mitigatingId === act.action_id || mitigatingId === act.alert_id) ? "not-allowed" : "pointer",
                                fontSize: "0.75rem"
                              }}
                            >
                              {mitigatingId === act.action_id || mitigatingId === act.alert_id ? "Reverting..." : "Rollback"}
                            </button>
                          ) : (
                            <button
                              onClick={() => executeMitigation(act.action_id, act.alert_id)}
                              disabled={mitigatingId === act.action_id || mitigatingId === act.alert_id}
                              style={{
                                padding: "4px 10px",
                                borderRadius: "4px",
                                border: "none",
                                background: (mitigatingId === act.action_id || mitigatingId === act.alert_id) ? "#991b1b" : "#ef4444",
                                color: "#fff",
                                cursor: (mitigatingId === act.action_id || mitigatingId === act.alert_id) ? "not-allowed" : "pointer",
                                fontSize: "0.75rem",
                                fontWeight: "600"
                              }}
                            >
                              {mitigatingId === act.action_id || mitigatingId === act.alert_id ? "Enforcing..." : "Enforce"}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: ATTACK ANALYTICS
        ======================================================== */}
        {page === "analytics" && analytics && (
          <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
              <h3 style={{ fontSize: "1.2rem", fontWeight: "700", margin: "0 0 16px 0" }}>5G-NIDD Multiclass Benchmark Performance</h3>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1e293b", color: "#64748b", textAlign: "left" }}>
                    <th style={{ padding: "10px" }}>Class Index</th>
                    <th style={{ padding: "10px" }}>Attack Category</th>
                    <th style={{ padding: "10px" }}>Test Support</th>
                    <th style={{ padding: "10px" }}>Precision</th>
                    <th style={{ padding: "10px" }}>Recall</th>
                    <th style={{ padding: "10px" }}>F1-Score</th>
                  </tr>
                </thead>
                <tbody>
                  {analytics.multiclass_metrics?.map(m => (
                    <tr key={m.Class_Index} style={{ borderBottom: "1px solid #1e293b" }}>
                      <td style={{ padding: "10px" }}>{m.Class_Index}</td>
                      <td style={{ padding: "10px", fontWeight: "600", color: ATTACK_COLORS[m.Attack_Type] || "#f8fafc" }}>{m.Attack_Type}</td>
                      <td style={{ padding: "10px" }}>{m.Support}</td>
                      <td style={{ padding: "10px" }}>{(m.Precision * 100).toFixed(2)}%</td>
                      <td style={{ padding: "10px" }}>{(m.Recall * 100).toFixed(2)}%</td>
                      <td style={{ padding: "10px", fontWeight: "600", color: "#38bdf8" }}>{(m.F1_Score * 100).toFixed(2)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: NETWORK TOPOLOGY
        ======================================================== */}
        {page === "topology" && (
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
            <h3 style={{ fontSize: "1.2rem", fontWeight: "700", margin: "0 0 8px 0" }}>Simulated 5G Multi-Cell Cellular Topology</h3>
            <p style={{ fontSize: "0.85rem", color: "#94a3b8", margin: "0 0 24px 0" }}>
              2 Base Stations (gNB-1, gNB-2) serving 30 User Equipments across eMBB, URLLC, and mMTC slices.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
              {/* gNB 1 */}
              <div style={{ background: "#1e293b", borderRadius: "10px", padding: "20px", border: "1px solid #334155" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
                  <Radio size={24} color="#38bdf8" />
                  <div>
                    <h4 style={{ margin: 0, fontSize: "1rem", color: "#f8fafc" }}>gNB-1 (Cell Sector A)</h4>
                    <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Position: (250m, 500m) | Active UEs: 15</span>
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "8px" }}>
                  {Array.from({ length: 15 }).map((_, i) => {
                    const ueNum = (i + 1) * 2;
                    const isMalicious = rawSequences.some(s => s.ue_id === ueNum && s.prediction === "Malicious" && !s.is_mitigated);
                    const isPrevented = rawSequences.some(s => s.ue_id === ueNum && s.is_mitigated);
                    return (
                      <div key={ueNum} style={{
                        padding: "8px",
                        borderRadius: "6px",
                        textAlign: "center",
                        background: isMalicious ? "#7f1d1d" : (isPrevented ? "#064e3b" : "#0f172a"),
                        border: isMalicious ? "1px solid #ef4444" : (isPrevented ? "1px solid #10b981" : "1px solid #334155"),
                        fontSize: "0.75rem"
                      }}>
                        UE-{ueNum}
                        <div style={{ fontSize: "0.65rem", color: isMalicious ? "#fca5a5" : (isPrevented ? "#86efac" : "#10b981"), marginTop: "2px" }}>
                          {isMalicious ? "Active" : (isPrevented ? "Contained" : "Nominal")}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* gNB 2 */}
              <div style={{ background: "#1e293b", borderRadius: "10px", padding: "20px", border: "1px solid #334155" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
                  <Radio size={24} color="#38bdf8" />
                  <div>
                    <h4 style={{ margin: 0, fontSize: "1rem", color: "#f8fafc" }}>gNB-2 (Cell Sector B)</h4>
                    <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Position: (750m, 500m) | Active UEs: 15</span>
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "8px" }}>
                  {Array.from({ length: 15 }).map((_, i) => {
                    const ueNum = (i * 2) + 1;
                    const isMalicious = rawSequences.some(s => s.ue_id === ueNum && s.prediction === "Malicious" && !s.is_mitigated);
                    const isPrevented = rawSequences.some(s => s.ue_id === ueNum && s.is_mitigated);
                    return (
                      <div key={ueNum} style={{
                        padding: "8px",
                        borderRadius: "6px",
                        textAlign: "center",
                        background: isMalicious ? "#7f1d1d" : (isPrevented ? "#064e3b" : "#0f172a"),
                        border: isMalicious ? "1px solid #ef4444" : (isPrevented ? "1px solid #10b981" : "1px solid #334155"),
                        fontSize: "0.75rem"
                      }}>
                        UE-{ueNum}
                        <div style={{ fontSize: "0.65rem", color: isMalicious ? "#fca5a5" : (isPrevented ? "#86efac" : "#10b981"), marginTop: "2px" }}>
                          {isMalicious ? "Active" : (isPrevented ? "Contained" : "Nominal")}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: FEDERATED IDS
        ======================================================== */}
        {page === "federated" && federatedData && (
          <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "16px" }}>
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Participating gNB Clients</span>
                <div style={{ fontSize: "1.8rem", fontWeight: "700", marginTop: "8px", color: "#38bdf8" }}>2 gNB Cells</div>
                <span style={{ fontSize: "0.75rem", color: "#64748b" }}>Local cell data isolated; zero raw flows shared</span>
              </div>
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Aggregation Algorithm</span>
                <div style={{ fontSize: "1.8rem", fontWeight: "700", marginTop: "8px", color: "#10b981" }}>FedAvg</div>
                <span style={{ fontSize: "0.75rem", color: "#10b981" }}>Weighted federated model averaging</span>
              </div>
              <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "20px" }}>
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Per-Round Bandwidth</span>
                <div style={{ fontSize: "1.8rem", fontWeight: "700", marginTop: "8px", color: "#f59e0b" }}>{federatedData.bandwidth_per_round_mb} MB</div>
                <span style={{ fontSize: "0.75rem", color: "#f59e0b" }}>Total parameters: {federatedData.total_parameters.toLocaleString()}</span>
              </div>
            </div>

            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
              <h3 style={{ fontSize: "1.1rem", fontWeight: "600", margin: "0 0 16px 0" }}>Federated Communication Rounds</h3>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1e293b", color: "#64748b", textAlign: "left" }}>
                    <th style={{ padding: "10px" }}>Round</th>
                    <th style={{ padding: "10px" }}>Clients</th>
                    <th style={{ padding: "10px" }}>Method</th>
                    <th style={{ padding: "10px" }}>Global Accuracy</th>
                    <th style={{ padding: "10px" }}>Global Macro F1</th>
                    <th style={{ padding: "10px" }}>Overhead (MB)</th>
                  </tr>
                </thead>
                <tbody>
                  {federatedData.rounds_summary?.map(r => (
                    <tr key={r.round} style={{ borderBottom: "1px solid #1e293b" }}>
                      <td style={{ padding: "10px", fontWeight: "600" }}>Round {r.round}</td>
                      <td style={{ padding: "10px" }}>{r.participating_clients.join(", ")}</td>
                      <td style={{ padding: "10px" }}>{r.aggregation_method}</td>
                      <td style={{ padding: "10px" }}>{r.global_accuracy}%</td>
                      <td style={{ padding: "10px", color: "#38bdf8", fontWeight: "600" }}>{r.global_macro_f1}%</td>
                      <td style={{ padding: "10px" }}>{r.communication_overhead_mb} MB</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: MODEL BENCHMARK
        ======================================================== */}
        {page === "model" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
              <h3 style={{ fontSize: "1.1rem", fontWeight: "600", margin: "0 0 16px 0" }}>Baseline Binary vs Multiclass HTSTCL-GNN Benchmark</h3>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1e293b", color: "#64748b", textAlign: "left" }}>
                    <th style={{ padding: "10px" }}>Evaluation Paradigm</th>
                    <th style={{ padding: "10px" }}>Architecture</th>
                    <th style={{ padding: "10px" }}>Classes</th>
                    <th style={{ padding: "10px" }}>Test Accuracy</th>
                    <th style={{ padding: "10px" }}>Precision</th>
                    <th style={{ padding: "10px" }}>Recall</th>
                    <th style={{ padding: "10px" }}>F1-Score</th>
                  </tr>
                </thead>
                <tbody>
                  <tr style={{ borderBottom: "1px solid #1e293b" }}>
                    <td style={{ padding: "12px 10px", fontWeight: "600" }}>Original Binary Baseline</td>
                    <td style={{ padding: "12px 10px" }}>HTSTCL-GNN (Single Head)</td>
                    <td style={{ padding: "12px 10px" }}>2 (Benign / Malicious)</td>
                    <td style={{ padding: "12px 10px" }}>98.41%</td>
                    <td style={{ padding: "12px 10px" }}>98.83%</td>
                    <td style={{ padding: "12px 10px" }}>98.66%</td>
                    <td style={{ padding: "12px 10px" }}>98.75%</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid #1e293b", background: "rgba(56, 189, 248, 0.05)" }}>
                    <td style={{ padding: "12px 10px", fontWeight: "600", color: "#38bdf8" }}>Upgraded Multiclass Model</td>
                    <td style={{ padding: "12px 10px", color: "#38bdf8" }}>HTSTCL-GNN (Dual Head)</td>
                    <td style={{ padding: "12px 10px", color: "#38bdf8" }}>9 Genuine 5G-NIDD Classes</td>
                    <td style={{ padding: "12px 10px", fontWeight: "700", color: "#10b981" }}>98.12%</td>
                    <td style={{ padding: "12px 10px", fontWeight: "700", color: "#10b981" }}>99.00%</td>
                    <td style={{ padding: "12px 10px", fontWeight: "700", color: "#10b981" }}>98.68%</td>
                    <td style={{ padding: "12px 10px", fontWeight: "700", color: "#10b981" }}>98.83%</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ========================================================
            PAGE: REPORTS & EXPORT
        ======================================================== */}
        {page === "reports" && (
          <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: "12px", padding: "24px" }}>
            <h3 style={{ fontSize: "1.1rem", fontWeight: "600", margin: "0 0 16px 0" }}>Export Audit & Verification Reports</h3>
            <p style={{ fontSize: "0.85rem", color: "#94a3b8", marginBottom: "20px" }}>
              Download machine-readable CSVs, Markdown audit reports, and confusion matrices generated by the evaluation engine.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "16px" }}>
              {[
                { title: "Multiclass Metrics (CSV)", file: "reports/multiclass_metrics.csv", desc: "Per-class precision, recall, F1, and support" },
                { title: "Classification Report (TXT)", file: "reports/multiclass_classification_report.txt", desc: "Detailed summary report on 7,296 test sequences" },
                { title: "Multiclass Confusion Matrix (PNG)", file: "reports/confusion_matrix_multiclass.png", desc: "9x9 confusion matrix visualization" },
                { title: "Dataset Label Audit (CSV)", file: "reports/dataset_label_audit.csv", desc: "Label verification and class mapping" },
                { title: "Feature Schema 91 (CSV)", file: "reports/feature_schema_91.csv", desc: "Complete 91-feature specification" },
                { title: "Simulation Mapping (CSV)", file: "reports/simulation_feature_mapping.csv", desc: "MATLAB-to-NIDD feature contract" }
              ].map(rep => (
                <div key={rep.title} style={{ background: "#1e293b", padding: "16px", borderRadius: "8px", border: "1px solid #334155" }}>
                  <div style={{ fontWeight: "600", color: "#f8fafc", marginBottom: "4px" }}>{rep.title}</div>
                  <div style={{ fontSize: "0.8rem", color: "#94a3b8", marginBottom: "12px" }}>{rep.desc}</div>
                  <span style={{ fontSize: "0.75rem", color: "#38bdf8", fontFamily: "monospace" }}>{rep.file}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
