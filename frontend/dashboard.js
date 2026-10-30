/**
 * dashboard.js — Real-time Dashboard Controller
 * ===============================================
 * Polls the Flask REST API every 2 seconds and updates:
 *  - KPI counters
 *  - Live traffic chart (Chart.js)
 *  - Detection event feed
 *  - Alert panel
 *  - Mitigation log
 *  - System status
 *  - Model info (loaded once)
 */

"use strict";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
// If opened directly from disk (file://) or via an alternative dev server (e.g. port 5500),
// point API calls to the Flask backend running on port 5000.
const API_BASE = (window.location.protocol === "file:" || (window.location.port !== "5000" && window.location.port !== ""))
  ? "http://localhost:5000"
  : "";

const POLL_INTERVAL = 2000;        // ms between polls
const MAX_FEED_ROWS = 40;          // max rows in detection table
const MAX_CHART_PTS = 60;          // data points on chart (~2 min)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let trafficChart       = null;
let feedPaused         = false;
let activeAttack       = null;
let modelInfoLoaded    = false;
let consecutiveErrors  = 0;

// Chart dataset arrays
const chartLabels = [];
const chartTotal  = [];
const chartAttack = [];

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------
function formatTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

function formatConf(v) {
  return (parseFloat(v) * 100).toFixed(0) + "%";
}

function animateCount(el, target) {
  const current = parseInt(el.textContent.replace(/,/g, "")) || 0;
  if (current === target) return;
  const step = Math.ceil(Math.abs(target - current) / 8);
  const next  = current < target ? Math.min(current + step, target)
                                 : Math.max(current - step, target);
  el.textContent = next.toLocaleString();
  if (next !== target) requestAnimationFrame(() => animateCount(el, target));
}

function labelClass(label) {
  const map = {
    normal: "label-normal",
    syn_flood: "label-syn_flood",
    udp_flood: "label-udp_flood",
    http_flood: "label-http_flood",
    icmp_flood: "label-icmp_flood",
    slowloris: "label-slowloris",
    unknown: "label-unknown",
  };
  return map[label] || "label-unknown";
}

// ---------------------------------------------------------------------------
// Chart.js setup
// ---------------------------------------------------------------------------
function initChart() {
  if (typeof Chart === "undefined") {
    console.warn("Chart.js is not loaded yet. Skipping chart initialization.");
    return;
  }
  try {
    const canvas = document.getElementById("traffic-chart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    trafficChart = new Chart(ctx, {
      type: "line",
      data: {
        labels: chartLabels,
        datasets: [
          {
            label: "Total pkt/s",
            data: chartTotal,
            borderColor: "rgba(56,189,248,0.85)",
            backgroundColor: "rgba(56,189,248,0.06)",
            borderWidth: 2,
            pointRadius: 0,
            fill: true,
            tension: 0.35,
          },
          {
            label: "Attack pkt/s",
            data: chartAttack,
            borderColor: "rgba(248,113,113,0.85)",
            backgroundColor: "rgba(248,113,113,0.06)",
            borderWidth: 2,
            pointRadius: 0,
            fill: true,
            tension: 0.35,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(9,14,26,0.95)",
            borderColor: "rgba(99,179,237,0.2)",
            borderWidth: 1,
            titleColor: "#e2e8f0",
            bodyColor: "#94a3b8",
          },
        },
        scales: {
          x: {
            grid: { color: "rgba(255,255,255,0.04)" },
            ticks: { color: "#475569", maxTicksLimit: 8, font: { size: 10 } },
          },
          y: {
            grid: { color: "rgba(255,255,255,0.04)" },
            ticks: { color: "#475569", font: { size: 10 } },
            beginAtZero: true,
          },
        },
      },
    });
  } catch (err) {
    console.error("Failed to initialize Chart.js:", err);
  }
}

function updateChart(history) {
  if (!trafficChart || !history || history.length === 0) return;

  // Replace chart data with last MAX_CHART_PTS points
  const slice = history.slice(-MAX_CHART_PTS);

  chartLabels.length  = 0;
  chartTotal.length   = 0;
  chartAttack.length  = 0;

  for (const pt of slice) {
    chartLabels.push(formatTime(pt.time));
    chartTotal.push(pt.pkt_rate);
    chartAttack.push(pt.attack_rate);
  }

  trafficChart.update();
}

// ---------------------------------------------------------------------------
// Status & Connection Handling
// ---------------------------------------------------------------------------
function setConnectionState(connected, errorMsg = "") {
  const dot = document.getElementById("status-dot");
  const txt = document.getElementById("status-text");
  const banner = document.getElementById("connection-banner");
  const bannerMsg = document.getElementById("connection-banner-msg");

  if (connected) {
    if (dot) dot.className = "status-dot running";
    if (txt) txt.textContent = "Running — Safe Simulation";
    if (banner) banner.style.display = "none";
  } else {
    if (dot) dot.className = "status-dot error";
    if (txt) txt.textContent = "Offline / Disconnected";
    if (banner) {
      banner.style.display = "flex";
      if (bannerMsg && errorMsg) bannerMsg.innerHTML = errorMsg;
    }
  }
}

function updateStatus(data) {
  setConnectionState(true);
  const up = document.getElementById("uptime-value");
  if (up) {
    const sec = Math.floor(data.uptime_sec || 0);
    const m   = String(Math.floor(sec / 60)).padStart(2, "0");
    const s   = String(sec % 60).padStart(2, "0");
    up.textContent = `${m}:${s}`;
  }
}

// ---------------------------------------------------------------------------
// KPI counters
// ---------------------------------------------------------------------------
function updateKPIs(trafficData, mitStats) {
  const cur = trafficData.current || {};
  animateCount(document.getElementById("kpi-packets-val"), cur.total_packets || 0);
  animateCount(document.getElementById("kpi-attacks-val"), cur.total_attacks || 0);
  animateCount(document.getElementById("kpi-anomalies-val"), cur.total_anomalies || 0);
  animateCount(document.getElementById("kpi-blocked-val"), mitStats.currently_blocked || 0);
}

// ---------------------------------------------------------------------------
// Detection feed
// ---------------------------------------------------------------------------
function updateFeed(events) {
  if (feedPaused) return;

  const tbody = document.getElementById("feed-tbody");
  if (!events || events.length === 0) return;

  // Remove empty-state row
  const emptyRow = tbody.querySelector("td[colspan]");
  if (emptyRow) emptyRow.closest("tr").remove();

  // Prepend new rows (events are newest-first from API)
  for (const e of events.slice(0, 8)) {
    const tr  = document.createElement("tr");
    tr.className = "row-new";

    const anomalyText = e.is_anomaly
      ? `<span style="color:var(--neon-purple)">⚠ ${(e.anomaly_score * 100).toFixed(0)}%</span>`
      : `<span style="color:var(--text-muted)">${(e.anomaly_score * 100).toFixed(0)}%</span>`;

    const actionCls = `action-${e.action || "none"}`;
    const actionText = e.action === "IP_BLOCK"   ? "🚫 Blocked"
                     : e.action === "RATE_LIMIT"  ? "⚡ Rate Ltd"
                     : "–";

    tr.innerHTML = `
      <td>${formatTime(e.timestamp)}</td>
      <td>${e.src_ip || "–"}</td>
      <td><span class="label-badge ${labelClass(e.ml_label)}">${e.ml_label || "?"}</span></td>
      <td>${formatConf(e.confidence)}</td>
      <td>${anomalyText}</td>
      <td class="${actionCls}">${actionText}</td>
    `;
    tbody.prepend(tr);
  }

  // Trim to max rows
  while (tbody.rows.length > MAX_FEED_ROWS) {
    tbody.deleteRow(tbody.rows.length - 1);
  }
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
function updateAlerts(alerts) {
  const list  = document.getElementById("alert-list");
  const badge = document.getElementById("alert-count-badge");
  badge.textContent = alerts.length;

  if (!alerts || alerts.length === 0) {
    list.innerHTML = '<div class="empty-state">No alerts — traffic looks normal</div>';
    return;
  }

  list.innerHTML = "";
  for (const a of alerts.slice(0, 10)) {
    const div = document.createElement("div");
    div.className = `alert-item severity-${a.severity}`;
    div.innerHTML = `
      <div class="alert-header">
        <span class="alert-severity ${a.severity}">${a.severity}</span>
        <span class="alert-time">${formatTime(a.timestamp)}</span>
      </div>
      <div class="alert-detail">
        <span class="label-badge ${labelClass(a.ml_label)}">${a.ml_label}</span>
        &nbsp;from <strong>${a.src_ip}</strong>
        &nbsp;· Conf: ${formatConf(a.confidence)}
        &nbsp;· Anomaly: ${(a.anomaly_score * 100).toFixed(0)}%
        &nbsp;· Action: <strong>${a.action || "none"}</strong>
      </div>
    `;
    list.appendChild(div);
  }
}

// ---------------------------------------------------------------------------
// Mitigation log
// ---------------------------------------------------------------------------
function updateMitigation(mitData) {
  const stats = mitData.stats || {};
  document.getElementById("mit-blocked-count").textContent = stats.currently_blocked || 0;
  document.getElementById("mit-rate-count").textContent    = stats.currently_rate_limited || 0;
  document.getElementById("mit-action-count").textContent  = stats.total_actions || 0;

  const logEl = document.getElementById("mitigation-log-list");
  const log   = mitData.action_log || [];

  if (log.length === 0) {
    logEl.innerHTML = '<div class="empty-state">No mitigation actions yet…</div>';
    return;
  }

  logEl.innerHTML = "";
  for (const entry of log.slice(0, 15)) {
    const div = document.createElement("div");
    div.className = `mit-log-item action-${entry.action}`;
    div.innerHTML = `
      <div>
        <span class="mit-log-time">${formatTime(entry.timestamp)}</span>
        &nbsp;
        <span class="mit-log-label">${entry.action}</span>
        &nbsp;IP:&nbsp;<span class="mit-log-ip">${entry.src_ip}</span>
      </div>
      <div class="mit-log-note">${entry.reason || ""}</div>
    `;
    logEl.appendChild(div);
  }
}

// ---------------------------------------------------------------------------
// Model info (loaded once)
// ---------------------------------------------------------------------------
function updateModelInfo(status) {
  if (modelInfoLoaded) return;
  const ml  = status.ml_model || {};
  const iso = status.anomaly_model || {};

  const rfFC = document.getElementById("rf-feature-count");
  if (rfFC && ml.features) rfFC.textContent = `${ml.features.length} features`;

  const rfCl = document.getElementById("rf-classes");
  if (rfCl && ml.classes) rfCl.textContent = ml.classes.join(", ");

  const isoT = document.getElementById("iso-threshold");
  if (isoT) isoT.textContent = iso.threshold ?? "–";

  modelInfoLoaded = true;
}

// ---------------------------------------------------------------------------
// Main poll cycle
// ---------------------------------------------------------------------------
async function safeFetch(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch (err) {
    console.warn(`Fetch failed for ${url}:`, err.message);
    return null;
  }
}

async function pollAll() {
  const [status, traffic, events, alerts, mitigation] = await Promise.all([
    safeFetch(`${API_BASE}/api/status`),
    safeFetch(`${API_BASE}/api/traffic`),
    safeFetch(`${API_BASE}/api/events?limit=50`),
    safeFetch(`${API_BASE}/api/alerts?limit=20`),
    safeFetch(`${API_BASE}/api/mitigation`),
  ]);

  if (status) {
    consecutiveErrors = 0;
    updateStatus(status);
    updateModelInfo(status);
  } else {
    consecutiveErrors++;
    if (consecutiveErrors >= 2) {
      const isFile = window.location.protocol === "file:";
      const msg = isFile
        ? `⚠️ <strong>Opened directly as a local file (file://):</strong> The DDoS detection system requires the Flask backend server. Run <code>python backend/app.py</code> in your terminal and open <a href="http://localhost:5000" target="_blank">http://localhost:5000</a>.`
        : `⚠️ <strong>Backend Unreachable:</strong> Flask server is not responding at <code>${API_BASE || 'http://localhost:5000'}</code>. Make sure <code>python backend/app.py</code> is running in your terminal.`;
      setConnectionState(false, msg);
    }
  }

  if (traffic)    { updateKPIs(traffic, (mitigation?.stats || {})); updateChart(traffic.history); }
  if (events)     { updateFeed(events); }
  if (alerts)     { updateAlerts(alerts); }
  if (mitigation) { updateMitigation(mitigation); }
}

// ---------------------------------------------------------------------------
// Demo controls
// ---------------------------------------------------------------------------
async function triggerAttack(type) {
  try {
    await fetch(`${API_BASE}/api/simulate/attack`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ type }),
    });
    activeAttack = type;

    // Update button styles
    document.querySelectorAll(".attack-btn").forEach(b => b.classList.remove("active"));
    const mapping = {
      syn_flood:  "btn-syn",
      udp_flood:  "btn-udp",
      http_flood: "btn-http",
      icmp_flood: "btn-icmp",
      slowloris:  "btn-slow",
      unknown:    "btn-unknown",
    };
    const id = mapping[type];
    if (id) document.getElementById(id)?.classList.add("active");

    document.getElementById("demo-active-label").textContent =
      `▶ Simulating: ${type.replace("_", " ").toUpperCase()}`;
  } catch (e) {
    console.error("triggerAttack failed", e);
  }
}

async function stopAttack() {
  try {
    await fetch(`${API_BASE}/api/simulate/stop`, { method: "POST" });
    activeAttack = null;
    document.querySelectorAll(".attack-btn").forEach(b => b.classList.remove("active"));
    document.getElementById("demo-active-label").textContent = "▶ Normal mixed traffic";
  } catch (e) {
    console.error("stopAttack failed", e);
  }
}

// ---------------------------------------------------------------------------
// Feed pause toggle
// ---------------------------------------------------------------------------
document.getElementById("feed-pause-toggle").addEventListener("change", function () {
  feedPaused = this.checked;
});

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  if (window.location.protocol === "file:") {
    const msg = `⚠️ <strong>Opened directly as a local file (file://):</strong> The DDoS detection system requires the Flask backend server. Run <code>python backend/app.py</code> in your terminal and open <a href="http://localhost:5000" target="_blank">http://localhost:5000</a>.`;
    setConnectionState(false, msg);
  }
  initChart();
  pollAll();                             // first poll immediately
  setInterval(pollAll, POLL_INTERVAL);  // then every 2s
});
