const requestChart = new Chart(document.getElementById("requestsChart"), {
  type: "line",
  data: {
    labels: [],
    datasets: [
      {
        label: "Allowed",
        data: [],
        borderColor: "#2f855a",
        backgroundColor: "rgba(47, 133, 90, 0.18)",
        tension: 0.3
      },
      {
        label: "Blocked",
        data: [],
        borderColor: "#b42318",
        backgroundColor: "rgba(180, 35, 24, 0.18)",
        tension: 0.3
      }
    ]
  }
});

const anomalyChart = new Chart(document.getElementById("anomalyChart"), {
  type: "bar",
  data: {
    labels: [],
    datasets: [
      {
        label: "Anomalies",
        data: [],
        backgroundColor: "#c46b2d"
      }
    ]
  }
});

async function api(url, options) {
  const response = await fetch(url, options);
  return response.json();
}

function severityClass(value) {
  const severity = String(value || "LOW").toLowerCase();
  return `alert-row-${severity}`;
}

function renderChipList(elementId, items, deleteHandlerName) {
  const target = document.getElementById(elementId);
  target.innerHTML = items.map(item => {
    const safeItem = encodeURIComponent(item);
    return `<span class="chip">${item}<button type="button" onclick="${deleteHandlerName}('${safeItem}')">remove</button></span>`;
  }).join("");
}

function updateSummary(summary) {
  document.getElementById("totalRequests").textContent = summary.total_requests;
  document.getElementById("totalAnomalies").textContent = summary.total_anomalies;
  document.getElementById("blockedIps").textContent = summary.blocked_ips;
  document.getElementById("openConnections").textContent = summary.open_connections;
}

function updateCharts(series) {
  requestChart.data.labels = series.map(item => item.minute);
  requestChart.data.datasets[0].data = series.map(item => item.allowed);
  requestChart.data.datasets[1].data = series.map(item => item.blocked);
  requestChart.update();

  anomalyChart.data.labels = series.map(item => item.minute);
  anomalyChart.data.datasets[0].data = series.map(item => item.anomalies);
  anomalyChart.update();
}

function updateAlerts(alerts) {
  const body = document.getElementById("alertsTable");
  body.innerHTML = alerts.map(alert => `
    <tr class="${severityClass(alert.severity)}">
      <td>${alert.time || alert.timestamp || ""}</td>
      <td>${alert.severity || "LOW"}</td>
      <td>${alert.client_ip || alert.ip || ""}</td>
      <td>${alert.reason || alert.message || ""}</td>
    </tr>
  `).join("");
}

function updateSuspiciousIps(items) {
  const body = document.getElementById("suspiciousIpsTable");
  body.innerHTML = items.map(item => `
    <tr>
      <td>${item.ip}</td>
      <td>${item.anomalies}</td>
      <td>${item.blocked ? "Blocked" : "Watching"}</td>
    </tr>
  `).join("");
}

function updateLogs(logs) {
  const body = document.getElementById("logsTable");
  body.innerHTML = logs.map(log => `
    <tr>
      <td>${log.time}</td>
      <td>${log.client_ip}</td>
      <td>${log.host}</td>
      <td>${log.port}</td>
      <td>${log.protocol}</td>
      <td>${log.action}</td>
      <td>${log.reason}</td>
    </tr>
  `).join("");
}

function updateConfig(config) {
  document.getElementById("rateLimitInput").value = config.rate_limit;
  document.getElementById("idsToggle").checked = config.ids_enabled;
  document.getElementById("dpiToggle").checked = config.dpi_enabled;
  document.getElementById("anomalyToggle").checked = config.anomaly_detection_enabled;
  document.getElementById("autoBlockToggle").checked = config.auto_block_enabled;
  renderChipList("blockedIpsList", config.blocked_ips, "removeBlockedIp");
  renderChipList("blockedSitesList", config.blocked_sites, "removeBlockedSite");
}

async function refreshDashboard() {
  const [summary, series, alerts, suspiciousIps, logs, config] = await Promise.all([
    api("/api/summary"),
    api("/api/traffic/series"),
    api("/api/alerts?limit=50"),
    api("/api/suspicious-ips?limit=20"),
    api("/api/logs?limit=60"),
    api("/api/config")
  ]);

  updateSummary(summary);
  updateCharts(series);
  updateAlerts(alerts);
  updateSuspiciousIps(suspiciousIps);
  updateLogs(logs);
  updateConfig(config);
}

document.getElementById("settingsForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  await api("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      rate_limit: Number(document.getElementById("rateLimitInput").value),
      ids_enabled: document.getElementById("idsToggle").checked,
      dpi_enabled: document.getElementById("dpiToggle").checked,
      anomaly_detection_enabled: document.getElementById("anomalyToggle").checked,
      auto_block_enabled: document.getElementById("autoBlockToggle").checked
    })
  });
  refreshDashboard();
});

document.getElementById("blockedIpForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("blockedIpInput");
  await api("/api/blocked-ips", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip: input.value.trim() })
  });
  input.value = "";
  refreshDashboard();
});

document.getElementById("blockedSiteForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("blockedSiteInput");
  await api("/api/block-sites", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ site: input.value.trim() })
  });
  input.value = "";
  refreshDashboard();
});

async function removeBlockedIp(ip) {
  await api(`/api/blocked-ips/${ip}`, { method: "DELETE" });
  refreshDashboard();
}

async function removeBlockedSite(site) {
  await api(`/api/block-sites/${site}`, { method: "DELETE" });
  refreshDashboard();
}

refreshDashboard();
setInterval(refreshDashboard, 4000);
