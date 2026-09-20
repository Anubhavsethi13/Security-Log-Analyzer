const API = "http://localhost:8000",
  $ = (id) => document.getElementById(id);
const sample = [
  {
    timestamp: "2026-09-20T10:15:02Z",
    source_ip: "203.0.113.42",
    event: "failed login",
    user: "admin",
    status: "failure",
  },
  {
    timestamp: "2026-09-20T10:15:05Z",
    source_ip: "203.0.113.42",
    event: "failed login",
    user: "root",
    status: "failure",
  },
  {
    timestamp: "2026-09-20T10:15:08Z",
    source_ip: "203.0.113.42",
    event: "failed login",
    user: "administrator",
    status: "failure",
  },
  {
    timestamp: "2026-09-20T10:16:11Z",
    source_ip: "198.51.100.77",
    event: "SQL injection attempt",
    path: "/login?id=1 OR 1=1",
    status: "blocked",
  },
  {
    timestamp: "2026-09-20T10:17:31Z",
    source_ip: "198.51.100.77",
    event: "privilege escalation",
    user: "svc-web",
    status: "detected",
  },
];
$("logInput").addEventListener(
  "input",
  () => ($("logMeta").textContent = `${$("logInput").value.length} characters`),
);
$("sampleBtn").addEventListener("click", () => {
  $("logInput").value = JSON.stringify(sample, null, 2);
  $("logMeta").textContent = `${$("logInput").value.length} characters`;
});
$("fileInput").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $("logInput").value = await f.text();
  $("logMeta").textContent = `${$("logInput").value.length} characters`;
});
async function health() {
  try {
    const r = await fetch(`${API}/api/health`),
      d = await r.json();
    $("apiStatus").textContent = d.groq_configured
      ? "API online"
      : "API online • keys needed";
  } catch {
    $("apiStatus").textContent = "Backend offline";
  }
}
health();
$("analyzeBtn").addEventListener("click", async () => {
  hideError();
  let logs;
  try {
    logs = JSON.parse($("logInput").value);
  } catch {
    return showError(
      "Invalid JSON. Paste a JSON object or array of log records.",
    );
  }
  setBusy(true);
  try {
    const r = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logs }),
      }),
      d = await r.json();
    if (!r.ok) throw Error(d.detail || "Analysis failed.");
    render(d);
  } catch (e) {
    showError(
      e.message + " Make sure the FastAPI backend is running on port 8000.",
    );
  } finally {
    setBusy(false);
  }
});
let pipelineTimer;
function setBusy(b) {
  $("analyzeBtn").disabled = b;
  $("analyzeBtn").textContent = b ? "Analyzing…" : "Analyze logs";
  document
    .querySelectorAll(".stage")
    .forEach((stage) => stage.classList.remove("active", "done"));
  clearInterval(pipelineTimer);
  if (b) {
    let index = 0;
    const stages = [...document.querySelectorAll(".stage")];
    const advance = () => {
      stages.forEach((stage, i) => stage.classList.toggle("done", i < index));
      if (stages[index]) stages[index].classList.add("active");
      index = Math.min(index + 1, stages.length - 1);
    };
    advance();
    pipelineTimer = setInterval(advance, 650);
  } else
    document
      .querySelectorAll(".stage")
      .forEach((stage) => stage.classList.add("done"));
}
function showError(m) {
  $("errorBox").textContent = m;
  $("errorBox").classList.remove("hidden");
}
function hideError() {
  $("errorBox").classList.add("hidden");
}
function esc(v) {
  return String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
}
function safeUrl(v) {
  try {
    let u = new URL(v);
    return ["http:", "https:"].includes(u.protocol) ? u.href : "#";
  } catch {
    return "#";
  }
}
function render(d) {
  let a = d.analysis || {},
    p = d.pipeline || {};
  $("results").classList.remove("hidden");
  $("riskLevel").textContent = (a.risk_level || "UNKNOWN").toUpperCase();
  $("summary").textContent = a.summary || "No summary returned.";
  $("logCount").textContent = p.logs_received ?? 0;
  $("indicatorCount").textContent = (p.indicators_extracted || []).length;
  $("intelStatus").textContent = (
    p.threat_intelligence?.status || "unknown"
  ).toUpperCase();
  $("threats").innerHTML =
    (a.threats || [])
      .map(
        (t) =>
          `<article class="threat"><div class="threat-title"><b>${esc(t.title || "Unnamed threat")}</b><span class="severity ${esc(t.severity || "")}">${esc(t.severity || "UNKNOWN")} • ${Number(t.confidence || 0)}%</span></div><p>${esc(t.impact || "Impact not specified.")}</p><ul class="evidence">${(t.evidence || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul><p><b>Actions:</b> ${(t.recommended_actions || []).map(esc).join(" • ")}</p></article>`,
      )
      .join("") || "<p class=muted>No threats returned.</p>";
  $("recommendations").innerHTML =
    (a.recommendations || []).map((x) => `<li>${esc(x)}</li>`).join("") ||
    "<li>No recommendations returned.</li>";
  $("reasoning").innerHTML = (a.agent_reasoning || [])
    .map(
      (x, i) =>
        `<div class="reason-step"><b>${String(i + 1).padStart(2, "0")}</b><div><b>${esc(x.step || "Step")}</b><p>${esc(x.detail || "")}</p></div></div>`,
    )
    .join("");
  let intel = p.threat_intelligence || {};
  $("intel").innerHTML =
    (intel.results || [])
      .map(
        (r) =>
          `<div class="intel-item"><a href="${safeUrl(r.url)}" target="_blank" rel="noopener">${esc(r.title || r.url || "Source")}</a><p>${esc(r.content || "")}</p></div>`,
      )
      .join("") ||
    `<p class=muted>${esc(intel.reason || "No external intelligence results.")}</p>`;
  $("results").scrollIntoView({ behavior: "smooth" });
}
