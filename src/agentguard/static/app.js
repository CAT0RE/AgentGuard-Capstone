const $ = (selector) => document.querySelector(selector);
let scenarios = [];
let agentScenarios = [];

async function request(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  setTimeout(() => node.classList.remove("show"), 2400);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[char]);
}

function compact(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value || {});
  return text.length > 190 ? `${text.slice(0, 190)}…` : text;
}

function setView(name) {
  document.querySelectorAll(".nav-item").forEach(node => node.classList.toggle("active", node.dataset.view === name));
  document.querySelectorAll(".view").forEach(node => node.classList.toggle("active", node.id === `${name}-view`));
  $("#page-title").textContent = { monitor: "Live Agent Monitor", agent: "Monitored Agent Loop", evaluation: "Security Evaluation", architecture: "System Architecture" }[name];
}

function updateScenarioDescription() {
  const selected = scenarios.find(item => item.id === $("#scenario").value);
  $("#scenario-description").textContent = selected?.description || "";
}

async function loadScenarios() {
  const data = await request("/api/scenarios");
  scenarios = data.scenarios;
  $("#scenario").innerHTML = scenarios.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.title)} · ${escapeHtml(item.category)}</option>`).join("");
  $("#scenario").value = "indirect_prompt_injection";
  updateScenarioDescription();
}

async function loadAgentScenarios() {
  const data = await request("/api/agent-scenarios");
  agentScenarios = data.scenarios;
  $("#agent-scenario").innerHTML = agentScenarios.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.title)}</option>`).join("");
  $("#agent-scenario").value = "injected_email";
  updateAgentDescription();
}

function updateAgentDescription() {
  const selected = agentScenarios.find(item => item.id === $("#agent-scenario").value);
  $("#agent-intent").textContent = selected ? `User intent: ${selected.user_intent}` : "";
}

async function runAgent() {
  const button = $("#agent-run-button"); button.disabled = true; button.textContent = "Running…";
  try {
    const result = await request("/api/agent-run", { method: "POST", body: JSON.stringify({ scenario_id: $("#agent-scenario").value, policy: $("#agent-policy").value }) });
    renderAgent(result); toast(`Agent run ${result.status}`);
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.innerHTML = "<span>↻</span> Run agent"; }
}

function renderAgent(result) {
  const blocked = ["blocked","confirm","verify","max_turns","error"].includes(result.status);
  const pill = $("#agent-status"); pill.className = `risk-pill ${blocked ? "critical" : "low"}`; pill.textContent = result.status.toUpperCase();
  $("#agent-result-title").textContent = blocked ? "Agent execution intercepted" : "Agent task completed";
  $("#agent-result-text").textContent = result.final_text || "No final model message.";
  $("#agent-turns").textContent = result.turns;
  $("#agent-tools").textContent = result.executed_tools.length;
  $("#agent-interventions").textContent = result.interventions.length;
  $("#agent-trace-id").textContent = result.trace_id;
  const timeline = $("#agent-timeline"); timeline.className = "timeline";
  timeline.innerHTML = result.trace.events.map((event, index) => {
    const assessment = result.trace.assessments[index];
    const title = event.tool_name || event.source;
    const content = event.kind === "tool_call" ? event.arguments : event.content;
    const findingHtml = assessment.findings.map(f => `<div class="finding"><b>${escapeHtml(f.title)}</b> · ${escapeHtml(f.evidence)}</div>`).join("");
    return `<div class="event"><span class="event-index">${String(index+1).padStart(2,"0")}</span><span class="event-type">${escapeHtml(event.kind.replace("_"," "))}</span><div class="event-main"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(compact(content))}</p></div><span class="decision ${escapeHtml(assessment.decision)}">${escapeHtml(assessment.decision)} · ${Math.round(assessment.score)}</span>${findingHtml ? `<div class="findings">${findingHtml}</div>` : ""}</div>`;
  }).join("");
}

async function runTrace() {
  const button = $("#run-button");
  button.disabled = true; button.textContent = "Running…";
  try {
    const result = await request("/api/run", { method: "POST", body: JSON.stringify({ scenario_id: $("#scenario").value, policy: $("#policy").value }) });
    renderTrace(result);
    toast(result.halted ? "Unsafe trajectory interrupted" : "Trace completed");
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.innerHTML = "<span>▶</span> Run trace"; }
}

function renderTrace(result) {
  const assessments = result.trace.assessments;
  const max = Math.round(result.max_risk_score);
  const highest = assessments.reduce((best, item) => item.score > best.score ? item : best, assessments[0]);
  const level = highest?.level || "low";
  const findings = assessments.reduce((sum, item) => sum + item.findings.length, 0);
  const terminal = result.halted ? (highest?.decision || "block") : "allow";
  const ring = $("#score-ring");
  ring.className = `score-ring ${level}`; ring.style.setProperty("--score", `${max * 3.6}deg`);
  $("#risk-score").textContent = max;
  $("#risk-level").className = `risk-pill ${level}`; $("#risk-level").textContent = level.toUpperCase();
  $("#decision-label").textContent = result.halted ? "Execution interrupted" : "Trace completed safely";
  $("#decision-copy").textContent = result.halt_reason || "The observed actions remained within the configured capability and risk policy.";
  $("#event-count").textContent = result.trace.events.length;
  $("#finding-count").textContent = findings;
  $("#intervention").textContent = terminal.toUpperCase();
  $("#expected").textContent = result.expected_unsafe ? "UNSAFE" : "SAFE";
  $("#trace-id").textContent = result.trace_id;
  $("#policy-badge").textContent = $("#policy").value.toUpperCase();
  const timeline = $("#timeline"); timeline.className = "timeline";
  timeline.innerHTML = assessments.map((assessment, index) => {
    const event = result.trace.events[index];
    if (!event) return "";
    const title = event.tool_name || event.source;
    const content = event.kind === "tool_call" ? event.arguments : event.content;
    const findingHtml = assessment.findings.map(f => `<div class="finding"><b>${escapeHtml(f.title)}</b> · ${escapeHtml(f.evidence)}</div>`).join("");
    return `<div class="event"><span class="event-index">${String(index + 1).padStart(2,"0")}</span><span class="event-type">${escapeHtml(event.kind.replace("_"," "))}</span><div class="event-main"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(compact(content))}</p></div><span class="decision ${escapeHtml(assessment.decision)}">${escapeHtml(assessment.decision)} · ${Math.round(assessment.score)}</span>${findingHtml ? `<div class="findings">${findingHtml}</div>` : ""}</div>`;
  }).join("");
}

async function runEvaluation() {
  const button = $("#evaluate-button"); button.disabled = true; button.textContent = "Evaluating…";
  try {
    const result = await request("/api/evaluate", { method: "POST", body: "{}" });
    renderMetrics(result); toast(`Evaluated ${result.case_count} labelled traces`);
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.textContent = "Run benchmark"; }
}

function renderMetrics(result) {
  const profiles = Object.entries(result.profiles);
  const best = profiles.reduce((winner, item) => item[1].metrics.f1 > winner[1].metrics.f1 ? item : winner, profiles[0])[0];
  $("#metric-cards").innerHTML = profiles.map(([name, value]) => {
    const m = value.metrics;
    return `<article class="metric-card ${name === best ? "best" : ""}"><h3>${escapeHtml(name.replace("_"," "))}${name === best ? " · BEST" : ""}</h3><div class="f1">${m.f1.toFixed(2)}</div><small>F1 score</small><div class="mini-metrics"><span>Precision<b>${m.precision.toFixed(2)}</b></span><span>Recall<b>${m.recall.toFixed(2)}</b></span><span>Accuracy<b>${m.accuracy.toFixed(2)}</b></span><span>Errors<b>${m.false_positive + m.false_negative}</b></span></div></article>`;
  }).join("");
  $("#metrics-chart").innerHTML = profiles.map(([name, value]) => {
    const m = value.metrics;
    return `<div class="bar-group">${[["P",m.precision],["R",m.recall],["F1",m.f1],["A",m.accuracy]].map(([label, number]) => `<div class="bar" style="height:${Math.max(2,number*100)}%"><em>${label}</em></div>`).join("")}<strong>${escapeHtml(name.replace("_"," "))}</strong></div>`;
  }).join("");
}

document.querySelectorAll(".nav-item").forEach(node => node.addEventListener("click", () => setView(node.dataset.view)));
$("#scenario").addEventListener("change", updateScenarioDescription);
$("#agent-scenario").addEventListener("change", updateAgentDescription);
$("#policy").addEventListener("change", () => $("#policy-badge").textContent = $("#policy").value.toUpperCase());
$("#run-button").addEventListener("click", runTrace);
$("#agent-run-button").addEventListener("click", runAgent);
$("#evaluate-button").addEventListener("click", runEvaluation);
loadScenarios().catch(error => toast(error.message));
loadAgentScenarios().catch(error => toast(error.message));
