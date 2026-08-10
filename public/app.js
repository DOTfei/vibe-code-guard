const STAGES = [
  ['discovery', 'Project discovery'], ['threat-model', 'Threat model'], ['secrets', 'Secrets'],
  ['static', 'Static analysis'], ['dependencies', 'Dependencies'], ['infrastructure', 'Infrastructure'],
  ['web', 'Web / runtime'], ['manual', 'Manual security review'], ['fix', 'Fix'],
  ['rescan', 'Re-scan'], ['decision', 'Final decision'],
];

const TOOL_ORDER = ['gitleaks', 'trufflehog', 'semgrep', 'trivy', 'osv-scanner', 'checkov', 'zap', 'nuclei'];
const PAGE_TITLES = { overview: 'Audit overview', findings: 'Findings', history: 'Scan history', toolkit: 'Toolkit health' };

let appState = { latest: null, runs: [] };
let toolkitState = null;
let currentRunId = null;
let eventSource = null;
let findingFilter = 'ALL';
let refreshTimer = null;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
}

function formatTime(value) {
  if (!value) return '—';
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(value) {
  if (!value) return '—';
  return new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function duration(run) {
  if (!run?.startedAt) return '—';
  const end = run.finishedAt ? new Date(run.finishedAt).getTime() : Date.now();
  const seconds = Math.max(0, Math.floor((end - new Date(run.startedAt).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function toolDuration(tool) {
  if (!tool?.startedAt) return '—';
  const end = tool.finishedAt ? new Date(tool.finishedAt).getTime() : Date.now();
  return `${((end - new Date(tool.startedAt).getTime()) / 1000).toFixed(1)}s`;
}

function statusClass(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'running' || value === 'scanning') return 'running';
  if (value === 'pass' || value === 'healthy' || value === 'verified') return 'pass';
  if (value === 'warning' || value === 'pass with warnings' || value === 'skipped' || value === 'fixed' || value === 'false_positive' || value === 'accepted_risk') return 'warning';
  if (value === 'fail' || value === 'broken' || value === 'error' || value === 'open' || value === 'reopened') return 'fail';
  return 'neutral';
}

function statusChip(status) {
  const cls = statusClass(status);
  return `<span class="status-chip status-chip--${cls}">${escapeHTML(status || 'WAITING')}</span>`;
}

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('is-visible');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove('is-visible'), 3400);
}

async function requestJSON(url, options = {}) {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function currentRun() {
  return appState.latest && appState.latest.id === currentRunId ? appState.latest : appState.latest;
}

function setView(view) {
  $$('.nav-item').forEach((item) => item.classList.toggle('is-active', item.dataset.view === view));
  $$('[data-view-panel]').forEach((panel) => panel.classList.toggle('is-active', panel.dataset.viewPanel === view));
  $('#page-title').textContent = PAGE_TITLES[view] || 'Audit overview';
  if (view === 'findings') renderFindings();
  if (view === 'history') renderHistory();
  if (view === 'toolkit') renderToolkit();
}

function renderPipeline(run) {
  const container = $('#pipeline-list');
  if (!run?.stages) {
    container.innerHTML = '<div class="empty-state">Start a local scan to see the real pipeline state.</div>';
    $('#pipeline-caption').textContent = 'Waiting for a run';
    return;
  }
  container.innerHTML = STAGES.map(([id], index) => {
    const stage = run.stages[id] || { status: 'WAITING', note: '' };
    const status = stage.status || 'WAITING';
    return `<div class="pipeline-row is-${statusClass(status)}">
      <span class="pipeline-index">${String(index + 1).padStart(2, '0')}</span>
      <div class="pipeline-stage"><span class="stage-node" aria-hidden="true"></span><strong>${escapeHTML(stage.label || STAGES[index][1])}</strong></div>
      <span class="pipeline-note">${escapeHTML(stage.note || stage.description || '')}</span>
      <span class="pipeline-status">${escapeHTML(status)}</span>
    </div>`;
  }).join('');
  const active = STAGES.find(([id]) => run.stages[id]?.status === 'RUNNING');
  $('#pipeline-caption').textContent = active ? `Current: ${active[1]}` : `${run.status || 'WAITING'} · ${run.mode || '—'} mode`;
}

function renderTools(run) {
  const container = $('#tool-grid');
  const tools = run?.tools;
  if (!tools) {
    container.innerHTML = '<div class="empty-state">Scanner cards appear when a run starts.</div>';
    return;
  }
  container.innerHTML = TOOL_ORDER.map((id) => {
    const tool = tools[id] || { label: id, purpose: '', status: 'WAITING', findingsCount: 0 };
    const status = tool.status || 'WAITING';
    const findings = tool.findingsCount === null || tool.findingsCount === undefined ? '—' : tool.findingsCount;
    return `<article class="tool-card is-${statusClass(status)}">
      <div class="tool-card-top"><h4>${escapeHTML(tool.label || id)}</h4>${statusChip(status)}</div>
      <p class="tool-purpose">${escapeHTML(tool.purpose || 'Security scanner')}</p>
      <div class="tool-meta"><div><span>Version</span><strong>${escapeHTML(tool.version || 'N/A')}</strong></div><div><span>Findings</span><strong>${findings}</strong></div><div><span>Duration</span><strong>${escapeHTML(toolDuration(tool))}</strong></div></div>
    </article>`;
  }).join('');
}

function renderActivity(run) {
  const container = $('#activity-list');
  if (!run?.events?.length) {
    container.innerHTML = '<div class="empty-state">No activity yet. Start a scan to watch actual child-process events arrive.</div>';
    return;
  }
  const events = run.events.slice(-35).reverse();
  container.innerHTML = events.map((event) => {
    const dangerous = /FAIL|ERROR|DO NOT DEPLOY/i.test(`${event.status || ''} ${event.message || ''}`);
    const warning = /WARNING|SKIPPED|STOP/i.test(`${event.status || ''} ${event.message || ''}`);
    const eventClass = dangerous ? 'is-danger' : warning ? 'is-warning' : '';
    return `<div class="activity-row ${eventClass}"><span class="activity-time">${formatTime(event.timestamp)}</span><span class="activity-bar"></span><span class="activity-message">${escapeHTML(event.message || event.kind || 'Event')}</span></div>`;
  }).join('');
}

function renderOverview() {
  const run = currentRun();
  $('#open-report').disabled = !run;
  $('#rescan-scan').disabled = !run || run.status === 'SCANNING';
  $('#stop-scan').classList.toggle('is-hidden', !run || run.status !== 'SCANNING');
  $('#auto-scan').disabled = Boolean(run?.status === 'SCANNING');
  $('#quick-scan').disabled = Boolean(run?.status === 'SCANNING');
  $('#full-scan').disabled = Boolean(run?.status === 'SCANNING');
  $('#current-project').textContent = run?.projectName || 'No scan started';
  $('#current-project-meta').textContent = run ? `${run.projectPath} · data stays local and scanner output is sanitized before persistence.` : 'Choose a local project to begin. The dashboard will store only scan metadata and sanitized output.';
  $('#run-mode').textContent = run?.mode || '—';
  $('#run-started').textContent = run ? formatDate(run.startedAt) : '—';
  $('#run-duration').textContent = run ? duration(run) : '—';
  const active = run && STAGES.find(([id]) => run.stages?.[id]?.status === 'RUNNING');
  $('#run-stage').textContent = active ? active[1] : run?.currentStage ? (run.stages?.[run.currentStage]?.label || run.currentStage) : 'Waiting';
  $('#live-marker').classList.toggle('is-live', run?.status === 'SCANNING');
  $('#live-marker').innerHTML = `<span></span> ${run?.status === 'SCANNING' ? 'live' : 'idle'}`;
  $('#summary-explanation').textContent = run?.releaseGate?.reason || 'The current screen will reflect real scanner events as they arrive.';
  const summary = run?.summary || {};
  $('#metric-critical').textContent = run ? (summary.critical ?? 0) : '—';
  $('#metric-high').textContent = run ? (summary.high ?? 0) : '—';
  $('#metric-medium').textContent = run ? (summary.medium ?? 0) : '—';
  $('#metric-low').textContent = run ? (summary.low ?? 0) : '—';
  $('#gate-label').textContent = run?.releaseGate?.label || 'Assessment pending';
  $('#gate-rule').textContent = run?.releaseGate?.reason || 'Run a scan to establish evidence.';
  const overall = $('#overall-status');
  overall.className = `status-chip status-chip--${statusClass(run?.status)}`;
  overall.textContent = run?.status || 'WAITING';
  $('#gate-panel').dataset.state = statusClass(run?.status);
  renderPipeline(run);
  renderTools(run);
  renderOrchestration(run);
  renderActivity(run);
  const totalFindings = run ? (summary.total || 0) : 0;
  $('#nav-findings-count').textContent = run ? String(totalFindings) : '—';
}

function renderOrchestration(run) {
  const plan = run?.orchestration;
  const risk = $('#orchestration-risk');
  const summary = $('#orchestration-summary');
  const tags = $('#orchestration-tags');
  const tools = $('#orchestration-tools');
  const explanation = $('#orchestration-explanation');
  if (!plan) {
    risk.className = 'status-chip status-chip--neutral';
    risk.textContent = 'N/A';
    summary.textContent = 'Quick and Full use the preserved fixed scan paths. Auto scan creates a deterministic plan from Git changes.';
    tags.innerHTML = '';
    tools.innerHTML = '';
    explanation.textContent = '';
    return;
  }
  risk.className = `status-chip status-chip--${plan.risk === 'HIGH' ? 'fail' : plan.risk === 'MEDIUM' ? 'warning' : 'pass'}`;
  risk.textContent = `${plan.risk} RISK`;
  summary.textContent = `${plan.changeSet.files.length} change${plan.changeSet.files.length === 1 ? '' : 's'} detected via ${plan.changeSet.source}. ${plan.summary.selected} selected · ${plan.summary.skipped} skipped · ${plan.summary.notApplicable} not applicable · ${plan.summary.recommended} recommended.`;
  tags.innerHTML = (plan.categories || []).map((category) => `<span>${escapeHTML(category.replaceAll('_', ' '))}</span>`).join('');
  tools.innerHTML = (plan.tools || []).map((item) => `<div class="orchestration-tool orchestration-tool--${String(item.decision).toLowerCase().replaceAll('_', '-')}"><strong>${escapeHTML(item.tool)}</strong><span>${escapeHTML(item.decision)}</span><small>${escapeHTML(item.reason)}</small></div>`).join('');
  explanation.innerHTML = (plan.explanation || []).slice(0, 8).map((line) => `<div>${escapeHTML(line)}</div>`).join('');
}

function allFindings() {
  const run = currentRun();
  return run ? (run.correlatedFindings || [...(run.findings || []), ...(run.resolvedFindings || [])]) : [];
}

function renderFindings() {
  const run = currentRun();
  const findings = allFindings();
  const counts = findings.reduce((result, finding) => { result[finding.severity] = (result[finding.severity] || 0) + 1; result.ALL += 1; return result; }, { ALL: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 });
  Object.entries(counts).forEach(([key, value]) => { const el = $(`#finding-count-${key.toLowerCase()}`); if (el) el.textContent = value; });
  $('#finding-run-label').textContent = currentRun() ? `${currentRun().projectName} · ${currentRun().id}` : 'No run selected';
  $$('.filter-tab').forEach((tab) => tab.classList.toggle('is-active', tab.dataset.severity === findingFilter));
  const visible = findingFilter === 'ALL' ? findings : findings.filter((finding) => finding.severity === findingFilter);
  const container = $('#findings-list');
  if (!visible.length) {
    container.innerHTML = `<div class="empty-state">${findings.length ? 'No findings match this severity filter.' : 'No parsed findings for the selected run.'}</div>`;
    return;
  }
  container.innerHTML = visible.map((finding) => {
    const observations = finding.observations || [];
    const detectedBy = [...new Set(observations.map((observation) => observation.scanner).filter(Boolean))];
    const rawFindings = (run?.findings || []).filter((raw) => observations.some((observation) => observation.scannerFindingId === raw.id));
    const lastEvent = finding.history?.[finding.history.length - 1];
    const terminal = ['FALSE_POSITIVE', 'ACCEPTED_RISK'].includes(finding.status);
    return `<article class="finding-card finding-card--${statusClass(finding.status)}">
      <div class="finding-top"><div><h3 class="finding-title">${escapeHTML(finding.title)}</h3><span class="finding-id">${escapeHTML(finding.id)} · ${observations.length} observation${observations.length === 1 ? '' : 's'}</span></div><div class="finding-badges"><span class="severity-label severity-label--${String(finding.severity).toLowerCase()}">${escapeHTML(finding.severity)}</span><span class="lifecycle-label lifecycle-label--${statusClass(finding.status)}">${escapeHTML(finding.status)}</span></div></div>
      <div class="finding-grid"><div class="finding-section"><span>Detected by</span><p>${escapeHTML(detectedBy.join(' · ') || 'Historical compatibility view')}</p></div><div class="finding-section"><span>Location</span><p>${escapeHTML(finding.location?.file || finding.location?.endpoint || 'Location not supplied')}</p></div><div class="finding-section"><span>Correlation confidence</span><p>${escapeHTML(finding.confidence || 'NONE')}</p></div></div>
      <details class="finding-observation-details"><summary>Show ${observations.length} scanner observation${observations.length === 1 ? '' : 's'}</summary><div class="finding-observations">${observations.map((observation) => `<span>${escapeHTML(observation.scanner || 'unknown')} · ${escapeHTML(observation.ruleId || 'rule')} · ${escapeHTML(observation.runId || 'run')}</span>`).join('')}</div>${rawFindings.length ? `<pre>${escapeHTML(JSON.stringify(rawFindings, null, 2))}</pre>` : '<p class="finding-raw-note">Raw Unified Findings are available in the run API for historical observations.</p>'}</details>
      <div class="finding-footer"><span>${lastEvent ? `${escapeHTML(lastEvent.event)} · ${escapeHTML(formatDate(lastEvent.timestamp))}` : 'No lifecycle history'}</span><span class="finding-status">${escapeHTML(finding.status)}</span></div>
      <div class="finding-actions">${terminal ? `<button class="button button--ghost finding-action" data-finding-id="${escapeHTML(finding.id)}" data-action-status="OPEN" type="button">Reopen manually</button>` : `<button class="button button--secondary finding-action" data-finding-id="${escapeHTML(finding.id)}" data-action-status="FIXED" type="button">Mark as fixed</button><button class="button button--ghost finding-action" data-finding-id="${escapeHTML(finding.id)}" data-action-status="FALSE_POSITIVE" type="button">False positive</button><button class="button button--ghost finding-action" data-finding-id="${escapeHTML(finding.id)}" data-action-status="ACCEPTED_RISK" type="button">Accept risk</button>`}</div>
    </article>`;
  }).join('');
  $$('.finding-action').forEach((button) => button.addEventListener('click', () => updateFindingStatus(button.dataset.findingId, button.dataset.actionStatus)));
}

async function updateFindingStatus(findingId, status) {
  const needsReason = ['FALSE_POSITIVE', 'ACCEPTED_RISK'].includes(status);
  const reason = window.prompt(needsReason ? `Reason required for ${status.replaceAll('_', ' ').toLowerCase()}:` : 'Optional lifecycle note:', '');
  if (reason === null) return;
  try {
    const run = currentRun();
    if (!run) throw new Error('Select a completed run first.');
    const response = await requestJSON(`/api/runs/${encodeURIComponent(run.id)}/findings/${encodeURIComponent(findingId)}/status`, { method: 'POST', body: JSON.stringify({ status, reason }) });
    appState.latest = response.run;
    renderOverview();
    renderFindings();
    showToast(`${findingId} marked ${status}.`);
  } catch (error) { showToast(error.message); }
}

function renderHistory() {
  const container = $('#history-list');
  const history = appState.runs || [];
  if (!history.length) {
    container.innerHTML = '<div class="empty-state">No runs yet. A scan will create the first append-only record.</div>';
    return;
  }
  container.innerHTML = history.map((run) => `<article class="history-row">
    <div class="history-project"><strong>${escapeHTML(run.projectName || 'Project')}</strong><span>${escapeHTML(run.projectPath || '')}</span></div>
    <div class="history-value"><span>Started</span><strong>${escapeHTML(formatDate(run.startedAt))}</strong></div>
    <div class="history-value"><span>Result</span><strong class="history-status history-status--${statusClass(run.status)}">${escapeHTML(run.status || 'UNKNOWN')}</strong></div>
    <div class="history-value"><span>Critical / High</span><strong>${run.summary?.critical || 0} / ${run.summary?.high || 0}</strong></div>
    <button class="button button--ghost view-run" type="button" data-run-id="${escapeHTML(run.id)}">View run</button>
  </article>`).join('');
  $$('.view-run').forEach((button) => button.addEventListener('click', () => selectRun(button.dataset.runId)));
}

function renderToolkit() {
  if (!toolkitState) {
    $('#health-overall').textContent = 'Checking…';
    $('#health-grid').innerHTML = '<div class="empty-state">Reading the real local doctor command…</div>';
    $('#optional-health-grid').innerHTML = '';
    return;
  }
  const doctor = toolkitState.doctor || {};
  $('#health-overall').textContent = doctor.overall || 'UNKNOWN';
  $('#health-checked').textContent = formatDate(doctor.checkedAt);
  $('#health-data').textContent = appState.latest?.dataDir || 'Local run directory';
  $('#health-grid').innerHTML = TOOL_ORDER.map((id) => {
    const tool = doctor.tools?.[id] || { label: id, status: 'UNKNOWN', path: null, version: null };
    const broken = tool.status !== 'HEALTHY';
    return `<article class="health-card"><div class="health-card-top"><h3>${escapeHTML(tool.label || id)}</h3><span class="health-status ${broken ? 'health-status--broken' : ''}">${escapeHTML(tool.status || 'UNKNOWN')}</span></div><p>${escapeHTML(tool.path || 'Binary not reported')}</p><div class="health-version">${escapeHTML(tool.version || 'Version not reported')}</div></article>`;
  }).join('');
  const optionalTools = toolkitState.optionalTools || {};
  const optionalEntries = Object.values(optionalTools);
  $('#optional-health-grid').innerHTML = optionalEntries.length ? optionalEntries.map((tool) => {
    const status = tool.status || 'UNKNOWN';
    const pending = status.includes('PENDING');
    return `<article class="health-card health-card--optional"><div class="health-card-top"><h3>${escapeHTML(tool.name || 'Optional tool')}</h3><span class="health-status ${pending ? 'health-status--pending' : ''}">${escapeHTML(status)}</span></div><p>${escapeHTML(tool.binary || 'CLI not installed')}</p><div class="health-version">${escapeHTML(tool.notes || 'Not part of the core health gate.')}</div></article>`;
  }).join('') : '<div class="empty-state">No optional components registered.</div>';
}

async function refreshState({ keepSelection = true } = {}) {
  try {
    appState = await requestJSON('/api/state');
    if (!keepSelection || !currentRunId || !appState.runs.some((run) => run.id === currentRunId)) currentRunId = appState.latest?.id || null;
    else if (appState.latest?.id === currentRunId) currentRunId = appState.latest.id;
    renderOverview();
    renderFindings();
    if ($('#view-history').classList.contains('is-active')) renderHistory();
    $('#connection-label').textContent = 'Local server connected';
  } catch (error) {
    $('#connection-label').textContent = 'Server unavailable';
    showToast(error.message);
  }
}

async function refreshToolkit() {
  try { toolkitState = await requestJSON('/api/toolkit'); renderToolkit(); } catch (error) { showToast(error.message); }
}

function subscribeToRun(runId) {
  if (eventSource) eventSource.close();
  eventSource = new EventSource(`/api/runs/${encodeURIComponent(runId)}/events`);
  eventSource.addEventListener('snapshot', (event) => {
    const payload = JSON.parse(event.data);
    if (payload.run) { appState.latest = payload.run; currentRunId = payload.run.id; renderOverview(); renderFindings(); }
  });
  eventSource.addEventListener('activity', (event) => {
    const activity = JSON.parse(event.data);
    const run = currentRun();
    if (run) { run.events = [...(run.events || []), activity]; renderActivity(run); }
    window.clearTimeout(subscribeToRun.timer);
    subscribeToRun.timer = window.setTimeout(() => refreshState(), 100);
  });
  eventSource.onerror = () => {
    if (currentRun()?.status !== 'SCANNING') eventSource.close();
  };
}

async function startScan(mode) {
  const projectPath = $('#project-path').value.trim();
  const webTarget = $('#web-target').value.trim();
  $('#form-message').textContent = '';
  if (!projectPath) { $('#form-message').textContent = 'Enter an existing local project path first.'; $('#project-path').focus(); return; }
  try {
    const response = await requestJSON('/api/scans', { method: 'POST', body: JSON.stringify({ projectPath, mode, webTarget: ['auto', 'full'].includes(mode) ? webTarget || undefined : undefined }) });
    currentRunId = response.runId;
    $('#form-message').textContent = '';
    showToast(`${mode === 'auto' ? 'Auto' : mode === 'full' ? 'Full' : 'Quick'} scan started.`);
    subscribeToRun(currentRunId);
    await refreshState({ keepSelection: true });
    setView('overview');
  } catch (error) { $('#form-message').textContent = error.message; }
}

async function selectRun(runId) {
  try {
    const response = await requestJSON(`/api/runs/${encodeURIComponent(runId)}`);
    appState.latest = response.run;
    currentRunId = runId;
    renderOverview();
    renderFindings();
    setView('overview');
    subscribeToRun(runId);
  } catch (error) { showToast(error.message); }
}

async function stopScan() {
  if (!currentRunId) return;
  try { await requestJSON(`/api/runs/${encodeURIComponent(currentRunId)}/stop`, { method: 'POST' }); showToast('Stop requested.'); } catch (error) { showToast(error.message); }
}

async function rescanCurrent() {
  const run = currentRun();
  if (!run) return;
  $('#project-path').value = run.projectPath || '';
  $('#web-target').value = run.webTarget || '';
  await startScan(['auto', 'full'].includes(run.mode) ? run.mode : 'quick');
}

async function openReport() {
  if (!currentRunId) return;
  try {
    const response = await fetch(`/api/runs/${encodeURIComponent(currentRunId)}/report`);
    $('#report-content').textContent = await response.text();
    $('#report-dialog').showModal();
  } catch (error) { showToast(error.message); }
}

async function runDoctor() {
  $('#toolkit-output').classList.add('is-hidden');
  try { toolkitState = await requestJSON('/api/toolkit/doctor', { method: 'POST' }); renderToolkit(); showToast('Doctor completed.'); } catch (error) { showToast(error.message); }
}

async function runSelfTest() {
  $('#toolkit-output').classList.add('is-hidden');
  try {
    const result = await requestJSON('/api/toolkit/self-test', { method: 'POST' });
    $('#toolkit-output').textContent = result.output;
    $('#toolkit-output').classList.remove('is-hidden');
    showToast(result.healthy ? 'Self-test passed.' : 'Self-test needs attention.');
    await refreshToolkit();
  } catch (error) { showToast(error.message); }
}

function wireEvents() {
  $$('[data-view]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
  $('#auto-scan').addEventListener('click', () => startScan('auto'));
  $('#quick-scan').addEventListener('click', () => startScan('quick'));
  $('#full-scan').addEventListener('click', () => startScan('full'));
  $('#stop-scan').addEventListener('click', stopScan);
  $('#rescan-scan').addEventListener('click', rescanCurrent);
  $('#refresh-button').addEventListener('click', () => { refreshState(); refreshToolkit(); });
  $('#open-report').addEventListener('click', openReport);
  $('#close-report').addEventListener('click', () => $('#report-dialog').close());
  $('#run-doctor').addEventListener('click', runDoctor);
  $('#run-self-test').addEventListener('click', runSelfTest);
  $$('.filter-tab').forEach((tab) => tab.addEventListener('click', () => { findingFilter = tab.dataset.severity; renderFindings(); }));
}

async function boot() {
  wireEvents();
  renderOverview();
  renderToolkit();
  await Promise.all([refreshState(), refreshToolkit()]);
  if (currentRun()?.status === 'SCANNING') subscribeToRun(currentRunId);
  refreshTimer = window.setInterval(() => {
    if (currentRun()?.status === 'SCANNING') refreshState();
  }, 2200);
}

window.addEventListener('beforeunload', () => { if (eventSource) eventSource.close(); window.clearInterval(refreshTimer); });
boot();
