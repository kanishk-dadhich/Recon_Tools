const form = document.getElementById('scan-form');
const consoleEl = document.getElementById('console');
const scanBtn = document.getElementById('scan-btn');
const minConfSlider = document.getElementById('min-conf');
const minConfVal = document.getElementById('min-conf-val');
const findingsBody = document.getElementById('findings-body');
const findingsWrap = document.getElementById('findings-table-wrap');
const emptyState = document.getElementById('empty-state');
const exportRow = document.getElementById('export-row');
const drawer = document.getElementById('detail-drawer');
const drawerContent = document.getElementById('drawer-content');
const drawerClose = document.getElementById('drawer-close');

let currentJobId = null;
let pollTimer = null;
let lastStatus = null;

minConfSlider.addEventListener('input', () => {
  minConfVal.textContent = minConfSlider.value;
});

function log(msg, cls) {
  const line = document.createElement('div');
  line.className = 'console-line' + (cls ? ' ' + cls : '');
  line.textContent = msg;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setPipelineStep(status) {
  const steps = document.querySelectorAll('#pipeline-steps li');
  const order = ['crawling', 'extracting', 'validating', 'done'];
  const idx = order.indexOf(status);
  steps.forEach((li) => {
    const stepIdx = order.indexOf(li.dataset.step);
    li.classList.remove('active', 'complete');
    if (stepIdx < idx) li.classList.add('complete');
    else if (stepIdx === idx) li.classList.add('active');
  });
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = document.getElementById('target').value.trim();
  if (!target) return;

  const confirmAuthorized = document.getElementById('confirm-authorized').checked;
  if (!confirmAuthorized) {
    log('! You must confirm you are authorized to test this target before scanning.', 'warn');
    return;
  }

  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';
  consoleEl.innerHTML = '';
  findingsWrap.style.display = 'none';
  emptyState.style.display = 'block';
  emptyState.querySelector('p').textContent = 'Scan in progress...';
  exportRow.style.display = 'none';
  lastStatus = null;

  log(`$ mass-pii-finder scan ${target}`, null);
  log('$ authorized-scope check: confirmed by user', 'dim');

  const scopeExtra = document.getElementById('scope-extra').value
    .split('\n').map((s) => s.trim()).filter(Boolean);

  const payload = {
    target,
    confirm_authorized: confirmAuthorized,
    max_files: parseInt(document.getElementById('max-files').value, 10),
    timeout: parseInt(document.getElementById('timeout').value, 10),
    probe: document.getElementById('probe').checked,
    min_confidence: parseInt(minConfSlider.value, 10),
    scope: scopeExtra,
    rate_limit: parseFloat(document.getElementById('rate-limit').value),
    enumerate_subdomains: document.getElementById('enumerate-subdomains').checked,
  };

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.error) {
      log('! ' + data.error, 'warn');
      resetButton();
      return;
    }
    currentJobId = data.job_id;
    pollTimer = setInterval(pollStatus, 900);
  } catch (err) {
    log('! request failed: ' + err.message, 'warn');
    resetButton();
  }
});

async function pollStatus() {
  if (!currentJobId) return;
  const res = await fetch(`/api/status/${currentJobId}`);
  const data = await res.json();

  if (data.status !== lastStatus) {
    log(`$ ${data.progress}`, data.status === 'error' ? 'warn' : null);
    setPipelineStep(data.status);
    lastStatus = data.status;
  }

  if (data.status === 'done') {
    clearInterval(pollTimer);
    renderResults(data);
    resetButton();
  } else if (data.status === 'error') {
    clearInterval(pollTimer);
    resetButton();
  }
}

function resetButton() {
  scanBtn.disabled = false;
  scanBtn.textContent = 'Run scan';
}

function renderResults(data) {
  const findings = data.findings || [];
  const meta = data.meta || {};

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach((f) => counts[f.severity]++);
  document.getElementById('stat-critical').textContent = counts.CRITICAL;
  document.getElementById('stat-high').textContent = counts.HIGH;
  document.getElementById('stat-medium').textContent = counts.MEDIUM;
  document.getElementById('stat-low').textContent = counts.LOW;

  log(`$ scanned ${meta.js_file_count || 0} JS file(s), found ${meta.sourcemap_count || 0} exposed sourcemap(s)`, 'ok');
  if (meta.pages_crawled) log(`$ crawled ${meta.pages_crawled} in-scope page(s)`, 'dim');
  if (meta.subdomain_count) log(`$ ${meta.subdomain_count} subdomain(s) found via passive CT log lookup`, 'dim');
  if (meta.scope_excluded_sample && meta.scope_excluded_sample.length) {
    log(`$ ${meta.scope_excluded_sample.length} URL(s) excluded as out-of-scope (not fetched)`, 'dim');
  }
  if (meta.sourcemaps && meta.sourcemaps.length) {
    meta.sourcemaps.slice(0, 5).forEach((sm) => log('  sourcemap: ' + sm, 'warn'));
  }
  log(`$ ${findings.length} finding(s) after triage`, 'ok');

  if (!findings.length) {
    emptyState.style.display = 'block';
    emptyState.querySelector('p').textContent = 'No findings above the selected confidence threshold. Try lowering min confidence, or the target may simply be clean.';
    findingsWrap.style.display = 'none';
    exportRow.style.display = 'none';
    return;
  }

  emptyState.style.display = 'none';
  findingsWrap.style.display = 'block';
  exportRow.style.display = 'flex';

  findingsBody.innerHTML = '';
  findings.forEach((f, i) => {
    const tr = document.createElement('tr');
    const files = (f.source_files || []).map(shortUrl).join('<br>');
    tr.innerHTML = `
      <td>${i + 1}</td>
      <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
      <td>${escapeHtml(f.type)}</td>
      <td>${f.confidence}</td>
      <td><span class="val-code">${escapeHtml(truncate(f.value, 70))}</span></td>
      <td class="src-files">${files}</td>
    `;
    tr.addEventListener('click', () => openDrawer(f));
    findingsBody.appendChild(tr);
  });

  document.getElementById('export-json').onclick = () => {
    window.location = `/api/report/${currentJobId}/json`;
  };
  document.getElementById('export-html').onclick = () => {
    window.location = `/api/report/${currentJobId}/html`;
  };
  document.getElementById('export-sarif').onclick = () => {
    window.location = `/api/report/${currentJobId}/sarif`;
  };
  document.getElementById('export-markdown').onclick = () => {
    window.location = `/api/report/${currentJobId}/markdown`;
  };
  document.getElementById('export-csv').onclick = () => {
    window.location = `/api/report/${currentJobId}/csv`;
  };
}

function openDrawer(f) {
  const notes = (f.validation && f.validation.notes) || [];
  const files = (f.source_files || []).map(shortUrl).join('<br>');
  let decodedHtml = '';
  if (f.validation && f.validation.decoded) {
    decodedHtml = `<div class="kv"><div class="k">Decoded JWT</div><div class="v">${escapeHtml(JSON.stringify(f.validation.decoded, null, 2))}</div></div>`;
  }
  let probeHtml = '';
  if (f.validation && f.validation.endpoint_probe) {
    probeHtml = `<div class="kv"><div class="k">Endpoint probe</div><div class="v">${escapeHtml(JSON.stringify(f.validation.endpoint_probe, null, 2))}</div></div>`;
  }

  drawerContent.innerHTML = `
    <h3><span class="sev-badge sev-${f.severity}">${f.severity}</span> &nbsp;${escapeHtml(f.type)}</h3>
    <div class="kv"><div class="k">Value</div><div class="v">${escapeHtml(f.value)}</div></div>
    <div class="kv"><div class="k">Confidence</div><div class="v">${f.confidence} / 100</div></div>
    <div class="kv"><div class="k">Category</div><div class="v">${escapeHtml(f.category)}</div></div>
    <div class="kv"><div class="k">Found in</div><div class="v">${files}</div></div>
    <div class="kv"><div class="k">Context</div><div class="v">${escapeHtml(f.context || '')}</div></div>
    ${decodedHtml}
    ${probeHtml}
    <div class="kv"><div class="k">Validation notes</div>${notes.map((n) => `<div class="note">${escapeHtml(n)}</div>`).join('')}</div>
  `;
  drawer.classList.add('open');
}

drawerClose.addEventListener('click', () => drawer.classList.remove('open'));

function shortUrl(u) {
  try {
    const parsed = new URL(u);
    return parsed.pathname.length > 40 ? '...' + parsed.pathname.slice(-40) : parsed.pathname;
  } catch (e) {
    return u;
  }
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}
