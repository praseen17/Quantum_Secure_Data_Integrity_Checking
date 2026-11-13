const connectionLabel = document.querySelector('#connection-label');
const statusPill = document.querySelector('.top-status');
const fileInput = document.querySelector('#file-input');
const uploadZone = document.querySelector('#upload-zone');
const fileList = document.querySelector('#file-list');
const fileDetail = document.querySelector('#file-detail');
const emptyDetail = document.querySelector('#empty-detail');
const toast = document.querySelector('#toast');
let selectedFile = null;
let busy = false;

async function request(url, options = {}) {
  const response = await fetch(url, options);
  const data = response.headers.get('content-type')?.includes('application/json')
    ? await response.json() : {};
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}

function notify(message) {
  toast.textContent = message;
  toast.classList.add('show');
  window.setTimeout(() => toast.classList.remove('show'), 5000);
}

function prettySize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function requestAudit(sampleCount) {
  return request(`/api/files/${selectedFile.session_id}/audit`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample_count: sampleCount }),
  });
}

function showAuditResult(result) {
  const good = result.manifest_valid && result.checkpoint_valid && result.challenge_valid && result.all_verified;
  document.querySelector('#result-indicator').textContent = good ? 'INTEGRITY OK' : 'ISSUE FOUND';
  document.querySelector('#result-indicator').className = `result-indicator ${good ? 'good' : 'warning'}`;
  if (good) {
    document.querySelector('#result-message').textContent = 'Every challenged shard matched the signed Merkle root.';
  } else if (result.unavailable) {
    document.querySelector('#result-message').textContent = `The audit detected ${result.unavailable} unavailable shard${result.unavailable === 1 ? '' : 's'}. Repair the flagged shard to restore the file.`;
  } else if (result.corrupt) {
    document.querySelector('#result-message').textContent = `The audit detected ${result.corrupt} corrupt shard${result.corrupt === 1 ? '' : 's'}. Repair the flagged shard to restore the file.`;
  } else {
    document.querySelector('#result-message').textContent = 'The signed challenge found an inconclusive result. Review the flagged shard and retry recovery.';
  }
  const counts = document.querySelector('#audit-counts');
  counts.hidden = false;
  const issueText = result.issues?.length
    ? ` · Flagged shard indexes: ${result.issues.map(issue => issue.index).join(', ')}` : '';
  counts.textContent = `Sampled ${result.sampled} · Verified ${result.verified} · Missing ${result.unavailable} · Corrupt ${result.corrupt}${issueText}`;
  if (result.issues?.length) document.querySelector('#shard-index').value = result.issues[0].index;
}

function setBusy(value) {
  busy = value;
  for (const button of document.querySelectorAll('.detail-panel button')) button.disabled = value;
  uploadZone.classList.toggle('busy', value);
}

async function loadFiles() {
  const data = await request('/api/files');
  document.querySelector('#file-count').textContent = data.files.length;
  fileList.replaceChildren();
  if (!data.files.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-list';
    empty.textContent = 'No files yet. Add a file to begin.';
    fileList.append(empty);
    return;
  }
  for (const item of data.files) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `file-item${selectedFile?.session_id === item.session_id ? ' selected' : ''}`;
    const icon = document.createElement('span');
    icon.className = 'file-icon';
    icon.textContent = '▤';
    const details = document.createElement('span');
    details.className = 'file-item-info';
    const name = document.createElement('strong');
    name.textContent = item.file_name;
    const meta = document.createElement('small');
    meta.textContent = `${prettySize(item.original_bytes)} · ${item.total_shards} shards`;
    details.append(name, meta);
    const marker = document.createElement('span');
    marker.className = `file-marker${item.recovered ? ' recovered' : ''}`;
    marker.textContent = item.recovered ? 'RESTORED' : 'STORED';
    button.append(icon, details, marker);
    button.addEventListener('click', () => selectFile(item.session_id));
    fileList.append(button);
  }
}

async function selectFile(sessionId, { preserveResult = false } = {}) {
  try {
    const details = await request(`/api/files/${sessionId}`);
    const isSameFile = selectedFile?.session_id === sessionId;
    selectedFile = details;
    fileDetail.hidden = false;
    emptyDetail.hidden = true;
    document.querySelector('#detail-name').textContent = details.file_name;
    document.querySelector('#detail-meta').textContent = `${prettySize(details.original_bytes)} · ${details.source_shards} data shards · ${details.total_shards} total shards`;
    document.querySelector('#detail-root').textContent = details.root;
    document.querySelector('#available-shards').textContent = details.available_shards;
    document.querySelector('#unavailable-shards').textContent = details.unavailable_shards;
    document.querySelector('#total-shards').textContent = details.total_shards;
    const sampleInput = document.querySelector('#sample-count');
    sampleInput.max = details.total_shards;
    if (!isSameFile || !sampleInput.value) {
      sampleInput.value = Math.min(details.total_shards, Math.max(1, Math.ceil(details.total_shards / 20)));
    } else {
      sampleInput.value = Math.min(details.total_shards, Math.max(1, Number(sampleInput.value)));
    }
    const indexInput = document.querySelector('#shard-index');
    indexInput.max = Math.max(0, details.total_shards - 1);
    if (!isSameFile || !indexInput.value) indexInput.value = '0';
    else indexInput.value = Math.min(details.total_shards - 1, Math.max(0, Number(indexInput.value)));
    document.querySelector('#storage-state').textContent = details.unavailable_shards ? 'DEGRADED' : 'READY';
    document.querySelector('#storage-state').classList.toggle('degraded', details.unavailable_shards > 0);
    const download = document.querySelector('#download-button');
    download.hidden = !details.recovered;
    if (details.recovered) download.href = details.download_url;
    if (!preserveResult) {
      document.querySelector('#result-indicator').textContent = 'READY';
      document.querySelector('#result-indicator').className = 'result-indicator idle';
      document.querySelector('#result-message').textContent = 'Run an integrity audit or choose a shard for a recovery exercise.';
      document.querySelector('#audit-counts').hidden = true;
    }
    await loadFiles();
  } catch (error) {
    notify(error.message);
  }
}

async function withOperation(button, operation, successLabel) {
  if (!selectedFile || busy) return;
  setBusy(true);
  const previousLabel = button.textContent;
  button.textContent = 'Working…';
  try {
    const data = await operation();
    button.textContent = successLabel;
    return data;
  } catch (error) {
    notify(error.message);
  } finally {
    window.setTimeout(() => { button.textContent = previousLabel; }, 800);
    setBusy(false);
  }
}

async function uploadFile(file) {
  if (!file || busy) return;
  if (file.size > 128 * 1024 * 1024) {
    notify('Choose a file no larger than 128 MiB.');
    return;
  }
  setBusy(true);
  uploadZone.querySelector('strong').textContent = 'Encoding and signing…';
  try {
    const url = `/api/files?name=${encodeURIComponent(file.name)}`;
    const data = await request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: file,
    });
    await loadFiles();
    await selectFile(data.session_id);
  } catch (error) {
    notify(error.message);
  } finally {
    uploadZone.querySelector('strong').textContent = 'Add a file';
    setBusy(false);
    fileInput.value = '';
  }
}

fileInput.addEventListener('change', () => uploadFile(fileInput.files[0]));
uploadZone.addEventListener('dragover', event => {
  event.preventDefault();
  uploadZone.classList.add('dragging');
});
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragging'));
uploadZone.addEventListener('drop', event => {
  event.preventDefault();
  uploadZone.classList.remove('dragging');
  uploadFile(event.dataTransfer.files[0]);
});

document.querySelector('#audit-button').addEventListener('click', async event => {
  const count = Number(document.querySelector('#sample-count').value);
  const result = await withOperation(event.currentTarget,
    () => requestAudit(count), 'Audit complete');
  if (!result) return;
  showAuditResult(result);
  await selectFile(selectedFile.session_id, { preserveResult: true });
});

document.querySelector('#loss-button').addEventListener('click', async event => {
  const index = Number(document.querySelector('#shard-index').value);
  const result = await withOperation(event.currentTarget, () => request(
    `/api/files/${selectedFile.session_id}/loss`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ shard_index: index }),
    }), 'Shard marked unavailable');
  if (!result) return;
  document.querySelector('#sample-count').value = selectedFile.total_shards;
  await selectFile(selectedFile.session_id, { preserveResult: true });
  const auditButton = document.querySelector('#audit-button');
  const audit = await withOperation(auditButton,
    () => requestAudit(selectedFile.total_shards), 'Loss detected');
  if (audit) showAuditResult(audit);
});

document.querySelector('#recover-button').addEventListener('click', async event => {
  const index = Number(document.querySelector('#shard-index').value);
  const result = await withOperation(event.currentTarget, () => request(
    `/api/files/${selectedFile.session_id}/recover`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ shard_index: index }),
    }), 'File recovered');
  if (!result) return;
  document.querySelector('#result-indicator').textContent = 'RECOVERED';
  document.querySelector('#result-indicator').className = 'result-indicator good';
  document.querySelector('#result-message').textContent = `Shard ${index} was reconstructed and checked against the original commitment. The restored file is ready to download.`;
  const download = document.querySelector('#download-button');
  download.href = result.download_url;
  download.hidden = false;
  await selectFile(selectedFile.session_id, { preserveResult: true });
});

document.querySelector('#guide-link').addEventListener('click', event => {
  event.preventDefault();
  window.open('/guide', '_blank', 'noopener');
});

async function start() {
  try {
    const status = await request('/api/status');
    if (!status.ready) throw new Error('Run scripts/build.sh before starting this interface.');
    connectionLabel.textContent = `Local service ready · ${status.stored_files} stored`;
    statusPill.classList.add('ready');
    await loadFiles();
  } catch (error) {
    connectionLabel.textContent = 'Local service unavailable';
    notify(error.message);
  }
}

start();
