const $ = (id) => document.getElementById(id);
const api = (url, opts) => fetch(url, { ...opts, headers: { 'content-type': 'application/json', ...opts?.headers } });

const fmt = (n) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) (n /= 1024), i++;
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
};
const when = (ms) => new Date(ms).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

// navigator.clipboard is undefined outside a secure context — plain http on a
// LAN IP, which is exactly how people first open this. Fail visibly, not silently.
const copy = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
};

let pick = null; // { source, path?, file?, label }

function setPick(p) {
  pick = p;
  $('create').disabled = !p;
  $('status').textContent = p ? `Selected: ${p.label}` : '';
  $('status').classList.remove('err');
}

// ---- upload tab ----------------------------------------------------------
$('drop').onclick = () => $('file').click();
$('file').onchange = () => $('file').files[0] && setPick({ source: 'upload', file: $('file').files[0], label: $('file').files[0].name });
for (const ev of ['dragenter', 'dragover']) $('drop').addEventListener(ev, (e) => (e.preventDefault(), $('drop').classList.add('over')));
for (const ev of ['dragleave', 'drop']) $('drop').addEventListener(ev, () => $('drop').classList.remove('over'));
$('drop').addEventListener('drop', (e) => {
  e.preventDefault();
  const f = e.dataTransfer.files[0];
  if (f) setPick({ source: 'upload', file: f, label: f.name });
});

// ---- library tab ---------------------------------------------------------
async function browse(p = '') {
  const r = await api(`/api/browse?p=${encodeURIComponent(p)}`);
  if (!r.ok) return ($('here').textContent = 'Cannot read that folder.');
  const { path, hasParent, entries } = await r.json();
  setPick(null); // moving somewhere else invalidates whatever was selected
  $('here').textContent = `/${path}`;
  $('files').innerHTML = '';

  // Folders open on click, so sharing one is a separate button for wherever you are.
  const folder = path.split('/').pop();
  $('shareFolder').textContent = folder ? `Share "${folder}" as a zip` : 'Share everything as a zip';
  $('shareFolder').onclick = () =>
    setPick({ source: 'library', path, label: `${folder || 'entire library'} (folder → zip)` });

  if (hasParent) {
    const up = document.createElement('li');
    up.textContent = '⬆︎ ..';
    up.onclick = () => browse(path.split('/').slice(0, -1).join('/'));
    $('files').append(up);
  }
  for (const e of entries) {
    const li = document.createElement('li');
    const full = path ? `${path}/${e.name}` : e.name;
    li.innerHTML = `<span>${e.dir ? '📁' : '📄'}</span><span></span><span class="size">${e.dir ? 'folder' : fmt(e.size)}</span>`;
    li.children[1].textContent = e.name;
    li.onclick = () => {
      if (e.dir) return browse(full);
      for (const s of $('files').children) s.removeAttribute('aria-selected');
      li.setAttribute('aria-selected', 'true');
      setPick({ source: 'library', path: full, label: e.name });
    };
    $('files').append(li);
  }
}

function tab(which) {
  const lib = which === 'library';
  $('tabUpload').ariaSelected = String(!lib);
  $('tabLibrary').ariaSelected = String(lib);
  $('paneUpload').classList.toggle('hide', lib);
  $('paneLibrary').classList.toggle('hide', !lib);
  setPick(null);
  if (lib) browse('');
}
$('tabUpload').onclick = () => tab('upload');
$('tabLibrary').onclick = () => tab('library');

// ---- create --------------------------------------------------------------
$('create').onclick = async () => {
  if (!pick) return;
  $('create').disabled = true;
  $('status').classList.remove('err');
  $('status').textContent = 'Creating…';

  const body = {
    source: pick.source,
    path: pick.path,
    name: pick.file?.name,
    hours: Number($('hours').value),
    password: $('pass').value || undefined,
    maxDownloads: $('max').value || undefined,
  };
  const r = await api('/api/links', { method: 'POST', body: JSON.stringify(body) });
  const data = await r.json();
  if (!r.ok) {
    $('status').textContent = data.error ?? 'Failed';
    $('status').classList.add('err');
    $('create').disabled = false;
    return;
  }

  if (pick.source === 'upload') {
    try {
      await upload(data.token, pick.file);
    } catch (err) {
      $('status').textContent = `Upload failed: ${err.message}`;
      $('status').classList.add('err');
      $('create').disabled = false;
      return;
    }
  }

  $('status').textContent = `${(await copy(data.url)) ? 'Link copied' : 'Link ready'}: ${data.url}`;
  $('pass').value = $('max').value = '';
  setPick(null);
  refresh();
};

// XHR, not fetch — fetch gives no upload progress.
const upload = (token, file) =>
  new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open('PUT', `/api/upload/${token}`);
    x.setRequestHeader('content-type', 'application/octet-stream');
    $('prog').classList.remove('hide');
    x.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      $('prog').value = (e.loaded / e.total) * 100;
      $('status').textContent = `Uploading ${fmt(e.loaded)} of ${fmt(e.total)}…`;
    };
    const done = (fn, arg) => ($('prog').classList.add('hide'), fn(arg));
    x.onload = () => (x.status < 300 ? done(resolve) : done(reject, new Error(`HTTP ${x.status}`)));
    x.onerror = () => done(reject, new Error('connection lost'));
    x.send(file);
  });

// ---- links list ----------------------------------------------------------
async function refresh() {
  const r = await api('/api/links');
  if (r.status === 401) return show('login');
  const links = await r.json();
  $('links').innerHTML = '';
  for (const l of links) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td></td><td></td><td></td><td></td>
      <td style="text-align:right;white-space:nowrap">
        <button data-copy>Copy</button> <button data-del>Delete</button></td>`;
    tr.children[0].innerHTML = `<div></div><code></code>`;
    tr.children[0].firstChild.textContent = `${l.locked ? '🔒 ' : ''}${l.name}`;
    tr.children[0].lastChild.textContent = l.url;
    tr.children[1].textContent =
      l.status === 'zipping' ? `zipping… ${fmt(l.size)}` : l.status === 'ready' ? fmt(l.size) : l.status;
    tr.children[2].textContent = when(l.expires);
    tr.children[3].textContent = l.maxDownloads ? `${l.downloads} / ${l.maxDownloads}` : l.downloads;
    const copyBtn = tr.querySelector('[data-copy]');
    copyBtn.onclick = async () => {
      copyBtn.textContent = (await copy(l.url)) ? 'Copied' : 'Select it';
      setTimeout(() => (copyBtn.textContent = 'Copy'), 1500);
    };
    tr.querySelector('[data-del]').onclick = async () => {
      const what = l.status === 'zipping' ? `Cancel zipping ${l.name}?` : `Delete the link for ${l.name}?`;
      if (!confirm(what)) return;
      await api(`/api/links/${l.token}`, { method: 'DELETE' });
      refresh();
    };
    $('links').append(tr);
  }
  // Keep polling while a zip is building so the size ticks up.
  if (links.some((l) => l.status === 'zipping')) setTimeout(refresh, 3000);
}

// ---- auth ----------------------------------------------------------------
function show(view) {
  $('login').classList.toggle('hide', view !== 'login');
  $('main').classList.toggle('hide', view === 'login');
  if (view === 'login') $('pw').focus();
}

$('login').onsubmit = async (e) => {
  e.preventDefault();
  const r = await api('/api/login', { method: 'POST', body: JSON.stringify({ password: $('pw').value }) });
  if (!r.ok) return ($('loginerr').textContent = 'Wrong password');
  $('pw').value = $('loginerr').textContent = '';
  start();
};

// ---- settings ------------------------------------------------------------
function showCap(maxMbps) {
  $('cap').value = maxMbps ?? '';
  $('capStatus').textContent = maxMbps ? `Currently capped at ${maxMbps} Mbps` : 'Currently unlimited';
  $('capStatus').classList.remove('err');
}

$('saveCap').onclick = async () => {
  const r = await api('/api/settings', {
    method: 'PUT',
    body: JSON.stringify({ maxMbps: $('cap').value === '' ? null : Number($('cap').value) }),
  });
  const data = await r.json();
  if (!r.ok) {
    $('capStatus').textContent = data.error ?? 'Failed';
    return $('capStatus').classList.add('err');
  }
  showCap(data.maxMbps);
};

async function start() {
  const r = await api('/api/config');
  if (r.status === 401) return show('login');
  const { library } = await r.json();
  $('tabLibrary').classList.toggle('hide', !library);
  show('main');
  showCap((await (await api('/api/settings')).json()).maxMbps);
  refresh();
}

start();
