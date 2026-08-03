const $ = (id) => document.getElementById(id);
const api = (url, opts) => fetch(url, { ...opts, headers: { 'content-type': 'application/json', ...opts?.headers } });

const fmt = (n) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) (n /= 1024), i++;
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
};
const when = (ms) => new Date(ms).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

// Extension chip, shown only in the light variant. Text beats an emoji table:
// no lookup to maintain and it renders identically everywhere.
const ext = (name) => (/\.([a-z0-9]{1,4})$/i.exec(name)?.[1] ?? 'file').toUpperCase();

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

// togglePopover(force) rather than showPopover(), which throws if it's already open —
// and optional-call so an old browser degrades to the #status line instead of
// breaking the rest of the handler.
let toastTimer;
const toast = (msg) => {
  const t = $('toast');
  t.textContent = msg;
  t.togglePopover?.(true);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.togglePopover?.(false), 3000);
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

  const copied = await copy(data.url);
  $('status').textContent = `${copied ? 'Link copied' : 'Link ready'}: ${data.url}`;
  toast(copied ? 'Link copied to clipboard' : 'Link ready — copy it from below');
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
  // Rebuilding the rows detaches whatever the open menu was anchored to. Closing
  // it outright would make the menu snap shut under the pointer every 3s while a
  // zip polls, so re-point it at the new button instead and only close it if the
  // link it belongs to is actually gone.
  const openFor = $('rowMenu').matches(':popover-open') ? menuFor?.token : null;
  $('links').innerHTML = '';
  $('noLinks').classList.toggle('hide', links.length > 0);
  $('count').textContent = links.length ? `${links.length} active ${links.length === 1 ? 'link' : 'links'}` : '';

  for (const l of links) {
    const li = document.createElement('li');
    // Structure via innerHTML, user-controlled text via textContent below.
    li.innerHTML = `<span class="ic"></span>
      <div class="main"><div class="nm"></div><code class="url"></code></div>
      <div class="stats">
        <div class="stat size"><span class="k">Size</span><span class="v"></span></div>
        <div class="stat"><span class="k">Expires</span><span class="v"></span></div>
        <div class="stat"><span class="k">Downloads</span><span class="v"></span></div>
      </div>
      <div class="acts">
        <button type="button" class="btn small dots">⋯</button>
      </div>`;

    li.querySelector('.ic').textContent = ext(l.name);
    li.querySelector('.nm').textContent = l.name;
    if (l.locked) {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = 'Password';
      li.querySelector('.nm').append(' ', chip);
    }
    li.querySelector('.url').textContent = l.url;

    const [size, expires, downloads] = li.querySelectorAll('.stat .v');
    size.textContent =
      l.status === 'zipping' ? `zipping… ${fmt(l.size)}` : l.status === 'ready' ? fmt(l.size) : l.status;
    expires.textContent = when(l.expires);
    downloads.textContent = l.maxDownloads ? `${l.downloads} / ${l.maxDownloads}` : l.downloads;

    // Three identical ⋯ buttons need to be told apart by anything reading the page.
    const dots = li.querySelector('.dots');
    dots.setAttribute('aria-label', `Actions for ${l.name}`);
    // Light dismiss has already closed the menu by the time click runs, so which
    // row it belonged to has to be captured on the way down.
    dots.onpointerdown = () => (openAtPress = $('rowMenu').matches(':popover-open') ? menuAnchor : null);
    dots.onclick = () => {
      const menu = $('rowMenu');
      const reclick = openAtPress === dots;
      openAtPress = null;
      // Always close first: reopening is what re-fires beforetoggle, and without it
      // a menu that's already open would keep the previous row's position.
      menu.togglePopover(false);
      if (reclick) return;
      menuFor = l;
      menuAnchor = dots;
      menu.togglePopover(true);
    };
    if (openFor === l.token) ((menuFor = l), (menuAnchor = dots));

    $('links').append(li);
  }
  if (openFor && !links.some((l) => l.token === openFor)) $('rowMenu').togglePopover?.(false);

  // Keep polling while a zip is building so the size ticks up.
  if (links.some((l) => l.status === 'zipping')) setTimeout(refresh, 3000);
}

// ---- row menu ------------------------------------------------------------
// One menu for every row rather than one per row: the row only has to say which
// link it stands for.
//
// Open/close is driven from JS rather than popovertarget. The declarative version
// can't express "move to another row": with the default toggle action a second
// row's button closes the open menu, and with action="show" the menu stays put
// while its actions retarget to the new row — visibly pointing at one link while
// acting on another.
let menuFor = null;
let menuAnchor = null;
let openAtPress = null;

// beforetoggle, not toggle: it fires synchronously before the menu is shown, so the
// position lands in the same frame it becomes visible. toggle is queued as a task,
// which meant the browser painted the menu at its previous spot — or at 0,0 the
// first time — and only then moved it.
$('rowMenu').addEventListener('beforetoggle', (e) => {
  if (e.newState !== 'open' || !menuAnchor) return;
  const m = $('rowMenu');
  const a = menuAnchor.getBoundingClientRect();

  // Anchor to edges rather than corners so nothing has to be measured: `right`
  // aligns to the button without knowing the menu's width, and `bottom` flips it
  // above without knowing its height. Measuring is what forced this to wait until
  // the menu was visible in the first place.
  m.style.left = 'auto';
  m.style.right = `${Math.max(8, innerWidth - a.right)}px`;

  // Buttons in the lower half open upward. A three-item menu always fits in half a
  // viewport, so this needs no height and is right on the very first open.
  if (a.bottom > innerHeight / 2) {
    m.style.top = 'auto';
    m.style.bottom = `${innerHeight - a.top + 4}px`;
  } else {
    m.style.bottom = 'auto';
    m.style.top = `${a.bottom + 4}px`;
  }
});

$('rowMenu').addEventListener('toggle', (e) => {
  // Focus has to wait until it's actually visible — you can't focus display: none.
  // #rowMenu sits at the end of the body, so tabbing from the button would
  // otherwise walk the whole page before reaching the menu.
  if (e.newState === 'open') $('rowMenu').querySelector('.menu-item').focus();
});

const copyLink = async (l) =>
  toast((await copy(l.url)) ? 'Link copied to clipboard' : 'Could not copy — select the link and copy it');

const deleteLink = async (l) => {
  const what = l.status === 'zipping' ? `Cancel zipping ${l.name}?` : `Delete the link for ${l.name}?`;
  if (!confirm(what)) return;
  await api(`/api/links/${l.token}`, { method: 'DELETE' });
  toast('Link deleted');
  refresh();
};

for (const item of $('rowMenu').querySelectorAll('[data-menu]')) {
  item.onclick = () => {
    const l = menuFor;
    $('rowMenu').togglePopover?.(false);
    ({ copy: copyLink, edit: openEdit, del: deleteLink })[item.dataset.menu](l);
  };
}

// ---- editing a live link -------------------------------------------------
// The token never changes, so extending an expiry or raising a limit fixes the
// link someone already has rather than making them chase a new one.
let editing = null;

function openEdit(l) {
  editing = l;
  $('editName').textContent = l.name;
  // Blank by default: the expiry only moves if it's explicitly chosen, so raising
  // a download limit doesn't quietly restart the clock too.
  $('editHours').value = '';
  $('editExpiry').textContent = `Currently expires ${when(l.expires)}`;
  $('editMax').value = l.maxDownloads ?? '';
  $('editDownloads').textContent = l.downloads
    ? `Downloaded ${l.downloads} ${l.downloads === 1 ? 'time' : 'times'} so far`
    : 'Not downloaded yet';
  $('editErr').textContent = '';
  $('edit').showModal();
}

$('editCancel').onclick = () => $('edit').close();

$('editForm').onsubmit = async (e) => {
  e.preventDefault();
  const body = { maxDownloads: $('editMax').value || null };
  if ($('editHours').value) body.hours = Number($('editHours').value);

  const r = await api(`/api/links/${editing.token}`, { method: 'PATCH', body: JSON.stringify(body) });
  if (!r.ok) return ($('editErr').textContent = (await r.json()).error ?? 'Could not save');

  $('edit').close();
  toast('Link updated');
  refresh();
};

// ---- auth ----------------------------------------------------------------
function show(view) {
  $('auth').classList.toggle('hide', view !== 'login');
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

$('saveTheme').onclick = async () => {
  const r = await api('/api/settings', { method: 'PUT', body: JSON.stringify({ theme: $('theme').value }) });
  if (!r.ok) {
    $('themeStatus').textContent = (await r.json()).error ?? 'Failed';
    return $('themeStatus').classList.add('err');
  }
  // The theme is resolved server-side into /theme.css, so it lands on a fresh load.
  location.reload();
};

async function start() {
  const r = await api('/api/config');
  if (r.status === 401) return show('login');
  const { library } = await r.json();
  $('tabLibrary').classList.toggle('hide', !library);
  show('main');
  const settings = await (await api('/api/settings')).json();
  showCap(settings.maxMbps);
  $('theme').value = settings.theme;
  refresh();
}

start();
