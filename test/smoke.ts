/**
 * One runnable check. Covers the paths that would hurt: auth, path traversal,
 * range/resume, per-link passwords, download limits, the server-wide speed cap,
 * and — most importantly — that expiry never deletes a file from the library share.
 *
 *   node test/smoke.ts
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/server.ts';

// writeSync so progress survives a kill if something ever wedges
const step = (m: string) => fs.writeSync(2, `  ok  ${m}\n`);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'handoff-test-'));
const dataDir = path.join(tmp, 'data');
const libraryDir = path.join(tmp, 'library');
fs.mkdirSync(dataDir);
fs.mkdirSync(path.join(libraryDir, 'photos'), { recursive: true });

// 1 MiB, big enough to time a speed limit against.
fs.writeFileSync(path.join(libraryDir, 'rate.bin'), Buffer.alloc(1 << 20, 9));

// Planted by "someone else with write access to the share", for the zip check below.
const outside = path.join(tmp, 'outside-secret.txt');
fs.writeFileSync(outside, 'DO-NOT-LEAK');
fs.symlinkSync(outside, path.join(libraryDir, 'escape'));
fs.mkdirSync(path.join(libraryDir, 'trap'));
fs.symlinkSync(outside, path.join(libraryDir, 'trap', 'innocent.txt'));

const original = path.join(libraryDir, 'notes.txt');
fs.writeFileSync(original, 'abcdefghij');
fs.writeFileSync(path.join(libraryDir, 'photos', 'a.txt'), 'one');
fs.writeFileSync(path.join(libraryDir, 'photos', 'b.txt'), 'two');

// Big enough that zip is still running when the cancel check fires.
fs.mkdirSync(path.join(libraryDir, 'big'));
for (let i = 0; i < 8; i++) {
  fs.writeFileSync(path.join(libraryDir, 'big', `blob${i}.bin`), Buffer.alloc(12 << 20, i));
}

const PASSWORD = 'correct-horse';
// trustProxy so the throttle checks below can present distinct client IPs.
const { app, db, sweep } = createApp({ dataDir, libraryDir, adminPassword: PASSWORD, trustProxy: true });
const server = app.listen(0);
await new Promise((r) => server.once('listening', r));
const port = (server.address() as { port: number }).port;
const base = `http://127.0.0.1:${port}`;

// fetch() treats Host as a forbidden header and drops it, so anything checking Host
// handling has to go out over a raw request or it silently tests nothing.
const statusWithHost = (host: string, path: string) =>
  new Promise<number>((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, path, headers: { host, cookie: sess } }, (res) => {
      res.resume();
      resolve(res.statusCode!);
    });
    r.on('error', reject);
    r.end();
  });

let sess = '';
const call = (url: string, opts: RequestInit = {}) =>
  fetch(base + url, {
    ...opts,
    redirect: 'manual',
    headers: { cookie: sess, 'content-type': 'application/json', ...(opts.headers as object) },
  });
const post = (url: string, body: unknown) => call(url, { method: 'POST', body: JSON.stringify(body) });
const grabCookie = (r: Response) => (r.headers.getSetCookie()[0] ?? '').split(';')[0];

const mkLink = async (body: Record<string, unknown>) => {
  const r = await post('/api/links', { hours: 24, ...body });
  assert.equal(r.status, 200, `create link: ${r.status}`);
  return (await r.json()) as { token: string; url: string };
};

// --- auth --------------------------------------------------------------------
// Each of these presents its own client IP, because a wrong guess now gates the IP
// that made it — sharing one would have the checks throttling each other.
const from = (ip: string, password: string) =>
  fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
    body: JSON.stringify({ password }),
  });

assert.equal((await call('/api/links')).status, 401, 'links require auth');
assert.equal((await from('192.0.2.1', 'nope')).status, 401, 'wrong password rejected');

const login = await post('/api/login', { password: PASSWORD });
assert.equal(login.status, 200, 'correct password accepted');
sess = grabCookie(login);
assert.ok(sess.startsWith('sess='), 'session cookie issued');
assert.equal((await call('/api/links')).status, 200, 'session works');

// A wrong password shuts the door on that IP for a moment. Fire the guesses in
// PARALLEL: the bug this guards is that an awaited delay only slows the request
// doing the awaiting, so a burst used to sleep concurrently and get through whole.
const burst = await Promise.all(Array.from({ length: 50 }, (_, i) => from('203.0.113.5', `nope${i}`)));
const landed = burst.filter((r) => r.status === 401).length;
assert.ok(landed <= 2, `parallel brute force got through: ${landed} of 50 guesses were actually checked`);
assert.ok(
  burst.some((r) => r.status === 429),
  'excess guesses must be refused outright, not queued behind a sleep',
);

// Sequential guesses from one IP are gated too, not merely counted.
assert.equal((await from('203.0.113.5', 'nope')).status, 429, 'the gate stays shut while the delay runs');

// ...and one attacker must never lock the real admin out. That is why the throttle
// is keyed per IP: a global one would let anyone hold the door shut.
assert.equal((await from('198.51.100.9', PASSWORD)).status, 200, 'a different IP is unaffected');

// Security headers on every response.
const headers = (await call('/api/links')).headers;
assert.equal(headers.get('x-frame-options'), 'DENY', 'clickjacking blocked');
assert.equal(headers.get('x-content-type-options'), 'nosniff');
assert.equal(headers.get('referrer-policy'), 'no-referrer', 'share tokens do not leak via Referer');
assert.match(headers.get('content-security-policy') ?? '', /script-src 'self'/, 'no inline script allowed');

step('auth, login throttling, security headers');

// --- path traversal ----------------------------------------------------------
for (const bad of ['../..', '/etc', '../../etc', 'photos/../../..']) {
  assert.equal((await call(`/api/browse?p=${encodeURIComponent(bad)}`)).status, 400, `browse escaped on ${bad}`);
  assert.equal((await post('/api/links', { source: 'library', path: bad, hours: 1 })).status, 400, `link escaped on ${bad}`);
}
const listing = (await (await call('/api/browse?p=')).json()) as { entries: { name: string }[] };
assert.deepEqual(
  listing.entries.map((e) => e.name),
  ['big', 'photos', 'trap', 'escape', 'notes.txt', 'rate.bin'],
  'directories sort first',
);

// A symlink inside the library must not smuggle its target out. inLibrary() realpaths
// and would reject this path outright — but zipping walks the tree itself, so without
// -y the archive quietly contains whatever the link points at. The shared folder is
// writable by other people on the LAN, so planting one is not a privileged act.
assert.equal((await call('/api/browse?p=escape')).status, 400, 'a symlink out of the library is not browsable');

step('path traversal blocked');

// --- DNS rebinding -------------------------------------------------------------
// A rebound request still carries the attacker's hostname, which is what makes
// pinning Host the defence. Bare IPs stay allowed — that is how a LAN box is opened.
assert.equal(await statusWithHost('evil.example.com', '/api/links'), 403, 'foreign Host rejected');
assert.equal(await statusWithHost(`127.0.0.1:${port}`, '/api/links'), 200, 'bare IP still allowed');
assert.equal(await statusWithHost(`localhost:${port}`, '/api/links'), 200, 'localhost still allowed');
// The recipient-facing side is behind the same guard — rebinding must not reach it.
assert.equal(await statusWithHost('evil.example.com', '/healthz'), 403, 'foreign Host rejected everywhere');

step('DNS rebinding blocked by Host pinning');

// --- library file: range request + original is never touched -------------------
const fileLink = await mkLink({ source: 'library', path: 'notes.txt' });
const ranged = await fetch(`${base}/f/${fileLink.token}/notes.txt`, { headers: { range: 'bytes=2-4' } });
assert.equal(ranged.status, 206, 'range request returns 206');
assert.equal(await ranged.text(), 'cde', 'range bytes correct');
assert.equal(ranged.headers.get('content-range'), 'bytes 2-4/10');

// A resumed download must not consume the quota.
const rows = (await (await call('/api/links')).json()) as { token: string; downloads: number }[];
const after = rows.find((l) => l.token === fileLink.token)!;
assert.equal(after.downloads, 0, 'mid-file range did not count as a download');
assert.equal(await (await fetch(`${base}/f/${fileLink.token}/notes.txt`)).text(), 'abcdefghij');

step('range requests + library originals untouched');

// --- upload ------------------------------------------------------------------
const payload = Buffer.alloc(70_000, 7);
const upLink = await mkLink({ source: 'upload', name: 'evil/../wedding.zip' });
const put = await call(`/api/upload/${upLink.token}`, {
  method: 'PUT',
  body: payload,
  headers: { 'content-type': 'application/octet-stream' },
});
assert.equal(put.status, 200, 'upload accepted');
const stored = path.join(dataDir, 'files', upLink.token, 'wedding.zip');
assert.ok(fs.existsSync(stored), 'upload filename stripped to a basename inside the token dir');
const got = Buffer.from(await (await fetch(`${base}/f/${upLink.token}/wedding.zip`)).arrayBuffer());
assert.ok(got.equals(payload), 'uploaded bytes round-trip');

step('upload round-trip');

// --- per-link password -------------------------------------------------------
const locked = await mkLink({ source: 'library', path: 'notes.txt', password: 'hunter2' });
assert.equal((await fetch(`${base}/f/${locked.token}/notes.txt`, { redirect: 'manual' })).status, 303, 'locked file gated');
// Per IP, like the admin login, so these each present their own.
const unlockAs = (ip: string, password: string) =>
  fetch(`${base}/d/${locked.token}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': ip },
    body: `password=${password}`,
  });

const wrong = await unlockAs('192.0.2.10', 'guess');
assert.match(wrong.headers.get('location')!, /bad=1/, 'wrong link password rejected');

// This endpoint needs no session at all, so it is the softest brute-force target in
// the app: anyone holding the link can grind it. It gets the same gate as the login.
const linkBurst = await Promise.all(Array.from({ length: 30 }, (_, i) => unlockAs('192.0.2.11', `guess${i}`)));
const checked = linkBurst.filter((r) => /bad=1/.test(r.headers.get('location') ?? '')).length;
assert.ok(checked <= 2, `link password brute force got through: ${checked} of 30 guesses were checked`);
assert.ok(
  linkBurst.some((r) => /slow=1/.test(r.headers.get('location') ?? '')),
  'throttled unlock attempts are refused',
);

const right = await unlockAs('192.0.2.12', 'hunter2');
const unlock = grabCookie(right);
assert.ok(unlock.startsWith(`u_${locked.token}=`), 'unlock cookie issued');
const opened = await fetch(`${base}/f/${locked.token}/notes.txt`, { headers: { cookie: unlock } });
assert.equal(await opened.text(), 'abcdefghij', 'unlocked download works');

step('per-link password');

// --- folders: browse in, share as a zip --------------------------------------
const sub = (await (await call('/api/browse?p=photos')).json()) as {
  entries: { name: string }[];
  hasParent: boolean;
};
assert.deepEqual(sub.entries.map((e) => e.name), ['a.txt', 'b.txt'], 'can browse into a subfolder');
assert.ok(sub.hasParent, 'subfolder offers a way back up');

const untilReady = async (token: string) => {
  for (let i = 0; i < 200; i++) {
    const rows = (await (await call('/api/links')).json()) as { token: string; status: string }[];
    const row = rows.find((l) => l.token === token);
    if (row && row.status !== 'zipping') return row;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('zip never finished');
};

const zipLink = await mkLink({ source: 'library', path: 'photos' });
assert.equal((await untilReady(zipLink.token)).status, 'ready', 'folder zipped');
const zipBytes = Buffer.from(await (await fetch(`${base}/f/${zipLink.token}/photos.zip`)).arrayBuffer());
assert.equal(zipBytes.subarray(0, 2).toString(), 'PK', 'served a real zip');
assert.ok(zipBytes.includes(Buffer.from('photos/a.txt')), 'zip nests entries under the folder name');
// Store-only: entries are the literal file bytes, no compression to undo.
assert.ok(zipBytes.includes(Buffer.from('one')) && zipBytes.includes(Buffer.from('two')), 'stored, not deflated');

// The originals are still there after we archived them.
assert.equal(fs.readFileSync(path.join(libraryDir, 'photos', 'a.txt'), 'utf8'), 'one', 'zipping did not move the source');

// The planted symlink has to be stored AS a link. Without -y, zip archives the bytes
// it points at, and the containment inLibrary() enforces everywhere else is bypassed
// by the one code path that walks the tree on its own.
const trapLink = await mkLink({ source: 'library', path: 'trap' });
assert.equal((await untilReady(trapLink.token)).status, 'ready', 'trap folder zipped');
const trapBytes = Buffer.from(await (await fetch(`${base}/f/${trapLink.token}/trap.zip`)).arrayBuffer());
assert.ok(!trapBytes.includes(Buffer.from('DO-NOT-LEAK')), 'zip followed a symlink out of the library');

// Deleting a link mid-zip must cancel the job and take the partial archive with it.
const doomed = await mkLink({ source: 'library', path: 'big' });
const doomedDir = path.join(dataDir, 'files', doomed.token);
const midFlight = (await (await call('/api/links')).json()) as { token: string; status: string }[];
assert.equal(
  midFlight.find((l) => l.token === doomed.token)!.status,
  'zipping',
  'cancel check is racing a real in-progress zip',
);
assert.equal((await call(`/api/links/${doomed.token}`, { method: 'DELETE' })).status, 200);
await new Promise((r) => setTimeout(r, 500));
assert.ok(!fs.existsSync(doomedDir), 'cancelled zip left nothing behind');
assert.ok(fs.existsSync(path.join(libraryDir, 'big', 'blob0.bin')), 'cancelling did not touch the source');

step('folders browse, zip, and cancel cleanly');

// --- download limit ----------------------------------------------------------
const capped = await mkLink({ source: 'library', path: 'notes.txt', maxDownloads: 1 });
assert.equal((await fetch(`${base}/f/${capped.token}/notes.txt`)).status, 200, 'first download allowed');
assert.equal((await fetch(`${base}/f/${capped.token}/notes.txt`)).status, 404, 'second download refused');

// 0 used to fall through a falsiness check and mean "no limit" — a link nobody can
// download is nonsense, so it must be refused, and on create just like on edit.
assert.equal(
  (await post('/api/links', { source: 'library', path: 'notes.txt', hours: 1, maxDownloads: 0 })).status,
  400,
  'zero download limit refused on create',
);

step('download limit');

// --- range edge cases --------------------------------------------------------
const MiB = 1 << 20;
const rate = await mkLink({ source: 'library', path: 'rate.bin' });

const tail = await fetch(`${base}/f/${rate.token}/rate.bin`, { headers: { range: 'bytes=1048570-' } });
assert.equal(tail.status, 206);
assert.equal(tail.headers.get('content-range'), `bytes 1048570-${MiB - 1}/${MiB}`);
assert.equal((await tail.arrayBuffer()).byteLength, 6, 'open-ended range');

const suffix = await fetch(`${base}/f/${rate.token}/rate.bin`, { headers: { range: 'bytes=-100' } });
assert.equal(suffix.status, 206, 'bytes=-N means the last N bytes');
assert.equal((await suffix.arrayBuffer()).byteLength, 100);

// Unsatisfiable ranges are refused, not quietly served whole.
const bad = await fetch(`${base}/f/${rate.token}/rate.bin`, { headers: { range: 'bytes=99999999-' } });
assert.equal(bad.status, 416, 'unsatisfiable range');
assert.equal(bad.headers.get('content-range'), `bytes */${MiB}`);

// HEAD reports the size without sending a body.
const head = await fetch(`${base}/f/${rate.token}/rate.bin`, { method: 'HEAD' });
assert.equal(head.headers.get('content-length'), String(MiB));
assert.equal(head.headers.get('accept-ranges'), 'bytes');

step('range edge cases');

// --- editing a live link ------------------------------------------------------
// The token has to survive an edit, or every change would strand whoever already
// has the link.
const ed = await mkLink({ source: 'library', path: 'notes.txt', hours: 1, maxDownloads: 2 });
const patch = (body: unknown) => call(`/api/links/${ed.token}`, { method: 'PATCH', body: JSON.stringify(body) });
const readLink = async () =>
  ((await (await call('/api/links')).json()) as { token: string; expires: number; maxDownloads: number | null }[]).find(
    (l) => l.token === ed.token,
  )!;

const before = await readLink();
assert.equal((await patch({ hours: 48 })).status, 200, 'expiry extended');
assert.ok((await readLink()).expires > before.expires, 'extending moved the expiry out');
assert.equal((await fetch(`${base}/f/${ed.token}/notes.txt`)).status, 200, 'the same token still works after an edit');

// Absent keys must not be touched — raising a limit can't silently reset the clock.
const extended = await readLink();
assert.equal((await patch({ maxDownloads: 5 })).status, 200, 'limit raised');
const afterLimit = await readLink();
assert.equal(afterLimit.maxDownloads, 5, 'new limit stored');
assert.equal(afterLimit.expires, extended.expires, 'editing the limit left the expiry alone');

assert.equal((await patch({ maxDownloads: null })).status, 200, 'limit cleared');
assert.equal((await readLink()).maxDownloads, null, 'cleared limit persisted as unlimited');

// One download has happened (the token check above), so a limit of 1 would delete
// the link on the next sweep. That has to be refused rather than silently obeyed.
const suicide = await patch({ maxDownloads: 1 });
assert.equal(suicide.status, 400, 'limit at or below the count refused');
assert.match(((await suicide.json()) as { error: string }).error, /already downloaded/i, 'refusal says why');
assert.ok(await readLink(), 'refused edit left the link alive');

// The UI's minute picker sends a fraction of an hour, which has to land as a whole
// millisecond — the expires column is an INTEGER.
const nowish = Date.now();
assert.equal((await patch({ hours: 5 / 60 })).status, 200, 'sub-hour expiry accepted');
const minutes = (await readLink()).expires;
assert.ok(Number.isInteger(minutes), 'fractional hours stored as whole milliseconds');
assert.ok(Math.abs(minutes - (nowish + 300_000)) < 2000, 'five minutes landed five minutes out');

assert.equal((await patch({ hours: 0 })).status, 400, 'zero expiry refused');
assert.equal((await patch({ maxDownloads: 2.5 })).status, 400, 'fractional limit refused');
assert.equal((await call('/api/links/nope', { method: 'PATCH', body: '{}' })).status, 404, 'unknown token 404s');

const savedSess = sess;
sess = '';
assert.equal((await patch({ hours: 1 })).status, 401, 'editing requires auth');
sess = savedSess;

step('links are editable in place, without reissuing the token');

// --- server-wide speed limit -------------------------------------------------
// A second deployment, capped globally, to check the limit applies across
// different links rather than only within one.
const capDir = fs.mkdtempSync(path.join(os.tmpdir(), 'handoff-cap-'));
fs.mkdirSync(path.join(capDir, 'data'));
const capped2 = createApp({
  dataDir: path.join(capDir, 'data'),
  libraryDir,
  adminPassword: PASSWORD,
  maxMbps: 16, // 2 MB/s for the whole server
});
const capServer = capped2.app.listen(0);
await new Promise((r) => capServer.once('listening', r));
const capBase = `http://127.0.0.1:${(capServer.address() as { port: number }).port}`;

const capLogin = await fetch(`${capBase}/api/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ password: PASSWORD }),
});
const capSess = (capLogin.headers.getSetCookie()[0] ?? '').split(';')[0];
const capLink = async () => {
  const r = await fetch(`${capBase}/api/links`, {
    method: 'POST',
    headers: { cookie: capSess, 'content-type': 'application/json' },
    body: JSON.stringify({ source: 'library', path: 'rate.bin', hours: 1 }),
  });
  return ((await r.json()) as { token: string }).token;
};

assert.equal(
  ((await (await fetch(`${capBase}/api/settings`, { headers: { cookie: capSess } })).json()) as { maxMbps: number })
    .maxMbps,
  16,
  'MAX_MBPS seeded the stored setting',
);

// Two *different* links, downloaded together, must still share the one budget.
const [a, b] = [await capLink(), await capLink()];
const t0 = performance.now();
await Promise.all([
  fetch(`${capBase}/f/${a}/rate.bin`).then((r) => r.arrayBuffer()),
  fetch(`${capBase}/f/${b}/rate.bin`).then((r) => r.arrayBuffer()),
]);
const bothMs = performance.now() - t0;
assert.ok(bothMs > 700, `global cap not shared across links: ${bothMs.toFixed(0)}ms for 2MiB at 2MB/s`);

// Raising the limit through the settings API takes effect immediately.
await fetch(`${capBase}/api/settings`, {
  method: 'PUT',
  headers: { cookie: capSess, 'content-type': 'application/json' },
  body: JSON.stringify({ maxMbps: null }),
});
const liftedT0 = performance.now();
await fetch(`${capBase}/f/${a}/rate.bin`).then((r) => r.arrayBuffer());
const liftedMs = performance.now() - liftedT0;
assert.ok(liftedMs < 300, `removing the cap did not take effect: ${liftedMs.toFixed(0)}ms`);

assert.equal(
  (await (await fetch(`${capBase}/api/settings`, { headers: { cookie: capSess } })).json() as { maxMbps: null })
    .maxMbps,
  null,
  'cleared limit persisted',
);
const capBad = await fetch(`${capBase}/api/settings`, {
  method: 'PUT',
  headers: { cookie: capSess, 'content-type': 'application/json' },
  body: JSON.stringify({ maxMbps: -5 }),
});
assert.equal(capBad.status, 400, 'negative speed limit refused');

capServer.closeAllConnections();
capServer.close();
capped2.db.close();
fs.rmSync(capDir, { recursive: true, force: true });

step('server-wide speed limit, live-editable');

// --- deployment theme ---------------------------------------------------------
// /theme.css carries the whole light/dark decision, so the recipient pages need no
// inline script. Each mode has to emit the right thing, and saving one setting must
// not clobber the other.
const themeCss = async () => (await fetch(`${base}/theme.css`)).text();
const putSetting = (body: unknown) => call('/api/settings', { method: 'PUT', body: JSON.stringify(body) });

assert.match(await themeCss(), /^@media \(prefers-color-scheme: dark\)/, 'default theme follows the visitor');

await putSetting({ theme: 'dark' });
const forcedDark = await themeCss();
assert.ok(!forcedDark.includes('@media (prefers-color-scheme'), 'forced dark must not be conditional');
assert.match(forcedDark, /color-scheme:\s*dark/, 'forced dark still ships the dark variant');

await putSetting({ theme: 'light' });
assert.equal((await themeCss()).trim(), '', 'light is style.css alone');

assert.equal((await putSetting({ theme: 'neon' })).status, 400, 'unknown theme refused');
assert.equal(
  ((await (await call('/api/settings')).json()) as { theme: string }).theme,
  'light',
  'refused theme left the stored one alone',
);

// A recipient is never signed in, so the download pages must still get their theme.
assert.equal((await fetch(`${base}/theme.css`, { headers: {} })).status, 200, 'theme.css is public');

// The regression this endpoint invites: two settings behind one PUT.
await putSetting({ maxMbps: 50 });
await putSetting({ theme: 'auto' });
assert.equal(
  ((await (await call('/api/settings')).json()) as { maxMbps: number }).maxMbps,
  50,
  'saving the theme cleared the speed limit',
);
await putSetting({ maxMbps: null });

step('deployment theme, and settings save independently');

// --- changing the admin password invalidates open sessions --------------------
{
  const rotDir = fs.mkdtempSync(path.join(os.tmpdir(), 'handoff-rotate-'));
  fs.mkdirSync(path.join(rotDir, 'data'));
  const cfg = { dataDir: path.join(rotDir, 'data'), libraryDir, adminPassword: 'first-password' };

  const one = createApp(cfg);
  const s1 = one.app.listen(0);
  await new Promise((r) => s1.once('listening', r));
  const p1 = (s1.address() as { port: number }).port;
  const cookie = (
    await fetch(`http://127.0.0.1:${p1}/api/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'first-password' }),
    })
  ).headers.getSetCookie()[0].split(';')[0];
  assert.equal((await fetch(`http://127.0.0.1:${p1}/api/links`, { headers: { cookie } })).status, 200);
  s1.closeAllConnections();
  s1.close();
  one.db.close();

  // Same data directory, new password — the old session cookie must be dead.
  const two = createApp({ ...cfg, adminPassword: 'second-password' });
  const s2 = two.app.listen(0);
  await new Promise((r) => s2.once('listening', r));
  const p2 = (s2.address() as { port: number }).port;
  assert.equal(
    (await fetch(`http://127.0.0.1:${p2}/api/links`, { headers: { cookie } })).status,
    401,
    'session survived a password change',
  );
  s2.closeAllConnections();
  s2.close();
  two.db.close();
  fs.rmSync(rotDir, { recursive: true, force: true });
}

step('password rotation kills open sessions');

// --- links with no expiry -----------------------------------------------------
// Stored as a sentinel rather than NULL, so the thing worth proving is that the
// sweep leaves it alone and that nobody ever sees the year-275760 date.
const forever = await mkLink({ source: 'library', path: 'notes.txt', hours: null });
const foreverRow = async () =>
  ((await (await call('/api/links')).json()) as { token: string; expires: number | null }[]).find(
    (l) => l.token === forever.token,
  );
assert.equal((await foreverRow())!.expires, null, 'no-expiry link reports null, not a sentinel');
sweep();
assert.ok(await foreverRow(), 'sweep left the no-expiry link alone');
assert.match(await (await fetch(`${base}/d/${forever.token}`)).text(), /Never/, 'download page says Never');

assert.equal(
  (await post('/api/links', { source: 'library', path: 'notes.txt' })).status,
  400,
  'omitted expiry is refused, not treated as never',
);

// Expiry can be removed from, and put back on, a link that already exists.
assert.equal((await patch({ hours: null })).status, 200, 'expiry removed from a live link');
assert.equal((await readLink()).expires, null, 'removal persisted');
assert.equal((await patch({ hours: 1 })).status, 200, 'expiry put back');
assert.ok((await readLink()).expires! > Date.now(), 'restored expiry is in the future');

step('links can have no expiry at all');

// --- expiry: owned files deleted, library originals untouched -----------------
db.prepare('UPDATE links SET expires = ?').run(Date.now() - 1000);
sweep();
assert.equal(((await (await call('/api/links')).json()) as unknown[]).length, 0, 'expired links purged');
assert.ok(!fs.existsSync(stored), 'expiry deleted the uploaded file');
assert.ok(!fs.existsSync(path.join(dataDir, 'files', upLink.token)), 'expiry removed the token directory');
assert.equal(fs.readFileSync(original, 'utf8'), 'abcdefghij', 'expiry did NOT touch the library original');
assert.ok(fs.existsSync(path.join(libraryDir, 'photos', 'a.txt')), 'library folder intact');
assert.equal((await fetch(`${base}/d/${fileLink.token}`)).status, 404, 'expired link 404s');

step('expiry deletes owned files only');

server.closeAllConnections(); // undici keeps sockets alive; close() alone would hang
server.close();
db.close();
fs.rmSync(tmp, { recursive: true, force: true });
console.log('smoke: all checks passed');
