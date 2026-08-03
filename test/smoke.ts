/**
 * One runnable check. Covers the paths that would hurt: auth, path traversal,
 * range/resume, per-link passwords, download limits, and — most importantly —
 * that expiry never deletes a file from the library share.
 *
 *   node test/smoke.ts
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
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

const original = path.join(libraryDir, 'notes.txt');
fs.writeFileSync(original, 'abcdefghij');
fs.writeFileSync(path.join(libraryDir, 'photos', 'a.txt'), 'one');
fs.writeFileSync(path.join(libraryDir, 'photos', 'b.txt'), 'two');

const PASSWORD = 'correct-horse';
const { app, db, sweep } = createApp({ dataDir, libraryDir, adminPassword: PASSWORD });
const server = app.listen(0);
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

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
assert.equal((await call('/api/links')).status, 401, 'links require auth');
assert.equal((await post('/api/login', { password: 'nope' })).status, 401, 'wrong password rejected');

const login = await post('/api/login', { password: PASSWORD });
assert.equal(login.status, 200, 'correct password accepted');
sess = grabCookie(login);
assert.ok(sess.startsWith('sess='), 'session cookie issued');
assert.equal((await call('/api/links')).status, 200, 'session works');

step('auth');

// --- path traversal ----------------------------------------------------------
for (const bad of ['../..', '/etc', '../../etc', 'photos/../../..']) {
  assert.equal((await call(`/api/browse?p=${encodeURIComponent(bad)}`)).status, 400, `browse escaped on ${bad}`);
  assert.equal((await post('/api/links', { source: 'library', path: bad, hours: 1 })).status, 400, `link escaped on ${bad}`);
}
const listing = (await (await call('/api/browse?p=')).json()) as { entries: { name: string }[] };
assert.deepEqual(
  listing.entries.map((e) => e.name),
  ['photos', 'notes.txt'],
  'directories sort first',
);

step('path traversal blocked');

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
const wrong = await fetch(`${base}/d/${locked.token}`, {
  method: 'POST',
  redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: 'password=guess',
});
assert.match(wrong.headers.get('location')!, /bad=1/, 'wrong link password rejected');
const right = await fetch(`${base}/d/${locked.token}`, {
  method: 'POST',
  redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: 'password=hunter2',
});
const unlock = grabCookie(right);
assert.ok(unlock.startsWith(`u_${locked.token}=`), 'unlock cookie issued');
const opened = await fetch(`${base}/f/${locked.token}/notes.txt`, { headers: { cookie: unlock } });
assert.equal(await opened.text(), 'abcdefghij', 'unlocked download works');

step('per-link password');

// --- folder -> zip -----------------------------------------------------------
const zipLink = await mkLink({ source: 'library', path: 'photos' });
const zipPath = path.join(dataDir, 'files', zipLink.token, 'photos.zip');
for (let i = 0; i < 100 && !fs.existsSync(zipPath); i++) await new Promise((r) => setTimeout(r, 50));
const zipped = await (async () => {
  for (let i = 0; i < 100; i++) {
    const rows = (await (await call('/api/links')).json()) as { token: string; status: string }[];
    const row = rows.find((l) => l.token === zipLink.token)!;
    if (row.status !== 'zipping') return row;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('zip never finished');
})();
assert.equal(zipped.status, 'ready', 'folder zipped');
const zipBytes = Buffer.from(await (await fetch(`${base}/f/${zipLink.token}/photos.zip`)).arrayBuffer());
assert.equal(zipBytes.subarray(0, 2).toString(), 'PK', 'served a real zip');
assert.ok(zipBytes.includes(Buffer.from('photos/a.txt')), 'zip nests entries under the folder name');

step('folder zipped');

// --- download limit ----------------------------------------------------------
const capped = await mkLink({ source: 'library', path: 'notes.txt', maxDownloads: 1 });
assert.equal((await fetch(`${base}/f/${capped.token}/notes.txt`)).status, 200, 'first download allowed');
assert.equal((await fetch(`${base}/f/${capped.token}/notes.txt`)).status, 404, 'second download refused');

step('download limit');

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
