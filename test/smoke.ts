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

// Big enough that zip is still running when the cancel check fires.
fs.mkdirSync(path.join(libraryDir, 'big'));
for (let i = 0; i < 8; i++) {
  fs.writeFileSync(path.join(libraryDir, 'big', `blob${i}.bin`), Buffer.alloc(12 << 20, i));
}

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
  ['big', 'photos', 'notes.txt'],
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
