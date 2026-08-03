import express, { type Request, type RequestHandler } from 'express';
import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export type Config = {
  dataDir: string;
  libraryDir: string;
  adminPassword: string;
  publicUrl?: string;
};

export type Link = {
  token: string;
  name: string;
  filePath: string;
  owned: number;
  size: number;
  pw: string | null;
  status: 'pending' | 'zipping' | 'ready' | 'error';
  expires: number;
  maxDownloads: number | null;
  downloads: number;
  created: number;
};

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const bytes = (n: number) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) (n /= 1024), i++;
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
};

const cookies = (req: Request): Record<string, string> =>
  Object.fromEntries(
    (req.headers.cookie ?? '')
      .split(';')
      .map((c) => {
        const i = c.indexOf('=');
        return i < 0 ? ['', ''] : [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1))];
      })
      .filter(([k]) => k),
  );

/** Constant-time compare that also hides length. */
const sameSecret = (a: string, b: string) =>
  timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());

export function createApp(cfg: Config) {
  const filesDir = path.join(cfg.dataDir, 'files');
  fs.mkdirSync(filesDir, { recursive: true });

  const secretFile = path.join(cfg.dataDir, 'secret');
  if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, randomBytes(32).toString('hex'), { mode: 0o600 });
  const SECRET = fs.readFileSync(secretFile);

  // Resolve once so containment checks compare real paths, not symlink aliases.
  const LIB = fs.existsSync(cfg.libraryDir) ? fs.realpathSync(cfg.libraryDir) : '';

  const db = new DatabaseSync(path.join(cfg.dataDir, 'handoff.db'));
  db.exec('PRAGMA journal_mode = WAL');
  db.exec(`CREATE TABLE IF NOT EXISTS links (
    token TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    filePath TEXT NOT NULL,
    owned INTEGER NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    pw TEXT,
    status TEXT NOT NULL,
    expires INTEGER NOT NULL,
    maxDownloads INTEGER,
    downloads INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
  )`);

  const q = {
    get: db.prepare('SELECT * FROM links WHERE token = ?'),
    all: db.prepare('SELECT * FROM links ORDER BY created DESC'),
    insert: db.prepare(
      `INSERT INTO links (token, name, filePath, owned, size, pw, status, expires, maxDownloads, downloads, created)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    ),
    finish: db.prepare('UPDATE links SET status = ?, size = ? WHERE token = ?'),
    count: db.prepare('UPDATE links SET downloads = downloads + 1 WHERE token = ?'),
    del: db.prepare('DELETE FROM links WHERE token = ?'),
    dead: db.prepare(
      'SELECT * FROM links WHERE expires <= ? OR (maxDownloads IS NOT NULL AND downloads >= maxDownloads)',
    ),
  };
  const get = (token: string) => q.get.get(token) as Link | undefined;

  // ---- signing -------------------------------------------------------------
  const mac = (v: string) => createHmac('sha256', SECRET).update(v).digest('base64url');
  const sign = (v: string) => `${v}.${mac(v)}`;
  const unsign = (s: string | undefined): string | null => {
    if (!s) return null;
    const i = s.lastIndexOf('.');
    if (i < 0) return null;
    const v = s.slice(0, i);
    return sameSecret(s.slice(i + 1), mac(v)) ? v : null;
  };

  const hashPw = (pw: string) => {
    const salt = randomBytes(16);
    return `${salt.toString('hex')}:${scryptSync(pw, salt, 32).toString('hex')}`;
  };
  const checkPw = (pw: string, stored: string) => {
    const [salt, want] = stored.split(':');
    return timingSafeEqual(Buffer.from(want, 'hex'), scryptSync(pw, Buffer.from(salt, 'hex'), 32));
  };

  // ---- library path containment -------------------------------------------
  /** Resolve a library-relative path, or null if it escapes the library root. */
  const inLibrary = (p: string): string | null => {
    if (!LIB) return null;
    const target = path.resolve(LIB, p.replace(/^[/\\]+/, ''));
    let real: string;
    try {
      real = fs.realpathSync(target);
    } catch {
      return null;
    }
    return real === LIB || real.startsWith(LIB + path.sep) ? real : null;
  };

  // ---- owned-file lifecycle ------------------------------------------------
  // Owned files always live at filesDir/<token>/. Deletion is derived from the
  // token, never from the stored path, so a link to a library file can never
  // delete the user's original.
  const ownedDir = (token: string) => path.join(filesDir, token);

  const remove = (l: Link) => {
    if (l.owned) fs.rmSync(ownedDir(l.token), { recursive: true, force: true });
    q.del.run(l.token);
  };

  const sweep = () => {
    for (const l of q.dead.all(Date.now()) as Link[]) remove(l);
  };

  const liveSize = (l: Link) => {
    if (l.status !== 'zipping') return l.size;
    try {
      return fs.statSync(l.filePath).size;
    } catch {
      return 0;
    }
  };

  const startZip = (token: string, src: string, out: string) => {
    fs.mkdirSync(path.dirname(out), { recursive: true });
    // ponytail: store-only (-0). Photos/video are already compressed, so deflate
    // buys ~nothing and costs hours on 40GB. Switch to -1 if you ever zip text.
    const p = spawn('zip', ['-r', '-0', '-q', out, path.basename(src)], {
      cwd: path.dirname(src),
      stdio: 'ignore',
    });
    const fail = () => q.finish.run('error', 0, token);
    p.on('error', fail);
    p.on('close', (code) => {
      if (code !== 0 || !fs.existsSync(out)) return fail();
      q.finish.run('ready', fs.statSync(out).size, token);
    });
  };

  // ---- app -----------------------------------------------------------------
  const app = express();
  app.set('trust proxy', true);
  app.set('x-powered-by', false);
  app.use(express.json({ limit: '1mb' }));

  const requireAdmin: RequestHandler = (req, res, next) => {
    const v = unsign(cookies(req).sess);
    if (v && Number(v) > Date.now()) return next();
    res.status(401).json({ error: 'Not signed in' });
  };

  app.post('/api/login', (req, res) => {
    if (!sameSecret(String(req.body?.password ?? ''), cfg.adminPassword)) {
      return res.status(401).json({ error: 'Wrong password' });
    }
    const until = Date.now() + 7 * 864e5;
    res.cookie('sess', sign(String(until)), { httpOnly: true, sameSite: 'lax', maxAge: 7 * 864e5 });
    res.json({ ok: true });
  });

  app.post('/api/logout', (_req, res) => {
    res.clearCookie('sess').json({ ok: true });
  });

  app.get('/healthz', (_req, res) => {
    res.type('text').send('ok');
  });

  app.get('/api/config', requireAdmin, (_req, res) => {
    res.json({ library: Boolean(LIB) });
  });

  app.get('/api/browse', requireAdmin, (req, res) => {
    const dir = inLibrary(String(req.query.p ?? ''));
    if (!dir || !fs.statSync(dir).isDirectory()) return res.status(400).json({ error: 'Bad path' });
    const entries = fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((e) => !e.name.startsWith('.'))
      .map((e) => {
        let size = 0;
        try {
          size = e.isDirectory() ? 0 : fs.statSync(path.join(dir, e.name)).size;
        } catch {}
        return { name: e.name, dir: e.isDirectory(), size };
      })
      .sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name));
    res.json({ path: path.relative(LIB, dir), hasParent: dir !== LIB, entries });
  });

  app.get('/api/links', requireAdmin, (req, res) => {
    sweep();
    const base = cfg.publicUrl?.replace(/\/+$/, '') ?? `${req.protocol}://${req.get('host')}`;
    res.json(
      (q.all.all() as Link[]).map((l) => ({
        token: l.token,
        name: l.name,
        size: liveSize(l),
        status: l.status,
        expires: l.expires,
        downloads: l.downloads,
        maxDownloads: l.maxDownloads,
        locked: Boolean(l.pw),
        url: `${base}/d/${l.token}`,
      })),
    );
  });

  app.post('/api/links', requireAdmin, (req, res) => {
    const b = req.body ?? {};
    const hours = Number(b.hours);
    if (!Number.isFinite(hours) || hours <= 0) return res.status(400).json({ error: 'Bad expiry' });

    const maxDownloads = b.maxDownloads ? Number(b.maxDownloads) : null;
    if (maxDownloads !== null && (!Number.isInteger(maxDownloads) || maxDownloads < 1)) {
      return res.status(400).json({ error: 'Bad download limit' });
    }

    const token = randomBytes(12).toString('base64url');
    const pw = b.password ? hashPw(String(b.password)) : null;
    const expires = Date.now() + hours * 3600e3;
    const row = (name: string, filePath: string, owned: number, size: number, status: Link['status']) =>
      q.insert.run(token, name, filePath, owned, size, pw, status, expires, maxDownloads, Date.now());

    if (b.source === 'library') {
      const target = inLibrary(String(b.path ?? ''));
      if (!target) return res.status(400).json({ error: 'Bad path' });
      if (fs.statSync(target).isDirectory()) {
        const name = `${path.basename(target)}.zip`;
        const out = path.join(ownedDir(token), name);
        row(name, out, 1, 0, 'zipping');
        startZip(token, target, out);
      } else {
        row(path.basename(target), target, 0, fs.statSync(target).size, 'ready');
      }
    } else if (b.source === 'upload') {
      const name = path.basename(String(b.name ?? '')).replace(/[/\\]/g, '') || 'download';
      row(name, path.join(ownedDir(token), name), 1, 0, 'pending');
    } else {
      return res.status(400).json({ error: 'Bad source' });
    }

    const base = cfg.publicUrl?.replace(/\/+$/, '') ?? `${req.protocol}://${req.get('host')}`;
    res.json({ token, url: `${base}/d/${token}` });
  });

  app.put('/api/upload/:token', requireAdmin, async (req, res) => {
    const l = get(String(req.params.token));
    if (!l || l.status !== 'pending') return res.status(404).json({ error: 'No pending upload' });

    fs.mkdirSync(ownedDir(l.token), { recursive: true });
    try {
      // pipeline (not req.pipe) so a dropped connection tears down the write
      // stream and we don't leave a half-file marked ready.
      await pipeline(req, fs.createWriteStream(l.filePath));
      const size = fs.statSync(l.filePath).size;
      q.finish.run('ready', size, l.token);
      res.json({ ok: true, size });
    } catch {
      fs.rmSync(ownedDir(l.token), { recursive: true, force: true });
      q.finish.run('error', 0, l.token);
      if (!res.headersSent) res.status(500).json({ error: 'Upload failed' });
    }
  });

  app.delete('/api/links/:token', requireAdmin, (req, res) => {
    const l = get(String(req.params.token));
    if (l) remove(l);
    res.json({ ok: true });
  });

  // ---- public download side ------------------------------------------------
  const live = (token: string): Link | undefined => {
    const l = get(token);
    if (!l) return;
    if (l.expires <= Date.now() || (l.maxDownloads !== null && l.downloads >= l.maxDownloads)) {
      remove(l);
      return;
    }
    return l;
  };

  const page = (title: string, body: string) => `<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
 :root{color-scheme:light dark}
 body{font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;padding:1rem}
 .card{max-width:26rem;width:100%;text-align:center}
 h1{font-size:1.25rem;margin:0 0 .25rem;overflow-wrap:anywhere}
 p{margin:.25rem 0;opacity:.7;font-size:.9rem}
 a.btn,button{display:inline-block;margin-top:1.25rem;padding:.7rem 1.4rem;border:0;border-radius:.5rem;
  background:#2563eb;color:#fff;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
 input{width:100%;box-sizing:border-box;margin-top:1rem;padding:.6rem;font:inherit;
  border:1px solid #8886;border-radius:.5rem;background:transparent;color:inherit}
</style>
<div class=card>${body}</div>`;

  app.get('/d/:token', (req, res) => {
    const l = live(req.params.token);
    if (!l) return res.status(404).type('html').send(page('Link expired', '<h1>This link has expired</h1>'));

    if (l.status === 'zipping') {
      return res
        .type('html')
        .set('refresh', '10')
        .send(page(l.name, `<h1>${esc(l.name)}</h1><p>Still being prepared — this page refreshes itself.</p>`));
    }
    if (l.status !== 'ready') {
      return res.status(503).type('html').send(page(l.name, '<h1>This file is not available</h1>'));
    }

    const unlocked = !l.pw || unsign(cookies(req)[`u_${l.token}`]) === l.token;
    const meta = `<p>${bytes(l.size)} — available until ${new Date(l.expires).toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    })}</p>`;

    if (!unlocked) {
      return res.type('html').send(
        page(
          l.name,
          `<h1>${esc(l.name)}</h1>${meta}
           <form method=post><input type=password name=password placeholder="Password" autofocus required>
           <button>Unlock</button></form>
           ${req.query.bad ? '<p style="color:#dc2626">Wrong password</p>' : ''}`,
        ),
      );
    }

    res.type('html').send(
      page(
        l.name,
        `<h1>${esc(l.name)}</h1>${meta}
         <a class=btn href="/f/${l.token}/${encodeURIComponent(l.name)}" download>Download</a>`,
      ),
    );
  });

  app.post('/d/:token', express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
    const l = live(req.params.token);
    if (!l?.pw) return res.redirect(303, `/d/${req.params.token}`);
    if (!checkPw(String(req.body?.password ?? ''), l.pw)) {
      return res.redirect(303, `/d/${l.token}?bad=1`);
    }
    res.cookie(`u_${l.token}`, sign(l.token), { httpOnly: true, sameSite: 'lax', maxAge: 864e5 });
    res.redirect(303, `/d/${l.token}`);
  });

  app.get('/f/:token/:name', (req, res) => {
    const l = live(req.params.token);
    if (!l || l.status !== 'ready') return res.status(404).type('text').send('Expired');
    if (l.pw && unsign(cookies(req)[`u_${l.token}`]) !== l.token) return res.redirect(303, `/d/${l.token}`);

    // Count a fresh start only, so a resumed or ranged request doesn't burn the quota.
    const range = req.headers.range;
    if (!range || /^bytes=0-/.test(range)) q.count.run(l.token);

    res.download(l.filePath, l.name, (err) => {
      if (err && !res.headersSent) res.status(404).type('text').send('Gone');
    });
  });

  app.use(express.static(path.join(HERE, '..', 'public')));

  return { app, db, sweep, config: cfg };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const adminPassword = process.env.ADMIN_PASSWORD ?? '';
  if (adminPassword.length < 8) {
    console.error('ADMIN_PASSWORD is required and must be at least 8 characters.');
    process.exit(1);
  }
  const { app, sweep } = createApp({
    dataDir: process.env.DATA_DIR ?? '/data',
    libraryDir: process.env.LIBRARY_DIR ?? '/library',
    adminPassword,
    publicUrl: process.env.PUBLIC_URL || undefined,
  });
  sweep();
  setInterval(sweep, 60_000).unref?.();
  const port = Number(process.env.PORT ?? 8080);
  app.listen(port, () => console.log(`handoff listening on :${port}`));
}
