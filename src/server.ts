import express, { type Request, type RequestHandler } from 'express';
import { DatabaseSync } from 'node:sqlite';
import { createHmac, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { spawn, type ChildProcess } from 'node:child_process';
import { Transform } from 'node:stream';
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
  /** Seeds the server-wide speed limit on first boot only; the UI owns it after that. */
  maxMbps?: number;
  /** Only set this when a reverse proxy really is in front: it makes X-Forwarded-For
   *  authoritative for req.ip, which the login throttle keys on. Left off, any client
   *  could spoof the header and get a fresh throttle bucket per request. */
  trustProxy?: boolean | string;
  /** Extra Host values to accept, beyond publicUrl, localhost and bare IPs. */
  allowedHosts?: string[];
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

const MBPS = 125_000; // bytes/sec in one megabit/sec

// "Never expires" is stored as the largest timestamp JS can represent rather than
// NULL: every comparison (the sweep query, live()) keeps working untouched, and no
// existing database has to be rebuilt to drop the NOT NULL on expires.
const NEVER = 8.64e15;
const never = (expires: number) => expires >= NEVER;

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

/** Async so a flood of login attempts uses the threadpool instead of stalling
 *  the event loop for everyone downloading. */
const derive = promisify(scrypt) as (pw: string, salt: Buffer, len: number) => Promise<Buffer>;

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
  db.exec('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');

  const q = {
    get: db.prepare('SELECT * FROM links WHERE token = ?'),
    all: db.prepare('SELECT * FROM links ORDER BY created DESC'),
    insert: db.prepare(
      `INSERT INTO links (token, name, filePath, owned, size, pw, status, expires, maxDownloads, downloads, created)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    ),
    finish: db.prepare('UPDATE links SET status = ?, size = ? WHERE token = ?'),
    edit: db.prepare('UPDATE links SET expires = ?, maxDownloads = ? WHERE token = ?'),
    count: db.prepare('UPDATE links SET downloads = downloads + 1 WHERE token = ?'),
    del: db.prepare('DELETE FROM links WHERE token = ?'),
    dead: db.prepare(
      'SELECT * FROM links WHERE expires <= ? OR (maxDownloads IS NOT NULL AND downloads >= maxDownloads)',
    ),
    getSetting: db.prepare('SELECT value FROM settings WHERE key = ?'),
    setSetting: db.prepare(
      'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    ),
  };
  const get = (token: string) => q.get.get(token) as Link | undefined;

  // Deriving the admin password costs ~100ms, which is what stops an exposed
  // login endpoint from being brute-forceable at network speed.
  const adminHash = scryptSync(cfg.adminPassword, SECRET, 32);
  // Sessions are signed with a key derived from the password, so changing
  // ADMIN_PASSWORD immediately invalidates every session that was already open.
  const sessionKey = createHmac('sha256', SECRET).update(adminHash).digest();

  // ---- signing -------------------------------------------------------------
  const mac = (key: Buffer, v: string) => createHmac('sha256', key).update(v).digest('base64url');
  const sign = (key: Buffer, v: string) => `${v}.${mac(key, v)}`;
  const unsign = (key: Buffer, s: string | undefined): string | null => {
    if (!s) return null;
    const i = s.lastIndexOf('.');
    if (i < 0) return null;
    const v = s.slice(0, i);
    const got = Buffer.from(s.slice(i + 1));
    const want = Buffer.from(mac(key, v));
    return got.length === want.length && timingSafeEqual(got, want) ? v : null;
  };

  const hashPw = (pw: string) => {
    const salt = randomBytes(16);
    return `${salt.toString('hex')}:${scryptSync(pw, salt, 32).toString('hex')}`;
  };
  const checkPw = async (pw: string, stored: string) => {
    const [salt, want] = stored.split(':');
    return timingSafeEqual(Buffer.from(want, 'hex'), await derive(pw, Buffer.from(salt, 'hex'), 32));
  };

  // ---- password-guess throttle ---------------------------------------------
  // Refusing early beats sleeping. `await setTimeout` only delays the request
  // doing the awaiting, so N guesses fired in parallel all sleep at the same time
  // and all get through — 200 concurrent guesses cost about as long as one.
  // A gate that rejects has no such bypass: the attacker's next attempt is refused
  // outright until the delay has actually elapsed.
  //
  // Keyed per IP, not globally, because a global gate is a lockout: whoever is
  // hammering the endpoint would hold the door shut on the real admin. Per IP an
  // attacker only ever throttles themselves.
  const guesses = new Map<string, { n: number; until: number }>();

  const who = (req: Request) => req.ip ?? req.socket.remoteAddress ?? '?';
  const blocked = (key: string) => (guesses.get(key)?.until ?? 0) > Date.now();

  const missed = (key: string) => {
    const g = guesses.get(key) ?? { n: 0, until: 0 };
    g.n++;
    g.until = Date.now() + Math.min(g.n * 250, 5000);
    guesses.set(key, g);
  };

  const tooMany = { error: 'Too many attempts — wait a few seconds and try again' };

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
  // Uploads live at filesDir/<token>/ and are the only files Handoff may delete.
  // Deletion is derived from the token, never from the stored path, so a link to
  // a library file can never reach the user's original.
  const ownedDir = (token: string) => path.join(filesDir, token);

  /** In-flight zip jobs, so deleting a link actually cancels the work. */
  const zipping = new Map<string, ChildProcess>();

  // ---- speed limiting ------------------------------------------------------
  // One token bucket for the whole deployment, shared by every active download.
  // Sharing is the point: a 500 Mbps cap has to mean 500 total across everyone,
  // not 500 per downloader, or it doesn't protect the uplink at all.
  type Bucket = { rate: number; tokens: number; last: number };
  const newBucket = (rate: number): Bucket => ({ rate, tokens: 0, last: Date.now() });

  // Reassigned when the admin changes the limit. The throttle reads it per chunk,
  // so a change takes effect on downloads that are already running.
  let globalBucket: Bucket | null = null;

  // ---- theme ---------------------------------------------------------------
  // Deployment-wide, not per-visitor: the admin picks how Handoff looks for
  // everyone, including the recipients who never see the admin UI.
  const THEMES = ['auto', 'light', 'dark'] as const;
  type Theme = (typeof THEMES)[number];
  const isTheme = (v: unknown): v is Theme => THEMES.includes(v as Theme);

  const readTheme = (): Theme => {
    const v = (q.getSetting.get('theme') as { value: string } | undefined)?.value;
    return isTheme(v) ? v : 'auto';
  };

  const readMax = (): number | null => {
    const row = q.getSetting.get('maxMbps') as { value: string } | undefined;
    const n = Number(row?.value);
    return Number.isFinite(n) && n > 0 ? n : null;
  };

  const applyMax = (mbps: number | null) => {
    q.setSetting.run('maxMbps', mbps === null ? '' : String(mbps));
    globalBucket = mbps === null ? null : newBucket(mbps * MBPS);
  };

  // MAX_MBPS seeds the setting on first boot; after that the UI is the source of truth.
  applyMax(q.getSetting.get('maxMbps') ? readMax() : (cfg.maxMbps ?? null));

  /** How long `n` bytes must wait. Credit is capped at 100ms so an idle link
   *  can't bank a burst that blows past the cap the moment someone connects. */
  const waitFor = (b: Bucket, n: number) => {
    const now = Date.now();
    b.tokens = Math.min(b.rate / 10, b.tokens + ((now - b.last) * b.rate) / 1000);
    b.last = now;
    b.tokens -= n;
    return b.tokens >= 0 ? 0 : Math.ceil((-b.tokens * 1000) / b.rate);
  };

  /** Paces a download against the server-wide cap, read per chunk so a limit
   *  changed mid-transfer applies to downloads already running. */
  const throttle = () =>
    new Transform({
      transform(chunk: Buffer, _enc, cb) {
        const wait = globalBucket ? waitFor(globalBucket, chunk.length) : 0;
        if (wait) setTimeout(cb, wait, null, chunk);
        else cb(null, chunk);
      },
    });

  const remove = (l: Link) => {
    zipping.get(l.token)?.kill();
    zipping.delete(l.token);
    if (l.owned) fs.rmSync(ownedDir(l.token), { recursive: true, force: true });
    q.del.run(l.token);
  };

  const sweep = () => {
    for (const l of q.dead.all(Date.now()) as Link[]) remove(l);
    // An IP that has been quiet for an hour is forgotten, so the map can't grow
    // without bound. The backoff caps at 5s regardless, so there is nothing worth
    // waiting an hour to reset.
    const stale = Date.now() - 3600e3;
    for (const [key, g] of guesses) if (g.until < stale) guesses.delete(key);
  };

  /** Archive size grows as zip works; report the partial size so the UI can tick. */
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
    // ponytail: store-only (-0). Photos and video are already compressed, so
    // deflate buys ~nothing and costs hours on 40GB. Use -1 if you ever zip text.
    // -y stores symlinks as links. Without it zip archives what they point AT,
    // which walks straight past inLibrary()'s containment: anyone who can write to
    // the shared folder could plant a link to / and read the host out of the zip.
    const p = spawn('zip', ['-r', '-0', '-q', '-y', out, path.basename(src)], {
      cwd: path.dirname(src),
      stdio: 'ignore',
    });
    zipping.set(token, p);
    const fail = () => {
      zipping.delete(token);
      q.finish.run('error', 0, token);
    };
    p.on('error', fail);
    p.on('close', (code, signal) => {
      zipping.delete(token);
      if (signal) return; // cancelled by remove(); the row is already gone
      if (code !== 0 || !fs.existsSync(out)) return fail();
      q.finish.run('ready', fs.statSync(out).size, token);
    });
  };

  // ---- app -----------------------------------------------------------------
  const app = express();
  app.set('trust proxy', cfg.trustProxy ?? false);
  app.set('x-powered-by', false);
  app.use(express.json({ limit: '1mb' }));

  // ---- DNS rebinding -------------------------------------------------------
  // An attacker's page on a 1-second-TTL domain re-resolves that domain to this
  // server's LAN address. The browser then treats their script as same-origin with
  // Handoff, and SameSite, CORS and the CSP all stop applying — their JS can just
  // read /api/links and browse the library. Pinning the Host header is the fix:
  // the rebound request still carries the attacker's hostname, not ours.
  //
  // Bare IPs are safe to accept for exactly that reason — a browser only sends an
  // IP in Host when the user typed one, which is how this gets opened on a LAN.
  const hostname = (h: string) => h.toLowerCase().replace(/:\d+$/, '');
  const isIp = (h: string) => /^\[[0-9a-f:.]+\]$/i.test(h) || /^\d{1,3}(\.\d{1,3}){3}$/.test(h);

  const allowedHosts = new Set(
    [cfg.publicUrl, ...(cfg.allowedHosts ?? [])]
      .flatMap((v) => {
        if (!v) return [];
        // Accept a bare host or a full URL in either field.
        const host = v.includes('://') ? URL.parse(v)?.host : v;
        return host ? [host.toLowerCase(), hostname(host)] : [];
      })
      .filter(Boolean),
  );

  app.use((req, res, next) => {
    const raw = (req.headers.host ?? '').toLowerCase();
    const bare = hostname(raw);
    if (!raw || isIp(bare) || bare === 'localhost' || allowedHosts.has(raw) || allowedHosts.has(bare)) return next();
    res.status(403).type('text').send('Bad host');
  });

  app.use((_req, res, next) => {
    res.set({
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      // Referer would otherwise carry the share token to any site the recipient
      // clicks through to.
      'referrer-policy': 'no-referrer',
      'content-security-policy':
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    });
    next();
  });

  const requireAdmin: RequestHandler = (req, res, next) => {
    const v = unsign(sessionKey, cookies(req).sess);
    if (v && Number(v) > Date.now()) return next();
    res.status(401).json({ error: 'Not signed in' });
  };

  app.post('/api/login', async (req, res) => {
    const key = `admin:${who(req)}`;
    if (blocked(key)) return res.status(429).json(tooMany);
    // Count on the way in, not on the way out. Deriving takes ~100ms, and counting
    // after it would leave the gate open for every guess that arrives while the
    // first one is still hashing — which is the whole parallel burst.
    missed(key);

    const attempt = await derive(String(req.body?.password ?? ''), SECRET, 32);
    if (!timingSafeEqual(attempt, adminHash)) return res.status(401).json({ error: 'Wrong password' });
    guesses.delete(key);
    const until = Date.now() + 7 * 864e5;
    res.cookie('sess', sign(sessionKey, String(until)), {
      httpOnly: true,
      sameSite: 'lax',
      secure: req.secure, // set when a proxy terminates TLS, absent on plain LAN http
      maxAge: 7 * 864e5,
    });
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

  app.get('/api/settings', requireAdmin, (_req, res) => {
    res.json({ maxMbps: readMax(), theme: readTheme() });
  });

  app.put('/api/settings', requireAdmin, (req, res) => {
    const b = req.body ?? {};
    // Apply only the keys that were sent. Once there's more than one setting here,
    // "absent" has to mean "leave alone" — otherwise saving the theme silently
    // clears the speed limit.
    if ('maxMbps' in b) {
      const raw = b.maxMbps;
      const mbps = raw === null || raw === undefined || raw === '' ? null : Number(raw);
      if (mbps !== null && (!Number.isFinite(mbps) || mbps <= 0)) {
        return res.status(400).json({ error: 'Speed limit must be a positive number of Mbps' });
      }
      applyMax(mbps);
    }
    if ('theme' in b) {
      if (!isTheme(b.theme)) return res.status(400).json({ error: 'Unknown theme' });
      q.setSetting.run('theme', b.theme);
    }
    res.json({ maxMbps: readMax(), theme: readTheme() });
  });

  // The whole theme decision, resolved once, server-side. Light needs nothing on top
  // of style.css; dark ships dark.css, either outright or behind the OS preference.
  // Doing it here is what keeps the recipient pages themed without any inline script —
  // the CSP has no 'unsafe-inline' for scripts, and adding one for a colour scheme
  // would be a bad trade.
  const darkCssFile = path.join(HERE, '..', 'public', 'dark.css');
  app.get('/theme.css', (_req, res) => {
    const theme = readTheme();
    // no-cache, not no-store: the browser still revalidates cheaply, but a theme
    // change shows up on the next load instead of whenever the cache expires.
    res.type('css').set('cache-control', 'no-cache');
    if (theme === 'light') return res.send('');
    // Read per request so editing dark.css doesn't need a restart. One small file
    // per page load — no worse than what express.static already does.
    const css = fs.readFileSync(darkCssFile, 'utf8');
    res.send(theme === 'dark' ? css : `@media (prefers-color-scheme: dark) {\n${css}\n}`);
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
        // null, not the sentinel: the UI shouldn't have to know how "never" is stored.
        expires: never(l.expires) ? null : l.expires,
        downloads: l.downloads,
        maxDownloads: l.maxDownloads,
        locked: Boolean(l.pw),
        url: `${base}/d/${l.token}`,
      })),
    );
  });

  /** null means never. The key has to be present either way — an omitted expiry on
   *  a link-expiry app should be a 400, not a permanent link by accident. */
  const readHours = (b: Record<string, unknown>): number | null | undefined => {
    if (!('hours' in b)) return undefined;
    const raw = b.hours;
    if (raw === null || raw === '') return null;
    const hours = Number(raw);
    return Number.isFinite(hours) && hours > 0 ? hours : undefined;
  };

  const at = (hours: number | null) => (hours === null ? NEVER : Date.now() + Math.round(hours * 3600e3));

  app.post('/api/links', requireAdmin, (req, res) => {
    const b = req.body ?? {};
    const hours = readHours(b);
    if (hours === undefined) return res.status(400).json({ error: 'Bad expiry' });

    const maxDownloads = b.maxDownloads ? Number(b.maxDownloads) : null;
    if (maxDownloads !== null && (!Number.isInteger(maxDownloads) || maxDownloads < 1)) {
      return res.status(400).json({ error: 'Bad download limit' });
    }

    const token = randomBytes(12).toString('base64url');
    const pw = b.password ? hashPw(String(b.password)) : null;
    const expires = at(hours);
    const row = (name: string, filePath: string, owned: number, size: number, status: Link['status']) =>
      q.insert.run(token, name, filePath, owned, size, pw, status, expires, maxDownloads, Date.now());

    if (b.source === 'library') {
      const target = inLibrary(String(b.path ?? ''));
      if (!target) return res.status(400).json({ error: 'Bad path' });
      const stat = fs.statSync(target);
      if (stat.isDirectory()) {
        // owned = 1: the archive is ours, lives under /data, and expires with the link.
        const name = `${path.basename(target)}.zip`;
        const out = path.join(ownedDir(token), name);
        row(name, out, 1, 0, 'zipping');
        startZip(token, target, out);
      } else {
        // owned = 0: served straight off the share, never copied and never deleted.
        row(path.basename(target), target, 0, stat.size, 'ready');
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

  // Extend an expiry, or raise a download limit, without reissuing the link — the
  // token stays valid, so whoever already has it doesn't need a new one.
  app.patch('/api/links/:token', requireAdmin, (req, res) => {
    // live(), not get(): a link that's already dead is gone, and reviving one the
    // admin's list no longer shows would be a surprise.
    const l = live(String(req.params.token));
    if (!l) return res.status(404).json({ error: 'No such link' });

    const b = req.body ?? {};
    let { expires, maxDownloads } = l;

    // Absent means "leave alone", so the admin can raise a limit without also
    // silently resetting the expiry clock.
    if ('hours' in b) {
      const hours = readHours(b);
      if (hours === undefined) return res.status(400).json({ error: 'Bad expiry' });
      expires = at(hours);
    }

    if ('maxDownloads' in b) {
      const raw = b.maxDownloads;
      maxDownloads = raw === null || raw === undefined || raw === '' ? null : Number(raw);
      if (maxDownloads !== null && (!Number.isInteger(maxDownloads) || maxDownloads < 1)) {
        return res.status(400).json({ error: 'Bad download limit' });
      }
      // A limit at or below the count already reached kills the link on the next
      // sweep, taking any uploaded file with it. That's a delete wearing an edit's
      // clothes, so make it be asked for explicitly.
      if (maxDownloads !== null && maxDownloads <= l.downloads) {
        return res.status(400).json({
          error: `Already downloaded ${l.downloads} ${l.downloads === 1 ? 'time' : 'times'} — pick a higher limit, or delete the link`,
        });
      }
    }

    q.edit.run(expires, maxDownloads, l.token);
    res.json({ ok: true, expires, maxDownloads });
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

  // The recipient pages share public/style.css with the admin UI, so the light
  // and dark variants can't drift apart between the two surfaces.
  const page = (title: string, body: string) => `<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<link rel=stylesheet href="/style.css">
<link rel=stylesheet href="/theme.css">
<div class=center><div class=card>${body}</div></div>`;

  // Matches ext() in public/app.js: a text chip renders the same everywhere and
  // needs no icon table. Shown in the light variant only.
  const ext = (name: string) => (/\.([a-z0-9]{1,4})$/i.exec(name)?.[1] ?? 'file').toUpperCase();

  const stat = (k: string, v: string, cls = '') =>
    `<div class="stat ${cls}"><span class="k">${k}</span><span class="v">${esc(v)}</span></div>`;

  const on = (ms: number, time = false) =>
    new Date(ms).toLocaleString('en-US', { dateStyle: 'medium', ...(time && { timeStyle: 'short' }) });

  /** Kicker, extension chip, filename — the head of every file-bearing state. */
  const head = (l: Link, kicker: string) =>
    `<p class=kicker>${kicker}</p><div class=ic>${ext(l.name)}</div><h1 class=fname>${esc(l.name)}</h1>`;

  app.get('/d/:token', (req, res) => {
    const l = live(req.params.token);
    // Expired and never-existed are deliberately the same page: telling a stranger
    // which one they hit leaks whether the token was ever real.
    if (!l) {
      return res.status(404).type('html').send(
        page(
          'Link expired',
          `<p class=kicker>Handoff</p><h1 class=fname>This link has expired</h1>
           <p class=note>Links stop working once they pass their expiry date or hit their download limit.
           Ask whoever sent it for a new one.</p>`,
        ),
      );
    }

    if (l.status === 'zipping') {
      return res
        .type('html')
        .set('refresh', '10')
        .send(
          page(
            l.name,
            `${head(l, 'Getting your file ready')}<div class=bar></div>
             <p class=note>This is still being packaged up — larger folders take a few minutes.
             Leave this page open, it refreshes itself.</p>`,
          ),
        );
    }

    if (l.status !== 'ready') {
      return res.status(503).type('html').send(
        page(
          l.name,
          `${head(l, 'Handoff')}<p class=note>Something went wrong while preparing this file.
           Ask whoever sent it to try again.</p>`,
        ),
      );
    }

    const meta = `<div class=stats>${stat('Size', bytes(l.size), 'size')}${stat('Expires', never(l.expires) ? 'Never' : on(l.expires))}</div>`;

    if (l.pw && unsign(SECRET, cookies(req)[`u_${l.token}`]) !== l.token) {
      return res.type('html').send(
        page(
          l.name,
          `${head(l, 'Password required')}${meta}
           <form method=post><input type=password name=password placeholder="Password" autofocus required>
           <button class="btn primary">Unlock</button></form>
           ${req.query.slow ? '<p class=err>Too many attempts. Wait a few seconds, then try again.</p>' : ''}
           ${req.query.bad ? '<p class=err>That password didn’t work. Try again.</p>' : ''}`,
        ),
      );
    }

    res.type('html').send(
      page(
        l.name,
        `${head(l, 'Shared with you')}${meta}
         <a class="btn primary" href="/f/${l.token}/${encodeURIComponent(l.name)}" download>Download</a>
         <p class=note>${never(l.expires) ? 'This link has no expiry date.' : `Access ends ${esc(on(l.expires, true))}.`}</p>`,
      ),
    );
  });

  app.post('/d/:token', express.urlencoded({ extended: false, limit: '4kb' }), async (req, res) => {
    const l = live(String(req.params.token));
    if (!l?.pw) return res.redirect(303, `/d/${req.params.token}`);

    // Same gate as the admin login. This endpoint needs no session at all, so
    // without it anyone holding a share link can grind its password flat out —
    // and these are short passwords, typed by hand and sent over text.
    const key = `link:${l.token}:${who(req)}`;
    if (blocked(key)) return res.redirect(303, `/d/${l.token}?slow=1`);
    missed(key); // before the derive, same reason as the admin login above

    if (!(await checkPw(String(req.body?.password ?? ''), l.pw))) {
      return res.redirect(303, `/d/${l.token}?bad=1`);
    }
    guesses.delete(key);
    res.cookie(`u_${l.token}`, sign(SECRET, l.token), {
      httpOnly: true,
      sameSite: 'lax',
      secure: req.secure,
      maxAge: 864e5,
    });
    res.redirect(303, `/d/${l.token}`);
  });

  app.get('/f/:token/:name', (req, res) => {
    const l = live(String(req.params.token));
    if (!l || l.status !== 'ready') return res.status(404).type('text').send('Expired');
    if (l.pw && unsign(SECRET, cookies(req)[`u_${l.token}`]) !== l.token) return res.redirect(303, `/d/${l.token}`);

    let stat: fs.Stats;
    try {
      stat = fs.statSync(l.filePath);
    } catch {
      return res.status(404).type('text').send('Gone');
    }

    // Range is handled here rather than by res.download, because a speed limit
    // needs a transform between the file and the socket and res.download owns
    // that pipe. Single ranges only — that's all browsers and download managers
    // send, and it's what res.download did too.
    let start = 0;
    let end = stat.size - 1;
    const m = /^bytes=(\d*)-(\d*)$/.exec((req.headers.range ?? '').trim());
    if (m) {
      const unsatisfiable = () => res.status(416).set('content-range', `bytes */${stat.size}`).end();
      if (m[1] === '') {
        const last = Number(m[2]);
        if (!last) return unsatisfiable();
        start = Math.max(0, stat.size - last);
      } else {
        start = Number(m[1]);
        if (m[2] !== '') end = Math.min(end, Number(m[2]));
      }
      if (start > end || start >= stat.size) return unsatisfiable();
      res.status(206).set('content-range', `bytes ${start}-${end}/${stat.size}`);
    }

    // Non-ASCII filenames need the RFC 5987 form; the plain one is the fallback.
    const ascii = l.name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
    res.set({
      'accept-ranges': 'bytes',
      'content-length': String(end - start + 1),
      'content-type': 'application/octet-stream',
      'last-modified': stat.mtime.toUTCString(),
      'content-disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(l.name)}`,
    });

    // Count fresh starts only, so a resume doesn't burn the download quota.
    if (start === 0) q.count.run(l.token);
    if (req.method === 'HEAD') return res.end();

    // Smaller reads when a cap applies: paces ~20 chunks/sec instead of stalling
    // on a 64KB chunk for half a second at low limits.
    const rate = globalBucket?.rate;
    const highWaterMark = rate ? Math.min(262_144, Math.max(16_384, Math.round(rate / 20))) : undefined;

    // The throttle is always in the pipe so a limit set mid-download still applies.
    const sent = pipeline(fs.createReadStream(l.filePath, { start, end, highWaterMark }), throttle(), res);
    sent.catch(() => {}); // recipient closed the tab or lost signal; nothing to do
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
    maxMbps: process.env.MAX_MBPS ? Number(process.env.MAX_MBPS) : undefined,
    // Set TRUST_PROXY=1 only when a reverse proxy terminates TLS in front of this.
    // It is what restores req.secure (so session cookies get the Secure flag) and
    // the caller's real IP for the login throttle.
    trustProxy: process.env.TRUST_PROXY ? true : false,
    allowedHosts: process.env.ALLOWED_HOSTS?.split(',')
      .map((h) => h.trim())
      .filter(Boolean),
  });
  sweep();
  setInterval(sweep, 60_000).unref?.();
  const port = Number(process.env.PORT ?? 8080);
  app.listen(port, () => console.log(`handoff listening on :${port}`));
}
