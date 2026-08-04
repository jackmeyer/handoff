# Handoff

Self-hosted share links for big files. Mount a folder, pick a file or a whole folder, get a link with
an expiry date.

Built for homelabbers who want to offer download links without setting up an entire Nextcloud instance.

- **Browse a mounted folder** in the admin UI and click any file to share it — served straight off the
  share, no copy and no wasted disk.
- **Or share a whole folder**, zipped once with no compression. The link works while it's still zipping,
  and deleting it cancels the job.
- **Or drag a file in** to upload it. Uploads aren't resumable, so put anything huge on the share instead.
- Links expire after any span you pick — minutes, hours or days — or never, and optionally carry a
  password and a download limit.
- **Cap total download bandwidth** so a share can't saturate your uplink.
- Range requests are supported, so a large download resumes instead of restarting.
- Expiry deletes the link and anything Handoff created for it. **Your mounted folder is only ever read
  from** — there is no code path that writes to it.

Recipients get a plain page: filename, size, expiry date, one Download button.

## Install on Unraid

Search **Handoff** in Community Applications.

| Setting | What to put |
| --- | --- |
| **Appdata** (`/data`) | `/mnt/user/appdata/handoff`. Needs room for the largest folder you plan to zip |
| **Library** (`/library`) | The folder to share from, e.g. `/mnt/user/Photos`. Read-only. Omit it for upload-only |
| **Admin password** | Required, 8+ characters. Gates the admin UI only, not share links |
| **Public URL** | Optional, e.g. `https://share.example.com`, so copied links work outside your LAN |
| **WebUI port** | `8080` |

Or with Docker:

```bash
docker run -d --name handoff -p 8080:8080 \
  -v /mnt/user/appdata/handoff:/data \
  -v /mnt/user/Photos:/library:ro \
  -e ADMIN_PASSWORD='something-long' \
  -e PUBLIC_URL='https://share.example.com' \
  ghcr.io/jackmeyer/handoff:latest
```

## Behind a reverse proxy

Handoff speaks plain HTTP and expects a proxy in front (SWAG, NPM, Traefik, Cloudflare Tunnel). For
nginx, the defaults will spool large transfers through your proxy's disk:

```nginx
client_max_body_size 0;       # browser uploads
proxy_buffering off;          # stream downloads instead of buffering them
proxy_request_buffering off;
proxy_read_timeout 1h;
```

Cloudflare's proxied (orange-cloud) traffic is a poor fit for tens of gigabytes. Use a tunnel with
proxying off, or point DNS straight at your origin.

## Speed limits

**Settings** in the web UI caps total download throughput in Mbps — a total across every active
download, not per connection. Changes apply to transfers already in progress. `MAX_MBPS` seeds the
value on first boot; the settings panel owns it afterwards.

## Configuration

| Env var | Default | Meaning |
| --- | --- | --- |
| `ADMIN_PASSWORD` | — | Required. 8+ chars. Container refuses to start without it |
| `PORT` | `8080` | HTTP port |
| `DATA_DIR` | `/data` | Database, browser uploads, generated archives |
| `LIBRARY_DIR` | `/library` | Read-only folder to browse. Absent → the browse tab is hidden |
| `PUBLIC_URL` | — | Base URL for generated links. Falls back to the request's host |
| `MAX_MBPS` | — | Seeds the speed limit on first boot only |
| `PUID` / `PGID` / `UMASK` | `99` / `100` / `022` | Standard Unraid ownership |

## Security

The admin password protects `/api/*` and the web UI. Share links are public by design, protected by a
96-bit random token plus an optional per-link password.

Login is scrypt-derived with a rising delay after repeated failures and no lockout, so a brute force
slows to a crawl but can't lock you out. Sessions are bound to the password, so rotating
`ADMIN_PASSWORD` ends any that were already open. Cookies are `HttpOnly` and `SameSite=Lax`, plus
`Secure` behind TLS. CSP, `X-Frame-Options`, `nosniff`, and `Referrer-Policy: no-referrer` are set on
every response.

Known limits:

- No per-IP or per-connection download rate limiting — your reverse proxy is the place for that.
- No audit log and no second factor.
- `ADMIN_PASSWORD` is an environment variable, so it's visible to anyone who can run `docker inspect`.
- Slow hashing raises the cost of guessing; it doesn't rescue a weak password.

Found something? Open an issue.

## Development

One Node process, one SQLite file, no build step. Node 24+ runs the TypeScript directly.

```bash
npm install
ADMIN_PASSWORD=devpassword DATA_DIR=./data LIBRARY_DIR=/path/to/some/files npm start
npm test && npm run typecheck
```

`npm test` starts a real server and covers auth, path traversal, range requests, uploads, passwords,
download limits, zipping, speed limits, and the expiry rules.

## License

MIT
