# Handoff

Self-hosted share links for big files. Point it at a folder on your array, set an expiry, get a link.

Built for the "just send me the wedding photos" problem — the one where the answer shouldn't be
a Google Drive upload or a whole NextCloud install.

- **Pick a folder** on your server → Handoff zips it once and serves the archive.
- **Pick a single file** → served in place, no copy, no wasted disk.
- **Or drag a file into the browser** → uploaded to the container.
- Every link gets an expiry, and optionally a password and a download limit.
- When a link expires, the link and anything Handoff created are deleted. **Files on your shares are
  never modified or removed.**
- Downloads support HTTP range requests, so a 40 GB archive resumes instead of restarting when your
  dad's connection drops.

The recipient gets a plain page with a filename, a size, an expiry date, and one Download button.

## Install on Unraid

Search **Handoff** in Community Applications, or add this repository under *Apps → Settings →
Manage Repositories*.

| Setting | What to put |
| --- | --- |
| **Appdata** (`/data`) | `/mnt/user/appdata/handoff` — needs room for the largest archive you'll share |
| **Library** (`/library`) | The share you want to share *from*, e.g. `/mnt/user/Photos`. Mounted read-only. Optional — leave it out and Handoff is upload-only |
| **Admin password** | Required, 8+ characters. Gates the upload UI only |
| **Public URL** | Optional, e.g. `https://share.example.com`. Set it so copied links are the ones your recipients can open |
| **WebUI port** | `8080` |

Handoff speaks plain HTTP and expects to sit behind your existing reverse proxy (SWAG, NPM, Traefik,
Cloudflare Tunnel). Two things to check there:

- Raise the proxy's body-size limit if you plan to use browser upload. Nginx defaults to 1 MB;
  `client_max_body_size 0;` removes the cap.
- Cloudflare's proxied (orange-cloud) traffic is a poor fit for tens of gigabytes. Use a tunnel with
  proxying off, or point DNS straight at your origin.

## Or with Docker

```bash
docker run -d --name handoff -p 8080:8080 \
  -v /mnt/user/appdata/handoff:/data \
  -v /mnt/user/Photos:/library:ro \
  -e ADMIN_PASSWORD='something-long' \
  -e PUBLIC_URL='https://share.example.com' \
  ghcr.io/YOUR_GITHUB_USER/handoff:latest
```

## Sending a 40 GB folder

1. Open the web UI, sign in.
2. **Pick from server** → double-click into your share → single-click the folder.
3. Expiry `7 days`, password if you want one.
4. **Create link.** Handoff starts zipping; the row shows the archive growing. The link works
   immediately — anyone who opens it early sees a "still being prepared" page that refreshes itself.
5. Copy the link (it's already on your clipboard) and send it.

A week later the zip deletes itself. Your original folder is untouched.

Uploads through the browser aren't resumable — if the connection drops mid-upload you start over. For
anything genuinely large, copy it to the share over SMB and use **Pick from server** instead.

## Configuration

| Env var | Default | Meaning |
| --- | --- | --- |
| `ADMIN_PASSWORD` | — | Required. 8+ chars. Container refuses to start without it |
| `PORT` | `8080` | HTTP port |
| `DATA_DIR` | `/data` | Database, uploads, generated archives |
| `LIBRARY_DIR` | `/library` | Read-only source tree. Absent → the browse tab is hidden |
| `PUBLIC_URL` | — | Base URL used when generating links. Falls back to the request's host |
| `PUID` / `PGID` / `UMASK` | `99` / `100` / `022` | Standard Unraid ownership |

## How it works

One Node process, one SQLite file, no build step. About 400 lines.

- Links are 96-bit random tokens. Guessing one is not a realistic attack.
- Per-link passwords are scrypt-hashed. The admin password is compared in constant time.
- Library paths are resolved through `realpath` and checked against the library root, so `../` and
  symlinks can't escape.
- **Deletion is derived from the link token, not from the stored file path.** A link to one of your
  library files has nothing under `/data` to delete, so expiry physically cannot reach your originals.
  There's a test for exactly this.
- Folder archives use store-only zip (`-0`). Photos and video are already compressed; deflate would
  buy nothing and cost hours.
- A sweeper runs every 60 seconds and on boot.

## Development

```bash
npm install
ADMIN_PASSWORD=devpassword DATA_DIR=./data LIBRARY_DIR=/Users/you/Pictures npm start
```

```bash
npm test && npm run typecheck
```

`npm test` is a single file that starts the real server and exercises auth, path traversal, range
requests, uploads, per-link passwords, download limits, zipping, and the expiry rules.

Node 24+ runs the TypeScript directly — there is nothing to compile.

## Publishing to Community Applications

1. Replace `YOUR_GITHUB_USER` throughout:
   ```bash
   grep -rl YOUR_GITHUB_USER . --exclude-dir=node_modules | xargs sed -i '' 's/YOUR_GITHUB_USER/yourname/g'
   ```
2. Push to a **public** GitHub repo named `handoff`. The included workflow builds and pushes
   `ghcr.io/<you>/handoff:latest` on every push to `main` — make the resulting package public in the
   repo's Packages settings.
3. Submit the repo at <https://ca.unraid.net/submit>, then run **Validate** and **Scan**.

`ca_profile.xml` and `templates/handoff.xml` are already in the layout CA expects.

## License

MIT
