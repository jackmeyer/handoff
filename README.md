# Handoff

Self-hosted share links for big files. Mount a folder, pick a file or a whole folder, get a link with
an expiry date.

Built for homelabbers who want to offer download links without setting up an entire Nextcloud instance.

- **Mount a folder** the way you would for any Docker container, then browse it in the admin UI.
- **Click a file** to share it. It's served straight off the share — no copy, no wasted disk.
- **Or share a whole folder**, which Handoff zips once with no compression. The link works right away;
  anyone who opens it early gets a "still being prepared" page that refreshes itself.
- **Or drag a file into the browser** to upload it into the container.
- Every link gets an expiry, and optionally a password and a download limit.
- **Cap your upload bandwidth** server-wide from the settings panel, so a download can't saturate your
  uplink and make the rest of your house unusable.
- When a link expires it's deleted, along with anything Handoff created for it — an uploaded file, or a
  generated archive. **Files in your mounted folder are only ever read.** Handoff has no code path that
  writes to it.
- Downloads support HTTP range requests, so a 40 GB archive resumes instead of restarting when your
  dad's connection drops.

The recipient gets a plain page with a filename, a size, an expiry date, and one Download button.

## Install on Unraid

Search **Handoff** in Community Applications, or add this repository under *Apps → Settings →
Manage Repositories*.

| Setting | What to put |
| --- | --- |
| **Appdata** (`/data`) | `/mnt/user/appdata/handoff` — see the disk-space note below if you plan to share folders |
| **Library** (`/library`) | The folder you want to browse and share from, e.g. `/mnt/user/Photos`. Mounted read-only. Optional — leave it out and Handoff is upload-only |
| **Admin password** | Required, 8+ characters. Gates the upload UI only |
| **Public URL** | Optional, e.g. `https://share.example.com`. Set it so copied links are the ones your recipients can open |
| **WebUI port** | `8080` |

Handoff speaks plain HTTP and expects to sit behind your existing reverse proxy (SWAG, NPM, Traefik,
Cloudflare Tunnel). Two things to check there:

- Raise the proxy's body-size limit if you plan to use browser upload. Nginx defaults to 1 MB;
  `client_max_body_size 0;` removes the cap.
- **Turn off proxy buffering.** This is the one that silently hurts. Nginx defaults to buffering both
  directions through disk temp files, so a 40 GB download gets spooled to your proxy's disk on the way
  out and a large upload gets written twice on the way in. Both directions want streaming:
  ```nginx
  proxy_buffering off;          # downloads stream straight through
  proxy_request_buffering off;  # uploads too
  proxy_read_timeout 1h;
  ```
- Cloudflare's proxied (orange-cloud) traffic is a poor fit for tens of gigabytes. Use a tunnel with
  proxying off, or point DNS straight at your origin.

**Disk space.** Generated archives and browser uploads live in `/data`. Zipping a 40 GB folder needs
40 GB free there, and on a default Unraid setup `/mnt/user/appdata` sits on your cache SSD — which is
usually the smallest disk you own. If you plan to share large folders, point the Appdata mapping at an
array share with room (`/mnt/user/handoff`) instead. Single files and uploads don't have this problem:
a file shared from the mounted folder is streamed in place and copies nothing.

## Or with Docker

```bash
docker run -d --name handoff -p 8080:8080 \
  -v /mnt/user/appdata/handoff:/data \
  -v /mnt/user/Photos:/library:ro \
  -e ADMIN_PASSWORD='something-long' \
  -e PUBLIC_URL='https://share.example.com' \
  ghcr.io/jackmeyer/handoff:latest
```

## Sending a folder of wedding photos

1. Sign in, open **Pick from server**, and click through to the folder. Clicking a folder opens it.
2. Once you're inside it, click **Share "Wedding Photos" as a zip** at the top right.
3. Expiry `7 days`, password if you want one.
4. **Create link** — it's copied to your clipboard. Send it.

Zipping starts immediately and the row shows the archive growing. You can send the link before it
finishes. Deleting a link that's still zipping cancels the job and cleans up the partial archive.

Archives are created with `zip -r -0` — stored, not compressed. Photos and video are already
compressed, so deflate buys nothing and costs hours on tens of gigabytes. The archive contains a single
top-level folder, so your dad doesn't get 3,000 loose files in his Downloads.

A week later the archive deletes itself. Your original folder is untouched.

Uploads through the browser aren't resumable — if the connection drops mid-upload you start over. For
anything genuinely large, put it on the share and use **Pick from server** instead.

## Speed limits

Open **Settings** in the web UI to cap total download throughput in Mbps. On a 1 Gbps uplink, setting
500 leaves you half your upload for everything else.

The cap is a **total across every active download**, not per connection — three people pulling three
different links share the 500, they don't get 500 each. That's the only version that actually protects
your uplink.

Changes apply immediately, including to downloads already in flight. Measured accuracy is within half a
percent: an 800 Mbps cap delivered 100,050,631 B/s against a 100,000,000 B/s target.

`MAX_MBPS` seeds the value on first boot, so a fresh Unraid install can arrive pre-capped, but the
settings panel is the source of truth afterwards.

## Configuration

| Env var | Default | Meaning |
| --- | --- | --- |
| `ADMIN_PASSWORD` | — | Required. 8+ chars. Container refuses to start without it |
| `PORT` | `8080` | HTTP port |
| `DATA_DIR` | `/data` | Database, browser uploads, generated archives |
| `LIBRARY_DIR` | `/library` | Read-only folder to browse. Absent → the browse tab is hidden |
| `PUBLIC_URL` | — | Base URL used when generating links. Falls back to the request's host |
| `MAX_MBPS` | — | Seeds the server-wide speed limit on first boot only. After that the settings panel owns it |
| `PUID` / `PGID` / `UMASK` | `99` / `100` / `022` | Standard Unraid ownership |

## How it works

One Node process, one SQLite file, no build step. About 400 lines.

- Links are 96-bit random tokens. Guessing one is not a realistic attack.
- Per-link passwords are scrypt-hashed. The admin password is compared in constant time.
- Library paths are resolved through `realpath` and checked against the library root, so `../` and
  symlinks can't escape.
- **Deletion is derived from the link token, not from the stored file path.** Only uploads and
  generated archives live under `/data/files/<token>/`, and that's the only thing expiry deletes. A link
  to a file in your mounted folder has nothing to delete, so expiry physically cannot reach it. There's
  a test for exactly this.
- Folder archives use store-only zip (`-0`), and an in-flight zip is killed if you delete its link.
- The speed limit is one token bucket shared by every active download, applied by a transform between
  the file and the socket. With no limit set the transform is a no-op — measured throughput is unchanged.
- Range requests are handled directly rather than by `res.download`, because the throttle needs to sit
  in that pipe. Single ranges only, which is all browsers and download managers send.
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
requests and their edge cases, uploads, per-link passwords, download limits, zipping and mid-zip
cancellation, the speed cap (including that its budget is shared across connections rather than applied
per-connection), and the expiry rules.

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
