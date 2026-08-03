#!/bin/sh
set -e

PUID="${PUID:-99}"
PGID="${PGID:-100}"
umask "${UMASK:-022}"

mkdir -p "$DATA_DIR/files"
# Not -R: /data holds multi-GB archives and a recursive chown on every boot is
# pointless. The app runs as PUID, so anything it creates is already correct.
chown "$PUID:$PGID" "$DATA_DIR" "$DATA_DIR/files"

exec su-exec "$PUID:$PGID" node /app/src/server.ts
