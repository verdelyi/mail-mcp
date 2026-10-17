#!/usr/bin/env bash
set -euo pipefail

IMAGE="greenmail/standalone:2.1.8"
NAME="mail-imap-mcp-rs-greenmail-test"
GREENMAIL_HOST="${GREENMAIL_HOST:-localhost}"
GREENMAIL_SMTP_PORT="${GREENMAIL_SMTP_PORT:-3025}"
GREENMAIL_IMAP_PORT="${GREENMAIL_IMAP_PORT:-3143}"
GREENMAIL_PLAIN_IMAP_PORT="${GREENMAIL_PLAIN_IMAP_PORT:-3144}"
GREENMAIL_USER="${GREENMAIL_USER:-test@localhost}"
GREENMAIL_PASS="${GREENMAIL_PASS:-test}"
GREENMAIL_PRELOAD_DIR="${GREENMAIL_PRELOAD_DIR:-$(pwd)/tests/fixtures/greenmail-preload}"

GREENMAIL_OPTS_DEFAULT="-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=test:${GREENMAIL_PASS}@localhost -Dgreenmail.users.login=email -Dgreenmail.preload.dir=/greenmail-preload -Dgreenmail.verbose"
GREENMAIL_OPTS="${GREENMAIL_OPTS:-$GREENMAIL_OPTS_DEFAULT}"

probe_greenmail() {
  python3 - "$GREENMAIL_HOST" "$GREENMAIL_IMAP_PORT" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

try:
    # docker-proxy accepts TCP before GreenMail listens; wait for the
    # IMAP greeting itself (TLS on this port, so any bytes will do).
    with socket.create_connection((host, port), timeout=1.5) as sock:
        sock.settimeout(1.5)
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock) as tls:
                if not tls.recv(16):
                    raise RuntimeError("no IMAP greeting")
        except ssl.SSLError as exc:
            raise RuntimeError(f"TLS not ready: {exc}")
except Exception as exc:
    print(exc)
    sys.exit(1)
PY
}

wait_for_greenmail() {
  local attempts=60
  local last_probe_error=""

  for _ in $(seq 1 "$attempts"); do
    if last_probe_error=$(probe_greenmail 2>&1); then
      return 0
    fi
    sleep 1
  done

  echo "GreenMail unreachable at ${GREENMAIL_HOST}:${GREENMAIL_IMAP_PORT} after ${attempts}s: ${last_probe_error}" >&2
  return 1
}

started_local_container=0
if ! probe_greenmail >/dev/null 2>&1; then
  if [[ ! -d "$GREENMAIL_PRELOAD_DIR" ]]; then
    echo "missing preload fixture directory: $GREENMAIL_PRELOAD_DIR" >&2
    exit 1
  fi

  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker pull "$IMAGE"

  docker run -d --rm --name "$NAME" \
    -e GREENMAIL_OPTS="$GREENMAIL_OPTS" \
    -v "$GREENMAIL_PRELOAD_DIR:/greenmail-preload:ro" \
    -p "$GREENMAIL_SMTP_PORT:3025" \
    -p "$GREENMAIL_IMAP_PORT:3993" \
    -p "$GREENMAIL_PLAIN_IMAP_PORT:3143" \
    "$IMAGE"

  started_local_container=1
fi

if [[ "$started_local_container" -eq 1 ]]; then
  cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT
fi

wait_for_greenmail

GREENMAIL_HOST="$GREENMAIL_HOST" \
GREENMAIL_SMTP_PORT="$GREENMAIL_SMTP_PORT" \
GREENMAIL_IMAP_PORT="$GREENMAIL_IMAP_PORT" \
GREENMAIL_PLAIN_IMAP_PORT="$GREENMAIL_PLAIN_IMAP_PORT" \
GREENMAIL_USER="$GREENMAIL_USER" \
GREENMAIL_PASS="$GREENMAIL_PASS" \
cargo test greenmail -- --ignored --nocapture
