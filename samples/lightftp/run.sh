#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 /path/to/patched-qemu" >&2
  exit 1
fi

QEMU_ROOT=$(cd "$1" && pwd)
QEMU_BIN="$QEMU_ROOT/build/qemu-x86_64"
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WORK_DIR=/tmp/rrfuzz_lightftp_rw
SRC_RELEASE="$WORK_DIR/src/Release"
TRACE="$WORK_DIR/auto_retr.trace"
CFG="$WORK_DIR/fftp_artifact.conf"
OUT=/tmp/rrfuzz_lightftp_sample
ROOT=/tmp/rrfuzz_lightftp_root

rm -rf "$WORK_DIR"
cp -a "$SCRIPT_DIR" "$WORK_DIR"

mkdir -p "$ROOT"
rm -rf "$OUT"
mkdir -p "$OUT"

# Step 1: build fftp from source
make -C "$SRC_RELEASE" fftp

# Step 2: generate TLS cert (required by fftp even in replay mode)
CERT=/tmp/rrfuzz_lightftp.crt
KEY=/tmp/rrfuzz_lightftp.key
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$KEY" -out "$CERT" -subj "/CN=localhost" 2>/dev/null
fi

# Step 3: re-record a fresh trace with the newly compiled binary.
# The pre-packaged trace was recorded in a different environment; address-layout
# differences cause replay to diverge.  Recording locally ensures binary and
# trace always match.
echo "test file for RR-Fuzz" > "$ROOT/test.txt"

# Kill any leftover server on port 2121 from a previous failed run
fuser -k 2121/tcp 2>/dev/null || true

SERVER_PID=""
cleanup_server() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup_server EXIT

RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE="$TRACE" \
  "$QEMU_BIN" "$SRC_RELEASE/fftp" "$CFG" >/dev/null 2>/dev/null &
SERVER_PID=$!

# Poll until the FTP port is listening (up to 10 seconds).
# Use ss (no TCP connect) — fftp is patched to handle exactly one connection
# for RR tracing, so a test-connect would consume that slot.
for i in $(seq 1 20); do
  if ss -tlnp 2>/dev/null | grep -q ':2121 '; then
    break
  fi
  sleep 0.5
done

python3 -c "
import ftplib, sys
try:
    ftp = ftplib.FTP()
    ftp.connect('127.0.0.1', 2121, timeout=5)
    ftp.login('anonymous', '')
    ftp.retrlines('LIST', lambda _: None)
    ftp.retrbinary('RETR test.txt', lambda _: None)
    ftp.quit()
except Exception as e:
    print(f'FTP record session error: {e}', file=sys.stderr)
    sys.exit(1)
"

cleanup_server
trap - EXIT

if [ ! -s "$TRACE" ]; then
  echo "error: trace recording failed (empty or missing trace file)" >&2
  exit 1
fi
echo "Trace recorded: $TRACE ($(wc -c < "$TRACE") bytes)"

# Step 4: fuzz with the fresh trace
PYTHONPATH="$QEMU_ROOT/linux-user/rr_fuzzing" \
python3 "$QEMU_ROOT/linux-user/rr_fuzzing/fuzzing/fuzz_main.py" \
  --qemu "$QEMU_BIN" \
  --target "$SRC_RELEASE/fftp" \
  --trace "$TRACE" \
  --args "$CFG" \
  --iterations 10 \
  --output "$OUT"

echo "LightFTP sample complete"
echo "  Work dir: $WORK_DIR"
echo "  Output:   $OUT"
