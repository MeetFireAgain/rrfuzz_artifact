#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 /path/to/patched-qemu [/path/to/totolink-rootfs]" >&2
  exit 1
fi

QEMU_ROOT=$(cd "$1" && pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ARCHIVE="$SCRIPT_DIR/sim_root.tar.xz"
WORK_ROOT=/tmp/rrfuzz_totolink_rootfs
TRACE_SRC="$SCRIPT_DIR/seeds/boa_totolink_v2.trace"
TRACE_WORK_ROOT=/tmp/rrfuzz_totolink_trace
TRACE_WORK="$TRACE_WORK_ROOT/boa_totolink_v2.trace"

if [ $# -eq 2 ]; then
  ROOTFS=$(cd "$2" && pwd)
else
  ROOTFS="$WORK_ROOT/sim_root"
  rm -rf "$WORK_ROOT"
  mkdir -p "$WORK_ROOT"
  if [ ! -f "$ARCHIVE" ]; then
    echo "error: missing rootfs archive: $ARCHIVE" >&2
    exit 1
  fi
  tar -xJf "$ARCHIVE" -C "$WORK_ROOT"
fi

QEMU_BIN="$QEMU_ROOT/build/qemu-mips"
DICT="$SCRIPT_DIR/config/totolink_http.dict"
OUT=/tmp/rrfuzz_totolink_sample
TARGET="$ROOTFS/bin/boa"

export RR_LOG_LEVEL=INFO
export RR_MOCK_IOCTLS=1
export RR_MOCK_WIRELESS=1
export RR_ENABLED=1

if [ ! -x "$QEMU_BIN" ]; then
  echo "error: missing QEMU binary: $QEMU_BIN" >&2
  exit 1
fi

if [ ! -f "$TARGET" ]; then
  echo "error: missing target binary: $TARGET" >&2
  exit 1
fi

rm -rf "$OUT" "$TRACE_WORK_ROOT"
mkdir -p "$OUT" "$TRACE_WORK_ROOT"
cp "$TRACE_SRC" "$TRACE_WORK"
if [ -f "$TRACE_SRC.bbl" ]; then
  cp "$TRACE_SRC.bbl" "$TRACE_WORK.bbl"
fi
rm -f "$TRACE_WORK.analyzer.pkl"

PYTHONPATH="$QEMU_ROOT/linux-user/rr_fuzzing" python3 "$QEMU_ROOT/linux-user/rr_fuzzing/fuzzing/fuzz_main.py"   --qemu "$QEMU_BIN"   --target "$TARGET"   --trace "$TRACE_WORK"   --dictionary "$DICT"   --iterations 10   --word-size 32   --ld-prefix "$ROOTFS"   --args "-c . -d"   --output "$OUT"

echo "TOTOLINK sample complete"
echo "  Rootfs: $ROOTFS"
echo "  Output: $OUT"
