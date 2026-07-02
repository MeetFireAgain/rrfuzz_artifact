#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 /path/to/patched-qemu" >&2
  exit 1
fi

QEMU_ROOT=$(cd "$1" && pwd)
QEMU_BIN="$QEMU_ROOT/build/qemu-x86_64"
TARGET_SRC="$QEMU_ROOT/linux-user/rr_fuzzing/tests/programs/simple/fuzz_target_simple.c"
WORK=/tmp/rrfuzz_case1

mkdir -p "$WORK"
rm -f "$WORK"/*

gcc -O0 -g -no-pie "$TARGET_SRC" -o "$WORK/simple_target"

printf 'hello\n' | RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE="$WORK/seed.trace" \
  "$QEMU_BIN" "$WORK/simple_target" >"$WORK/record.txt" 2>"$WORK/record.err"

RR_FUZZING_ENABLED=1 RR_MODE=replay RR_TRACE_FILE="$WORK/seed.trace" \
  "$QEMU_BIN" "$WORK/simple_target" >"$WORK/replay.txt" 2>"$WORK/replay.err"

test -s "$WORK/seed.trace"

echo "Case 1 complete"
echo "  Work dir: $WORK"
echo "  Trace:    $WORK/seed.trace"
echo "  Record:   $WORK/record.txt"
echo "  Replay:   $WORK/replay.txt"
