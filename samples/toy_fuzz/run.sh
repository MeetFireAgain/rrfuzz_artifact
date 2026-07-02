#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 /path/to/patched-qemu" >&2
  exit 1
fi

QEMU_ROOT=$(cd "$1" && pwd)
QEMU_BIN="$QEMU_ROOT/build/qemu-x86_64"
TARGET_SRC="$QEMU_ROOT/linux-user/rr_fuzzing/tests/programs/vuln/vuln_stdin.c"
FUZZ_MAIN="$QEMU_ROOT/linux-user/rr_fuzzing/fuzzing/fuzz_main.py"
WORK=/tmp/rrfuzz_case2

mkdir -p "$WORK"
rm -rf "$WORK/out"
rm -f "$WORK"/seed.trace "$WORK"/record.txt "$WORK"/record.err "$WORK"/fuzz.txt "$WORK"/fuzz.err "$WORK"/vuln_stdin

gcc -O0 -g -no-pie "$TARGET_SRC" -o "$WORK/vuln_stdin"

printf 'AHELLO\n' | RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE="$WORK/seed.trace" \
  "$QEMU_BIN" "$WORK/vuln_stdin" >"$WORK/record.txt" 2>"$WORK/record.err"

PYTHONPATH="$QEMU_ROOT/linux-user/rr_fuzzing" \
python3 "$FUZZ_MAIN" \
  --qemu "$QEMU_BIN" \
  --target "$WORK/vuln_stdin" \
  --trace "$WORK/seed.trace" \
  --iterations 10 \
  --output "$WORK/out" >"$WORK/fuzz.txt" 2>"$WORK/fuzz.err"

test -f "$WORK/out/fuzzing.log"

echo "Case 2 complete"
echo "  Work dir: $WORK"
echo "  Output:   $WORK/out"
echo "  Log:      $WORK/out/fuzzing.log"
