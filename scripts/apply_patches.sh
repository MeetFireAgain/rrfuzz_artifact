#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 /path/to/qemu-checkout" >&2
  exit 1
fi

QEMU_ROOT=$(cd "$1" && pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ARTIFACT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BASE_EXPECTED=95b9e0d2ade5d633fd13ffba96a54e87c65baf39

if ! git -C "$QEMU_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: $QEMU_ROOT is not a git checkout" >&2
  exit 1
fi

HEAD_COMMIT=$(git -C "$QEMU_ROOT" rev-parse HEAD)
if [ "$HEAD_COMMIT" != "$BASE_EXPECTED" ]; then
  echo "error: expected QEMU checkout at $BASE_EXPECTED but found $HEAD_COMMIT" >&2
  exit 1
fi

if [ -n "$(git -C "$QEMU_ROOT" status --porcelain)" ]; then
  echo "error: worktree is not clean" >&2
  exit 1
fi

git -C "$QEMU_ROOT" apply --whitespace=nowarn "$ARTIFACT_ROOT/patches/0001-qemu-core-integration.patch"
git -C "$QEMU_ROOT" apply --whitespace=nowarn "$ARTIFACT_ROOT/patches/0002-rrfuzz-runtime-and-demos.patch"

echo "Applied RR-Fuzz patch set to $QEMU_ROOT"
