#!/usr/bin/env python3
"""
multi_trace_fuzzer.py — Multi-trace round-robin fuzzing orchestrator for RRFuzz.

Runs N FuzzingCore instances (one per seed trace) in serial round-robin, with a
shared crash-hash set so duplicate crashes are deduplicated globally.

Usage:
    from orchestrator.multi_trace_fuzzer import MultiTraceFuzzer

    fuzzer = MultiTraceFuzzer(
        traces=['/tmp/traces/GET_abc.trace', '/tmp/traces/POST_abc.trace', ...],
        qemu_path='/path/to/qemu-mipsel',
        target_binary='/path/to/httpd',
        output_dir='/tmp/fuzz_output',
        # any extra kwargs are forwarded to each FuzzingCore
        ld_prefix='/path/to/rootfs',
        auth_boundary=104,
        manual_fork_point=104,
    )
    fuzzer.run(total_iterations=5000, rotation_chunk=500)

Or from CLI:
    python3 multi_trace_fuzzer.py \
        --qemu /path/to/qemu \
        --target /path/to/httpd \
        --traces /tmp/traces/*.trace \
        --output /tmp/fuzz_output \
        --iterations 10000 \
        [--ld-prefix /path/to/rootfs] \
        [--auth-boundary 104] \
        [--chunk 500]
"""

import argparse
import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure fuzzing/ is on path when run directly
_here = Path(__file__).resolve().parent.parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from conductor.fuzzing_core import FuzzingCore
from conductor.constants import COVERAGE_MAP_SIZE


def _detect_auth_boundary(trace_path: str, arch: str = 'auto') -> int:
    """Run TraceAnalyzer on a single trace file and return its auth_boundary index."""
    try:
        from conductor.trace_analyzer import TraceAnalyzer
        ta = TraceAnalyzer(trace_path, arch=arch)
        boundary = ta.get_auth_boundary()
        return boundary
    except Exception as e:
        print(f"[MultiTrace] auth_boundary detection failed for {trace_path}: {e}")
        return 0


class MultiTraceFuzzer:
    """
    Round-robin multi-trace fuzzing orchestrator.

    Each trace gets its own FuzzingCore (with its own QEMU process, mutator, etc.).
    All cores share a single crash_hashes set so crashes are deduplicated globally.
    Rotation: run each core for `rotation_chunk` iterations before moving to the next.
    """

    def __init__(
        self,
        traces: List[str],
        qemu_path: str,
        target_binary: str,
        output_dir: str,
        rotation_chunk: int = 500,
        **core_kwargs: Any,
    ):
        if not traces:
            raise ValueError("MultiTraceFuzzer requires at least one trace")

        self.traces = [str(t) for t in traces]
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.rotation_chunk = rotation_chunk
        self._qemu_path = qemu_path
        self._target = target_binary
        self._core_kwargs = core_kwargs

        # Shared crash hash set — injected into each CrashDetector after construction
        self._shared_crash_hashes: set = set()

        # Shared coverage master bitmap — OR-merged across all cores after each chunk
        self._master_bitmap = bytearray(COVERAGE_MAP_SIZE)

        # Detect arch from qemu binary name for TraceAnalyzer
        _qemu_name = Path(qemu_path).name  # e.g. qemu-mipsel, qemu-arm
        _arch = 'auto'
        if 'mipsel' in _qemu_name or 'mips' in _qemu_name:
            _arch = 'mips'
        elif 'arm' in _qemu_name and '64' not in _qemu_name:
            _arch = 'arm'
        elif 'aarch64' in _qemu_name or 'arm64' in _qemu_name:
            _arch = 'aarch64'

        # Whether caller explicitly supplied auth_boundary / manual_fork_point
        _explicit_boundary = 'auth_boundary' in core_kwargs and core_kwargs['auth_boundary'] > 0
        _explicit_fp = 'manual_fork_point' in core_kwargs and core_kwargs['manual_fork_point'] is not None

        # Build one FuzzingCore per trace
        self.cores: List[FuzzingCore] = []
        self._trace_boundaries: List[int] = []  # detected auth_boundary per trace

        for i, trace_path in enumerate(self.traces):
            trace_name = Path(trace_path).stem
            sub_out = str(self.output_dir / f'trace_{i:02d}_{trace_name}')

            # Per-trace auth_boundary detection (unless caller forced a global value)
            per_kwargs = dict(core_kwargs)
            if not _explicit_boundary or not _explicit_fp:
                boundary = _detect_auth_boundary(trace_path, arch=_arch)
                self._trace_boundaries.append(boundary)
                if boundary > 0:
                    if not _explicit_boundary:
                        per_kwargs['auth_boundary'] = boundary
                    if not _explicit_fp:
                        per_kwargs['manual_fork_point'] = boundary
                    print(f"[MultiTrace] Core {i}: auto-detected auth_boundary={boundary} "
                          f"for {Path(trace_path).name}")
                else:
                    self._trace_boundaries.append(0)
            else:
                self._trace_boundaries.append(core_kwargs.get('auth_boundary', 0))

            print(f"[MultiTrace] Initializing core {i}: {trace_path} → {sub_out}")
            core = FuzzingCore(
                qemu_path=qemu_path,
                target_binary=target_binary,
                initial_trace=trace_path,
                output_dir=sub_out,
                **per_kwargs,
            )
            # Inject shared crash hash set for global deduplication
            core.crash_detector.crash_hashes = self._shared_crash_hashes
            self.cores.append(core)

        print(f"[MultiTrace] {len(self.cores)} cores ready, chunk={rotation_chunk}")

    # ------------------------------------------------------------------

    def run(self, total_iterations: int, rotation_chunk: Optional[int] = None):
        """
        Run all cores in round-robin for total_iterations iterations.

        Args:
            total_iterations: Total iterations spread across all cores.
            rotation_chunk: Iterations per core per rotation (default: self.rotation_chunk).
        """
        chunk = rotation_chunk or self.rotation_chunk
        done = 0
        start = time.time()

        print(f"\n[MultiTrace] Starting: {total_iterations} iters across "
              f"{len(self.cores)} traces, chunk={chunk}")

        try:
            while done < total_iterations:
                for core in self.cores:
                    remaining = total_iterations - done
                    if remaining <= 0:
                        break
                    this_chunk = min(chunk, remaining)
                    idx = self.cores.index(core)
                    boundary = self._trace_boundaries[idx] if idx < len(self._trace_boundaries) else 0
                    print(f"\n[MultiTrace] Core {idx} "
                          f"({Path(core.initial_trace).stem}, auth_boundary={boundary}) — "
                          f"{this_chunk} iters (total done={done}/{total_iterations})")

                    # Merge master bitmap INTO this core before it runs,
                    # so it starts with knowledge of all previously found edges.
                    self._merge_master_into_core(core)

                    core.run(max_iterations=this_chunk)
                    done += this_chunk

                    # Merge this core's bitmap back into master
                    self._merge_core_into_master(core)

        except KeyboardInterrupt:
            print("\n[MultiTrace] Interrupted by user")

        elapsed = time.time() - start
        self._print_summary(done, elapsed)

    # ------------------------------------------------------------------

    # ------------------------------------------------------------------

    def _merge_core_into_master(self, core: FuzzingCore):
        """OR this core's global_bitmap into the master bitmap."""
        cb = core.coverage_tracker.global_bitmap
        mb = self._master_bitmap
        # Vectorized OR via struct for speed
        n = len(mb) // 8
        master_longs = list(struct.unpack(f'<{n}Q', bytes(mb)))
        core_longs = struct.unpack(f'<{n}Q', bytes(cb[:n*8]))
        for k in range(n):
            master_longs[k] |= core_longs[k]
        self._master_bitmap = bytearray(struct.pack(f'<{n}Q', *master_longs))

    def _merge_master_into_core(self, core: FuzzingCore):
        """
        OR the master bitmap into this core's global_bitmap and update virgin_bits
        so the core treats master-known edges as already seen (won't re-report them
        as new, but also won't re-explore paths already covered by sibling cores).
        """
        mb = self._master_bitmap
        cb = core.coverage_tracker.global_bitmap
        vb = core.coverage_tracker.virgin_bits
        n = len(mb) // 8
        master_longs = struct.unpack(f'<{n}Q', bytes(mb))
        core_longs = list(struct.unpack(f'<{n}Q', bytes(cb[:n*8])))
        vb_longs = list(struct.unpack(f'<{n}Q', bytes(vb[:n*8])))
        changed = False
        for k in range(n):
            ml = master_longs[k]
            if ml and ml != core_longs[k]:
                new_bits = ml & ~core_longs[k]   # bits in master but not yet in core
                if new_bits:
                    core_longs[k] |= ml
                    vb_longs[k] &= ~new_bits      # mark as seen in virgin map
                    changed = True
        if changed:
            core.coverage_tracker.global_bitmap = bytearray(
                struct.pack(f'<{n}Q', *core_longs))
            core.coverage_tracker.virgin_bits = bytearray(
                struct.pack(f'<{n}Q', *vb_longs))

    # ------------------------------------------------------------------

    def _print_summary(self, total_done: int, elapsed: float):
        print(f"\n{'=' * 60}")
        print(f"[MultiTrace] Summary: {total_done} iterations in {elapsed:.1f}s "
              f"({total_done / max(elapsed, 1):.1f} iter/s)")
        print(f"  Shared unique crashes: {len(self._shared_crash_hashes)}")
        total_crashes = 0
        total_edges = 0
        for i, core in enumerate(self.cores):
            crashes = len(core.crash_detector.crashes)
            edges = core.coverage_tracker.get_stats().get('total_edges', 0)
            total_crashes += crashes
            total_edges = max(total_edges, edges)  # edges are shared via bitmap
            print(f"  Core {i:02d} ({Path(self.traces[i]).stem}): "
                  f"crashes={crashes}, edges={edges}")
        print(f"  Total crashes (with dups): {total_crashes}")
        print(f"  Max coverage edges seen:   {total_edges}")
        print(f"  Output dir: {self.output_dir}")
        print('=' * 60)

        # Write a JSON summary
        summary = {
            'total_iterations': total_done,
            'elapsed_seconds': elapsed,
            'unique_crash_hashes': sorted(self._shared_crash_hashes),
            'traces': [
                {
                    'trace': self.traces[i],
                    'crashes': len(core.crash_detector.crashes),
                    'edges': core.coverage_tracker.get_stats().get('total_edges', 0),
                }
                for i, core in enumerate(self.cores)
            ],
        }
        summary_path = self.output_dir / 'multi_trace_summary.json'
        summary_path.write_text(json.dumps(summary, indent=2))
        print(f"[MultiTrace] Summary written to {summary_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='RRFuzz multi-trace round-robin fuzzer')
    parser.add_argument('--qemu', required=True, help='QEMU binary path')
    parser.add_argument('--target', required=True, help='Target binary path')
    parser.add_argument('--traces', nargs='+', required=True, help='Seed trace files')
    parser.add_argument('--output', required=True, help='Output directory')
    parser.add_argument('--iterations', type=int, default=5000, help='Total iterations')
    parser.add_argument('--chunk', type=int, default=500, help='Iterations per core per rotation')
    parser.add_argument('--ld-prefix', default=None, help='QEMU LD prefix (rootfs)')
    parser.add_argument('--auth-boundary', type=int, default=0, help='Auth boundary syscall index')
    parser.add_argument('--fork-point', type=int, default=None, help='Manual fork point')
    args = parser.parse_args()

    # Expand glob patterns (shell may not expand inside --traces list)
    import glob
    trace_files = []
    for pattern in args.traces:
        expanded = glob.glob(pattern)
        if expanded:
            trace_files.extend(expanded)
        elif Path(pattern).exists():
            trace_files.append(pattern)
    if not trace_files:
        print(f"[MultiTrace] ERROR: No trace files matched: {args.traces}")
        sys.exit(1)

    print(f"[MultiTrace] Using {len(trace_files)} trace(s):")
    for t in trace_files:
        print(f"  {t}")

    core_kwargs: Dict[str, Any] = {}
    if args.ld_prefix:
        core_kwargs['ld_prefix'] = args.ld_prefix
    if args.auth_boundary:
        core_kwargs['auth_boundary'] = args.auth_boundary
    if args.fork_point is not None:
        core_kwargs['manual_fork_point'] = args.fork_point

    fuzzer = MultiTraceFuzzer(
        traces=trace_files,
        qemu_path=args.qemu,
        target_binary=args.target,
        output_dir=args.output,
        rotation_chunk=args.chunk,
        **core_kwargs,
    )
    fuzzer.run(total_iterations=args.iterations)


if __name__ == '__main__':
    main()
