#!/usr/bin/env python3
import sys
import os
import signal
import argparse
import resource
from pathlib import Path

# Hard memory limit: 12GB per fuzzer process — prevent OOM killer from hitting unrelated processes
try:
    _MEM_LIMIT = 12 * 1024 ** 3
    resource.setrlimit(resource.RLIMIT_AS, (_MEM_LIMIT, _MEM_LIMIT))
except Exception:
    pass

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from conductor.fuzzing_core import FuzzingCore
from conductor.mutator import SmartMutator

_fuzzing_core_ref = None

def _sigterm_handler(signum, frame):
    """Ensure QEMU children are killed when timeout(1) sends SIGTERM."""
    if _fuzzing_core_ref is not None:
        try:
            _fuzzing_core_ref.cleanup()
        except Exception:
            pass
    sys.exit(128 + signum)

signal.signal(signal.SIGTERM, _sigterm_handler)

def main():
    parser = argparse.ArgumentParser(description="RR-Fuzz: Universal QEMU Fuzzer")
    parser.add_argument("--qemu", required=True, help="Path to QEMU binary")
    parser.add_argument("--target", required=True, help="Path to target binary")
    parser.add_argument("--trace", default="", help="Path to initial trace file (single seed)")
    parser.add_argument("--traces", nargs="+", metavar="TRACE",
                        help="One or more seed trace files (multi-seed corpus mode). "
                             "Overrides --trace. The fuzzer rotates through all seeds.")
    parser.add_argument("--trace-dir", metavar="DIR",
                        help="Directory of *.trace files to use as seeds (auto-discovered).")
    parser.add_argument("--output", default="fuzzing_output", help="Output directory")
    parser.add_argument("--iterations", type=int, default=1000, help="Max iterations")
    parser.add_argument("--infinite", action="store_true", help="Run indefinitely")
    parser.add_argument("--no-progress-timeout", type=int, default=300, help="Timeout if no progress (seconds)")
    parser.add_argument("--args", default="", help="Target binary arguments")
    parser.add_argument("--tree", action="store_true", help="Enable Syscall Tree visualization (default: False)")
    parser.add_argument("--persistence", action="store_true", help="Enable unified session persistence (Auto Save/Resume)")
    parser.add_argument("--word-size", type=int, default=0, help="Word size (32 or 64, 0 for auto)")
    parser.add_argument("--endian", default="auto", choices=["auto", "little", "big"], help="Endianness")
    parser.add_argument("-n", "--workers", type=int, default=1, help="Number of worker processes (default: 1)")
    parser.add_argument("--dictionary", help="Path to dictionary file")
    parser.add_argument("--ld-prefix", help="QEMU LD Prefix (RootFS)")
    parser.add_argument("--fork-point", type=int, help="Manual fork point index (overrides DFC logic)")
    
    # Ablation Study Flags
    parser.add_argument("--disable-dfc", action="store_true", help="Disable DynamicForkController (ablation V0/V1)")
    parser.add_argument("--disable-smartdict", action="store_true", help="Disable SmartMutator (use BaseMutator instead)")
    parser.add_argument("--disable-pathfinder", action="store_true", help="Disable PathFinder guided execution")
    parser.add_argument("--auth-boundary", type=int, default=0,
                        help="Syscall index marking end of auth phase. Mutations on network-fd "
                             "syscalls after this index are prioritised as the primary attack "
                             "surface (post-auth network input). Default=0 (disabled).")
    # Auto-record mode
    parser.add_argument("--auto-record", action="store_true",
                        help="Auto-discover endpoints and record traces before fuzzing. "
                             "Requires --sim-root. Produces traces consumed by multi-trace mode.")
    parser.add_argument("--sim-root", default=None,
                        help="Path to target rootfs (used by --auto-record for endpoint discovery "
                             "and as QEMU LD prefix if --ld-prefix is not specified).")
    parser.add_argument("--auto-record-max", type=int, default=20,
                        help="Max endpoints to probe in --auto-record mode (default: 20).")
    parser.add_argument("--multi-trace", action="store_true",
                        help="Run all resolved traces in round-robin via MultiTraceFuzzer.")
    parser.add_argument("--chunk", type=int, default=500,
                        help="Iterations per trace per rotation in --multi-trace mode (default: 500).")

    args = parser.parse_args()

    # ── Auto-record mode ──────────────────────────────────────────────────────
    if args.auto_record:
        from recorder.auto_recorder import AutoRecorder
        sim_root = args.sim_root or args.ld_prefix
        if not sim_root:
            print("[!] --auto-record requires --sim-root (or --ld-prefix)", file=sys.stderr)
            sys.exit(1)
        auto_out = str(Path(args.output) / 'auto_traces')
        print(f"[*] --auto-record: discovering endpoints and recording traces → {auto_out}")
        recorder = AutoRecorder(
            qemu_path=args.qemu,
            target_binary=args.target,
            sim_root=sim_root,
            output_dir=auto_out,
        )
        recorded = recorder.run(max_endpoints=args.auto_record_max)
        if not recorded:
            print("[!] --auto-record produced 0 valid traces — check target startup", file=sys.stderr)
            sys.exit(1)
        # Inject auto-recorded traces into --traces list for downstream use
        if not args.traces:
            args.traces = recorded
        else:
            args.traces = list(args.traces) + recorded
        print(f"[*] Auto-record complete: {len(recorded)} traces added")

    # ── Resolve seed traces ──────────────────────────────────────────────────
    # Priority: --traces > --trace-dir > --trace
    all_traces: list[str] = []
    if args.traces:
        all_traces = [str(Path(t).resolve()) for t in args.traces if Path(t).exists()]
    elif args.trace_dir:
        d = Path(args.trace_dir)
        all_traces = sorted(str(p) for p in d.glob("*.trace") if p.is_file())
        if not all_traces:
            print(f"[!] No *.trace files found in {args.trace_dir}", file=sys.stderr)
            sys.exit(1)
    elif args.trace:
        all_traces = [args.trace]
    else:
        print("[!] Specify at least one of --trace, --traces, or --trace-dir", file=sys.stderr)
        sys.exit(1)

    primary_trace = all_traces[0]
    if len(all_traces) > 1:
        print(f"[*] Multi-seed mode: {len(all_traces)} traces loaded")
        for i, t in enumerate(all_traces):
            print(f"    [{i}] {t}")

    # ── Multi-trace round-robin mode ─────────────────────────────────────────
    if args.multi_trace and len(all_traces) > 1:
        from orchestrator.multi_trace_fuzzer import MultiTraceFuzzer
        core_kw = {}
        if args.ld_prefix:
            core_kw['ld_prefix'] = args.ld_prefix
        elif args.sim_root:
            core_kw['ld_prefix'] = args.sim_root
        if args.auth_boundary:
            core_kw['auth_boundary'] = args.auth_boundary
        if args.fork_point is not None:
            core_kw['manual_fork_point'] = args.fork_point
        fuzzer = MultiTraceFuzzer(
            traces=all_traces,
            qemu_path=args.qemu,
            target_binary=args.target,
            output_dir=args.output,
            rotation_chunk=args.chunk,
            **core_kw,
        )
        fuzzer.run(total_iterations=args.iterations)
        return 0

    global _fuzzing_core_ref
    fuzzing_core = None
    try:
        # Use FuzzingCore._derive_arch() for consistent arch detection
        arch = FuzzingCore._derive_arch(args.qemu)

        # Initialize Core
        if args.disable_smartdict:
            from conductor.mutator import BaseMutator
            mutator = BaseMutator()
        else:
            mutator = SmartMutator(
                primary_trace,
                target_binary=args.target,
                word_size=args.word_size,
                endian=args.endian,
                dictionary_file=args.dictionary,
                arch=arch,
                auth_boundary=args.auth_boundary,
            )

        fuzzing_core = _fuzzing_core_ref = FuzzingCore(
            qemu_path=args.qemu,
            target_binary=args.target,
            initial_trace=primary_trace,
            extra_seed_traces=all_traces[1:],   # additional seeds for rotation
            output_dir=args.output,
            mutator=mutator,
            use_fork_server=True,  # Internal design: high-speed fork server
            enable_persistence=args.persistence,
            target_args=args.args,
            enable_tree_viz=args.tree,
            ld_prefix=args.ld_prefix,
            manual_fork_point=args.fork_point,
            enable_dfc=not args.disable_dfc,
            enable_pathfinder=not args.disable_pathfinder,
            auth_boundary=args.auth_boundary  # ✅ FIX: pass through so FuzzingCore can preserve it
        )
        
        # Multi-Process Mode
        if args.workers > 1:
            from multiprocess.fuzz_master import FuzzMaster
            print(f"[*] Starting Multi-Process Master with {args.workers} workers")
            master = FuzzMaster(
                qemu_path=args.qemu,
                target_binary=args.target,
                initial_trace=args.trace,
                target_args=args.args,
                num_workers=args.workers,
                sync_dir=args.output,
                mutator_type="base" if args.disable_smartdict else "smart",
                enable_pathfinder=not args.disable_pathfinder,
                enable_persistence=args.persistence,
                dictionary_file=args.dictionary,
                ld_prefix=args.ld_prefix,
                manual_fork_point=args.fork_point
            )
            master.run()
            return 0

        # Run Fuzzing (Single-Process)
        stop_conditions = {
            'max_iterations': args.iterations,
            'no_progress_timeout': None if args.infinite else args.no_progress_timeout,
            'infinite': args.infinite
        }

        fuzzing_core.run_advanced(stop_conditions)
        
        print("\n✅ Fuzzing completed successfully!")
        return 0
    
    except KeyboardInterrupt:
        print("\n[Main] Interrupted by user")
        return 130
    
    except Exception as e:
        print(f"\n❌ Error during fuzzing: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    finally:
        if fuzzing_core:
            print("[Main] Cleaning up...")
            fuzzing_core.cleanup()

if __name__ == '__main__':
    sys.exit(main())
