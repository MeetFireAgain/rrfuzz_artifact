#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RR-Fuzz Multi-Process Entry Point

Multi-process fuzzing using FuzzMaster to coordinate multiple workers.
Implements Layer 4 of DETAILED_ARCHITECTURE.md.

Usage:
    # Basic multi-process fuzzing (8 workers)
    python3 fuzz_multiprocess.py --qemu ./qemu --trace trace.bin --target ./program -n 8
    
    # With smart mutation
    python3 fuzz_multiprocess.py --qemu ./qemu --trace trace.bin --target ./program -n 4 --smart
    
    # With time limit (1 hour)
    python3 fuzz_multiprocess.py --qemu ./qemu --trace trace.bin --target ./program -n 8 --timeout 3600

Author: RR-Fuzz Team
Date: 2025-11-03
"""

import os
import sys
import signal
import argparse
import multiprocessing as mp
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from multiprocess.fuzz_master import FuzzMaster


# Global for signal handling
_fuzz_master = None


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global _fuzz_master
    
    print(f"\n[Main] Received signal {signum}, shutting down...")
    
    if _fuzz_master:
        _fuzz_master.shutdown_requested = True
    
    sys.exit(0)


def validate_args(args):
    """Validate command line arguments"""
    errors = []
    
    if not os.path.exists(args.qemu):
        errors.append(f"QEMU executable not found: {args.qemu}")
    
    if not os.path.exists(args.target):
        errors.append(f"Target binary not found: {args.target}")
    
    if not os.path.exists(args.trace):
        errors.append(f"Trace file not found: {args.trace}")
    
    if args.recipe and not os.path.exists(args.recipe):
        errors.append(f"Recipe file not found: {args.recipe}")
    
    if args.workers < 1:
        errors.append(f"Number of workers must be >= 1")
    
    if args.timeout and args.timeout < 1:
        errors.append(f"Timeout must be >= 1 second")
    
    return errors


def main():
    """Main entry point"""
    global _fuzz_master
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='RR-Fuzz - Multi-Process Fuzzing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic multi-process fuzzing (8 workers)
  python3 fuzz_multiprocess.py --qemu ./qemu --trace trace.bin --target ./program -n 8
  
  # Smart mutation with 4 workers
  python3 fuzz_multiprocess.py --qemu ./qemu --trace trace.bin --target ./program -n 4 --smart
  
  # Recipe-driven with 8 workers
  python3 fuzz_multiprocess.py --qemu ./qemu --trace trace.bin --target ./program -n 8 \\
      --smart --recipe recipes.json
  
  # Time-limited (1 hour, 16 workers)
  python3 fuzz_multiprocess.py --qemu ./qemu --trace trace.bin --target ./program -n 16 \\
      --timeout 3600

For more information, see ARCHITECTURE_README.md
        """
    )
    
    # Required arguments
    parser.add_argument('--qemu', required=True,
                        help='Path to QEMU executable')
    parser.add_argument('--target', required=True,
                        help='Path to target binary')
    parser.add_argument('--trace', required=True,
                        help='Path to initial trace file (seed)')
    parser.add_argument('--args', default=None,
                        help='Target binary arguments')
    
    # Multi-process configuration
    parser.add_argument('-n', '--workers', type=int, default=mp.cpu_count(),
                        help=f'Number of worker processes (default: {mp.cpu_count()})')
    parser.add_argument('--sync-dir', default='sync_dir',
                        help='Synchronization directory (default: sync_dir)')
    
    # Optional arguments
    parser.add_argument('--timeout', type=int, default=None,
                        help='Maximum time in seconds (default: unlimited)')
    parser.add_argument('--display-interval', type=int, default=5,
                        help='Display interval in seconds (default: 5)')
    
    # Mutation mode
    mutation_group = parser.add_mutually_exclusive_group()
    mutation_group.add_argument('--smart', action='store_true',
                                help='Use smart mutation (trace-aware)')
    mutation_group.add_argument('--random', action='store_true',
                                help='Use random mutation (default)')
    
    # Recipe support
    parser.add_argument('--recipe', default=None,
                        help='Recipe file for guided mutation (requires --smart)')
    
    # Persistence support
    parser.add_argument('--persistence', action='store_true',
                        help='Enable per-worker persistence (auto-save/resume)')
    
    # PathFinder control
    parser.add_argument('--no-pathfinder', action='store_false', dest='pathfinder',
                        help='Disable PathFinder (CFG guidance)')
    parser.set_defaults(pathfinder=True)
    
    args = parser.parse_args()
    
    # Validate arguments
    errors = validate_args(args)
    if errors:
        print("❌ Validation errors:")
        for error in errors:
            print(f"  - {error}")
        return 1
    
    # Check recipe without smart
    if args.recipe and not args.smart:
        print("⚠️  Warning: --recipe requires --smart, enabling smart mutation")
        args.smart = True
    
    # Determine mutator type
    mutator_type = "smart" if args.smart else "base"
    
    # Print configuration
    print(f"\n{'=' * 70}")
    print(f"RR-Fuzz - Multi-Process Fuzzing")
    print(f"{'=' * 70}")
    print(f"QEMU:         {args.qemu}")
    print(f"Target:       {args.target}")
    if args.args:
        print(f"Args:         {args.args}")
    print(f"Trace:        {args.trace}")
    print(f"Sync Dir:     {args.sync_dir}")
    print(f"Workers:      {args.workers}")
    print(f"Mode:         {'Smart' if args.smart else 'Random'} Mutation")
    if args.recipe:
        print(f"Recipe:       {args.recipe}")
    if args.timeout:
        print(f"Timeout:      {args.timeout}s")
    print(f"{'=' * 70}\n")
    
    # Create FuzzMaster
    try:
        print("[Main] Creating FuzzMaster...")
        fuzz_master = FuzzMaster(
            qemu_path=args.qemu,
            target_binary=args.target,
            target_args=args.args,
            initial_trace=args.trace,
            num_workers=args.workers,
            sync_dir=args.sync_dir,
            mutator_type=mutator_type,
            recipe_file=args.recipe,
            master_timeout=args.timeout,
            enable_persistence=args.persistence,
            enable_pathfinder=args.pathfinder
        )
        _fuzz_master = fuzz_master
        
        # Run fuzzing
        print("\n[Main] Starting multi-process fuzzing...\n")
        fuzz_master.run()
        
        print("\n✅ Multi-process fuzzing completed successfully!")
        return 0
    
    except KeyboardInterrupt:
        print("\n[Main] Interrupted by user")
        if _fuzz_master:
            _fuzz_master.shutdown()
        return 130
    
    except Exception as e:
        print(f"\n❌ Error during fuzzing: {e}")
        import traceback
        traceback.print_exc()
        
        if _fuzz_master:
            _fuzz_master.shutdown()
        
        return 1


if __name__ == '__main__':
    # Set multiprocessing start method to 'spawn' for better compatibility
    mp.set_start_method('spawn', force=True)
    sys.exit(main())

