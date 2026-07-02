#!/usr/bin/env python3
"""
FuzzingCore - Layer 2: Core Fuzzing Engine + Layer 5: Monitoring & Analysis

Main fuzzing loop coordinator, orchestrating all fuzzing components.
Implements Layer 2 and Layer 5 architectures described in DETAILED_ARCHITECTURE.md.

Layer 5 Integration (DETAILED_ARCHITECTURE.md lines 382-408):
- SyscallTree Visualizer: Automatically generate syscall tree HTML (Key feature)
- CrashAnalyzer: Automatically analyze and deduplicate crashes
- CorpusManager: Automatically save and manage corpus
"""

import os
import sys
import time
import subprocess
import threading
import glob
import json
import random
import signal
import gc
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from pathlib import Path

from .trace_manager import TraceManager, Trace
from .mutator import BaseMutator, SmartMutator
from .coverage import CoverageTracker
from .qemu_executor import QEMUExecutor, ExecutionResult
from .fuzzing_metrics import FuzzingMetrics, FailureReason
from .iteration_result import (
    IterationResult, IterationStatus,
    create_success_result, create_failure_result
)
from .mutation_dependency_graph import MutationDependencyGraph
from .async_logger import AsyncLogger, alog
from .watchdog import FuzzingWatchdog
from .static_analyzer import StaticAnalyzer
from .evolution_engine import EvolutionEngine, ReRecordingExecutor
from .trace_pool import TracePool
from .target_profile import TargetProfile
from .lifecycle_manager import TargetLifecycleManager
from .security_watchdog import SecurityWatchdog
from .checkpoint import CheckpointManager
from .constants import get_mutation_type_name

# Ensure parent directory is in sys.path for internal imports
_fuzzing_dir = Path(__file__).parent.parent.resolve()
if str(_fuzzing_dir) not in sys.path:
    sys.path.insert(0, str(_fuzzing_dir))

# Attempt to import PathFinder (Prioritize the dual-level CFG version)
_HAS_PATH_FINDER = False
PathFinder = None
PathFinderConfig = None

# Prioritize DualLevelPathFinder for CFG-guided fuzzing
try:
    from .dual_level_path_finder import DualLevelPathFinder
    PathFinder = DualLevelPathFinder
    _HAS_PATH_FINDER = True
    print("[FuzzingCore] Loaded DualLevelPathFinder")
except ImportError as e:
    print(f"[FuzzingCore] ⚠️ DualLevelPathFinder import failed: {e}. PathFinder unavailable.")
    _HAS_PATH_FINDER = False

# Attempt to import RecipePool
_HAS_RECIPE_POOL = False
RecipePool = None
try:
    from multiprocess import recipe_pool as _rp_module
    RecipePool = _rp_module.RecipePool
    _HAS_RECIPE_POOL = True
except ImportError:
    pass

# Attempt to import DynamicForkController
_HAS_DYNAMIC_FORK = False
DynamicForkController = None
try:
    from multiprocess import dynamic_fork_controller as _dfc_module
    DynamicForkController = _dfc_module.DynamicForkController
    _HAS_DYNAMIC_FORK = True
except ImportError:
    pass

# Layer 5: Import monitoring and analysis components
try:
    from multiprocess.crash_analyzer import CrashAnalyzer as Layer5CrashAnalyzer
    from multiprocess.corpus_manager import CorpusManager
    _HAS_LAYER5_CRASH = True
    _HAS_LAYER5_CORPUS = True
except ImportError:
    _HAS_LAYER5_CRASH = False
    _HAS_LAYER5_CORPUS = False

# ✅ BB Trace support
try:
    from .bb_trace_parser import BBTraceParser, BBEntry
    BB_TRACE_AVAILABLE = True
except ImportError:
    BB_TRACE_AVAILABLE = False


@dataclass
class FuzzingStatistics:
    """Fuzzing session statistics"""
    total_execs: int = 0
    paths_found: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    timeouts: int = 0
    last_new_path: float = field(default_factory=time.time)
    start_time: float = field(default_factory=time.time)
    session_start_time: float = field(default_factory=time.time)
    session_execs: int = 0
    
    @property
    def execs_per_sec(self) -> float:
        """Calculate executions per second (Session-based)"""
        elapsed = time.time() - self.session_start_time
        if elapsed < 1.0:
            return 0.0
        return self.session_execs / elapsed

    @property
    def historical_execs_per_sec(self) -> float:
        """Calculate historical executions per second"""
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0
        return self.total_execs / elapsed
    
    @property
    def elapsed_time(self) -> float:
        """Get elapsed time"""
        return time.time() - self.start_time


class CrashDetector:
    """Simple crash detector and deduplicator"""
    
    def __init__(self, output_dir: str, worker_id: int = 0):
        self.output_dir = output_dir
        self.worker_id = worker_id
        self.crashes = []
        self.crash_hashes = set()
    
    def save_crash(self, result: ExecutionResult, trace: Trace, mutations: list):
        """Save crash info"""
        import hashlib

        # Create crash directory
        crash_dir = Path(self.output_dir) / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate crash hash based on PC + signal for deduplication.
        # Including mutation content caused every variant to be a "unique" crash.
        pc = getattr(result, 'pc', 0) or 0
        # Normalize garbage PCs: SHM field is 8 bytes, but 32-bit targets only write
        # the lower 4 bytes — upper 32 bits are uninitialized junk causing every
        # crash to look unique. Any PC > 4GB is treated as invalid; collapse to 0
        # (signal-only grouping), matching CrashAnalyzer._compute_crash_hash logic.
        if pc > 0x100000000:
            pc = 0
        crash_data = f"{pc}_{result.signal_number}"
        crash_hash = hashlib.md5(crash_data.encode()).hexdigest()[:8]
        
        # Check if duplicate
        if crash_hash in self.crash_hashes:
            print(f"[CrashDetector] Duplicate crash (hash={crash_hash}), skipping")
            return False
        
        self.crash_hashes.add(crash_hash)
        crash_id = f"crash_w{self.worker_id}_{len(self.crashes):06d}_{crash_hash}"
        
        # Save crash trace
        import shutil
        crash_trace = crash_dir / f"{crash_id}.bin"
        if os.path.exists(trace.file_path):
            shutil.copy(trace.file_path, crash_trace)
        
        # Save crash metadata
        crash_meta = crash_dir / f"{crash_id}.meta"
        
        try:
            payload = {
                'crash_id': crash_id,
                'crash_hash': crash_hash,
                'trace_id': trace.id,
                'trace_file': str(trace.file_path),
                'status': int(result.status),
                'status_name': str(result.status_name),
                'exit_code': int(result.qemu_exit_code),
                'signal': int(result.signal_number),
                'timestamp': time.time(),
                'mutations': [
                    {
                        'syscall_index': m.syscall_index,
                        'syscall_name': 'unknown',
                        'cmd': m.cmd,
                        'mutation_type': get_mutation_type_name(m.cmd),  # ✅ Use mapping
                        'arg_index': m.arg_index,
                        'data': m.data.hex() if isinstance(m.data, bytes) else str(m.data),
                        'offset': m.offset,
                        'size': m.size,
                    }
                    for m in mutations
                ],
            }
            tmp_meta = crash_meta.with_suffix(crash_meta.suffix + '.tmp')
            with open(tmp_meta, 'w') as f:
                json.dump(payload, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_meta, crash_meta)
        except Exception as e:
            print(f"[CrashDetector] ❌ Failed to dump metadata to JSON: {e}")
            import traceback
            traceback.print_exc()
        
        self.crashes.append(crash_id)
        print(f"[CrashDetector] 💥 New crash saved: {crash_id}")
        return crash_id  # return crash_id so callers can reference the saved file


class FuzzingCore:
    """
    Layer 2: Core Fuzzing Loop Coordinator
    
    Responsibilities:
    1. Coordinate all fuzzing components
    2. Implement the main fuzzing loop
    3. Manage fuzzing statistics
    4. Handle crashes and new coverage
    5. Save interesting traces
    6. Detect and save crashes
    7. Update statistics
    """
    
    def __init__(
        self,
        qemu_path: str,
        target_binary: str,
        initial_trace: str,
        output_dir: str = "fuzzing_output",
        mutator: Optional[BaseMutator] = None,
        enable_monitoring: bool = True,
        enable_pathfinder: bool = True,  # PathFinder enabled by default
        enable_tree_viz: bool = False,   # Visualizer disabled by default (performance)
        use_fork_server: bool = True,    # AFL-style persistent mode (Process Persistence)
        enable_persistence: bool = False,# Unified session persistence (Save/Auto-Resume)
        use_energy_scheduler: bool = True,  # Energy Scheduler enabled by default (+40% coverage)
        initial_stats: Optional[Dict] = None,
        shared_coverage: Optional[Any] = None,  # SharedCoverage for multi-process mode
        target_args: str = "",   # Target program arguments
        sync_dir: Optional[str] = None, # ✅ Sync directory for seed exchange
        worker_id: int = 0,      # ✅ Worker ID for identifying own seeds
        ld_prefix: Optional[str] = None, # ✅ QEMU LD Prefix (RootFS)
        manual_fork_point: Optional[int] = None, # ✅ Force specific fork point
        enable_dfc: bool = True,         # ✅ Ablation: disable DynamicForkController
        auth_boundary: int = 0,          # ✅ Post-auth boundary syscall index
        extra_seed_traces: Optional[List[str]] = None,  # Additional traces for corpus rotation
    ):
        # """
        alog(f"[FuzzingCore] __init__ called. _HAS_PATH_FINDER={_HAS_PATH_FINDER}, PathFinder class={(PathFinder.__name__ if PathFinder else 'None')}", "CORE")
        self.qemu_path = qemu_path
        self.recipe_pool = None

        # ✅ Performance: Start AsyncLogger
        self.logger = AsyncLogger(log_file=os.path.join(output_dir, "fuzzing.log"), console=True)
        self.logger.start()
        alog(f"Initializing... ld_prefix={ld_prefix}", "CORE", "INFO")

        # ✅ FIX: Store ld_prefix for stable restarts
        self.ld_prefix = ld_prefix

        # Auto-detect auth_boundary from the seed trace if caller didn't specify one.
        # auth_boundary = index of the first accept() / socketcall(SYS_ACCEPT) in the trace.
        # Pre-auth syscalls (ld.so loading, libc init, TCP bind/listen) are excluded from
        # the mutable candidate pool — they cannot be influenced by a remote attacker.
        if auth_boundary == 0 and initial_trace:
            try:
                import conductor.trace_analyzer as _ta_mod
                _ta = _ta_mod.TraceAnalyzer(initial_trace, arch=self._derive_arch(qemu_path))
                _detected = _ta.get_auth_boundary()
                if _detected > 0:
                    auth_boundary = _detected
                    alog(f"auth_boundary auto-detected: {auth_boundary}", "CORE", "INFO")
            except Exception as _e:
                alog(f"auth_boundary auto-detection failed: {_e}", "CORE", "WARN")
        self.auth_boundary = auth_boundary  # ✅ Persist for SmartMutator recreation

        # 🔥 2026-03-10: Clean up orphaned shared memory from previous crashed runs
        from .shared_memory import FuzzSharedMemory
        FuzzSharedMemory.cleanup_orphaned_shm()


        # Core Component: Seed & Trace Management
        self.trace_pool = TracePool(output_dir)
        if use_energy_scheduler:
            from .seed_manager_adapter import SeedManagerAdapter
            self.trace_manager = SeedManagerAdapter(
                initial_trace=initial_trace,
                use_advanced=True
            )
            # Link trace_manager to pool
            self.trace_pool.add_trace(self.trace_manager.get_trace_by_id("trace_000"), category='INITIAL', save=False)
            alog("Energy Scheduler / AdvancedSeedQueue enabled", "CORE", "INFO")
        else:
            self.trace_manager = TraceManager(initial_trace=initial_trace)
            self.trace_pool.add_trace(self.trace_manager.trace_pool[0], category='INITIAL', save=False)
            alog("📝 Using legacy TraceManager", "CORE", "INFO")
        alog("TraceManager initialized", "CORE", "DEBUG")

        # ── Multi-seed corpus rotation ──────────────────────────────────────
        # Register any extra seed traces so the energy scheduler / trace_manager
        # can select among them. The primary trace is already registered above.
        self._all_seed_traces: List[str] = [initial_trace] + (extra_seed_traces or [])
        self._seed_cursor: int = 0          # round-robin cursor for forced rotation
        self._seed_rotate_every: int = 200  # rotate every N iterations if no new cov
        if extra_seed_traces:
            for extra_trace in extra_seed_traces:
                try:
                    if os.path.exists(extra_trace):
                        self.trace_manager.add_trace(extra_trace)
                        alog(f"Extra seed trace registered: {extra_trace}", "CORE", "INFO")
                except Exception as _e:
                    alog(f"Failed to register extra seed {extra_trace}: {_e}", "CORE", "WARN")

        # Layer 2: Core Components
        self.mutator = mutator if mutator else BaseMutator()
        # ✅ Multi-process: Pass shared_coverage to CoverageTracker
        self.coverage_tracker = CoverageTracker(shared_coverage=shared_coverage)
        alog("CoverageTracker initialized", "CORE", "DEBUG")


        # ✅ Layer 2: Core Components - Execution Engine
        self.use_fork_server = use_fork_server
        if use_fork_server:
            alog("🚀 Using Process Persistence (Fork Server Mode)", "CORE", "INFO")
        else:
            alog("🚀 Using Fresh Execution Mode (One process per task)", "CORE", "INFO")
        # Derive target architecture from QEMU path
        self.arch = FuzzingCore._derive_arch(qemu_path)
        
        self.execution_engine = QEMUExecutor(
            qemu_path, 
            target_binary, 
            target_args=target_args,
            persistent_mode=use_fork_server,
            log_file=os.path.join(output_dir, "qemu_debug.log"),
            ld_prefix=ld_prefix
        )
        alog(f"Execution engine initialized. SHM_ENV={self.execution_engine._coverage_env_value}, Target Arch={self.arch}", "CORE", "INFO")


        self.crash_detector = CrashDetector(output_dir, worker_id=worker_id)
        alog("CrashDetector initialized", "CORE", "DEBUG")


        # Fuzzing Session Tracking
        self.stats = FuzzingStatistics()
        if initial_stats:
            for k, v in initial_stats.items():
                if hasattr(self.stats, k):
                    setattr(self.stats, k, v)
            alog(f"Restored stats: execs={self.stats.total_execs}, paths={self.stats.paths_found}", "CORE", "INFO")
            
        self.metrics = FuzzingMetrics()
        self.mutation_graph = MutationDependencyGraph()
        
        # ✅ Restore persistence state if provided
        self.start_time = initial_stats.get('start_time', time.time()) if initial_stats else time.time()
        self.total_executions = initial_stats.get('total_execs', 0) if initial_stats else 0
        self.total_iterations = initial_stats.get('total_iterations', 0) if initial_stats else 0 

        # Output directory and paths
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.target_binary = target_binary  # P0-1: Save for PathFinder
        self.target_args = target_args       # ✅ Fix: Store target_args for restart
        self.initial_trace = initial_trace   # ✅ Save initial trace for PathFinder mapping

        
        # PathFinder support (multi-level static analysis + dynamic trace mapping)
        self.enable_pathfinder = enable_pathfinder and _HAS_PATH_FINDER
        self.path_finder = None
        
        # Dynamic Fork Controller (intelligent multi-path exploration)
        self.enable_dynamic_fork = _HAS_DYNAMIC_FORK
        self.dynamic_fork = None
        self.security_watchdog = SecurityWatchdog()
        
        if enable_pathfinder and _HAS_PATH_FINDER:
            # Initialize PathFinder
            self._init_pathfinder()
        
        # ✅ Enable Syscall Tree Visualizer
        self.enable_tree_viz = enable_tree_viz
        
        # ✅ Start Visualizer in __init__
        if enable_tree_viz:
            try:
                self._start_realtime_visualizer()
            except Exception as e:
                alog(f"⚠️ Tree Visualizer failed to start: {e}", "CORE", "WARN")
        
        # ✅ Avoid duplicate RecipePool creation
        if not self.recipe_pool and _HAS_RECIPE_POOL and isinstance(mutator, SmartMutator) and mutator.recipe_mode:
            self.recipe_pool = RecipePool(max_active=50, retirement_threshold=100)
            # Load initial recipes from mutator
            if mutator.recipes:
                self.recipe_pool.add_recipes(mutator.recipes)
                alog(f"✅ RecipePool enabled ({len(mutator.recipes)} recipes)", "CORE", "INFO")
        
        self.last_cfg_analysis_iter = 0
        self.last_cfg_analysis_time = 0
        self.cfg_analysis_interval_iters = 100
        self.cfg_analysis_interval_time = 60
        self.min_cfg_analysis_interval = 5.0 # Minimum seconds between analyses even if new coverage
        
        self.trace_analyzer_cache = {} # {trace_file: TraceAnalyzer}
        self.max_trace_cache_size = 5  # 🔥 2026-03-19: Reduced from 30 to 5; each TraceAnalyzer can hold 200MB+
    
        self.last_cfg_analysis_time = time.time()
        self.last_cfg_analysis_iter = 0
        
        # ✅ Multi-process seed sharing
        self.sync_dir = Path(sync_dir) if sync_dir else None
        self.worker_id = worker_id
        self.imported_seeds = set()
        self.last_seed_sync_iter = 0
        self.seed_sync_interval = 200 # Import every 200 iterations
        
        # Layer 5: Monitoring and Analysis Components
        self.enable_monitoring = enable_monitoring  # ✅ Ensure defined
        self.layer5_crash_analyzer = None
        self.layer5_corpus_manager = None
        
        if enable_monitoring or self.sync_dir:
            alog(f"🔍 Layer 5 enabled: Monitoring & Analysis (SyncMode: {bool(self.sync_dir)})", "CORE", "INFO")
            
            # 1. CrashAnalyzer (deduplication and analysis)
            if _HAS_LAYER5_CRASH:
                # In MP mode, use sync_dir for global deduplication
                analyzer_dir = self.sync_dir if self.sync_dir else Path(output_dir)
                self.layer5_crash_analyzer = Layer5CrashAnalyzer(analyzer_dir, worker_id=self.worker_id, target_name=Path(self.target_binary).name)
                alog(f"  ✅ CrashAnalyzer enabled (Target: {analyzer_dir})", "CORE", "INFO")
            else:
                alog(f"  ⚠️  CrashAnalyzer unavailable (using basic CrashDetector)", "CORE", "WARN")
            
            # 2. CorpusManager (persistence)
            if _HAS_LAYER5_CORPUS:
                corpus_dir = (self.sync_dir / "corpus") if self.sync_dir else (Path(output_dir) / "corpus")
                self.layer5_corpus_manager = CorpusManager(corpus_dir)
                alog(f"  ✅ CorpusManager enabled (Target: {corpus_dir})", "CORE", "INFO")
            else:
                alog(f"  ⚠️  CorpusManager unavailable", "CORE", "WARN")
            
        self.dynamic_fork_controller = None
        if enable_dfc and _HAS_DYNAMIC_FORK and DynamicForkController is not None:
            try:
                # Pre-load analyzer for initial trace to share among components
                initial_analyzer = self._get_analyzer(initial_trace)
                
                # If mutator is SmartMutator, ensure it uses this analyzer
                if isinstance(self.mutator, SmartMutator):
                     self.mutator.analyzer = initial_analyzer
                
                # ✅ Layer 6: Evolutionary Promotion Engine (Must be init before DFC)
                if not hasattr(self, 'evolution_engine') or self.evolution_engine is None:
                    self.evolution_engine = EvolutionEngine(output_dir)
                    self.target_profile = None
                    self._init_re_recorder(output_dir)

                self.dynamic_fork_controller = DynamicForkController(
                    executor=self.execution_engine,
                    path_finder=self.path_finder,
                    mutator=self.mutator,
                    recipe_pool=self.recipe_pool,
                    coverage_tracker=self.coverage_tracker,
                    trace_manager=self.trace_manager,
                    fuzzing_stats=self.stats,
                    mutation_graph=self.mutation_graph,
                    crash_detector=self.crash_detector,
                    crash_analyzer=self.layer5_crash_analyzer,
                    analyzer=initial_analyzer,
                    evolution_engine=self.evolution_engine,
                    manual_fork_point=manual_fork_point,
                    auth_boundary=self.auth_boundary,  # ✅ FIX: DFC knows auth boundary
                    arch=self.arch
                )

                if manual_fork_point is not None:
                    alog(f"🎯 Manual Fork Point OVERRIDE: {manual_fork_point}", "CORE", "INFO")
                    self.dynamic_fork_controller.manual_fork_point = manual_fork_point
                self.dynamic_fork_controller.triage_callback = self._triage_crash_online
                alog(f"DynamicForkController enabled (Depth-First mode)", "CORE", "INFO")
            except Exception as e:
                alog(f"⚠️ DynamicForkController initialization failed: {e}", "CORE", "WARN")
                import traceback
                traceback.print_exc()
                self.dynamic_fork_controller = None
        elif not enable_dfc:
            alog(f"[Ablation] DynamicForkController DISABLED (--disable-dfc)", "CORE", "INFO")
            self._ensure_evolution_engine(output_dir)
        else:
            alog(f"⚠️ DynamicForkController unavailable", "CORE", "WARN")
            self._ensure_evolution_engine(output_dir)

        # ✅ Initialize Watchdog (Phase 1 Fix: Tighten timeout for performance)
        self.watchdog = FuzzingWatchdog(
            executor_check_func=self._check_executor_alive,
            restart_func=self._restart_execution_engine,
            timeout_seconds=45,  # Optimized: (2s exec + 0.5s overhead) * 8 Havoc stacked * 2 safety factor
            check_interval=2     # Increased frequency to 2s
        )
        alog(f"  Watchdog: Enabled (Timeout=45s)", "CORE", "INFO")
        # Wire watchdog into DFC and executor so they can suppress during intentional QEMU resets
        if self.dynamic_fork_controller:
            self.dynamic_fork_controller._watchdog = self.watchdog
        if self.execution_engine:
            self.execution_engine._watchdog = self.watchdog

        # ✅ State Persistence (Checkpoint System)
        self.enable_persistence = enable_persistence
        self.checkpoint_manager = CheckpointManager(output_dir) if enable_persistence else None
        self.checkpoint_interval = 300  # Save every 5 minutes
        self.last_checkpoint_time = time.time()
        
        alog(f"  Output directory: {output_dir}", "CORE", "INFO")
        alog(f"  Initial trace: {initial_trace}", "CORE", "INFO")
        alog(f"  Monitoring: {'Enabled' if enable_monitoring else 'Disabled'}", "CORE", "INFO")
        alog(f"  PathFinder: {'Enabled' if self.path_finder else 'Disabled'}", "CORE", "INFO")
        alog(f"  Syscall Tree Export: {'Enabled' if enable_tree_viz else 'Disabled'}", "CORE", "INFO")
        # print(f"  Dynamic Fork: {'Enabled' if self.dynamic_fork_controller else 'Disabled'}")

        if self.checkpoint_manager:
            if self.checkpoint_manager.exists():
                alog(f"📂 Found existing checkpoint in {output_dir}. Auto-resuming...", "CORE", "INFO")
                self.checkpoint_manager.load(self)
            else:
                alog(f"💾 Persistence enabled. Periodic saving every {self.checkpoint_interval}s", "CORE", "INFO")
        
        alog(f"✅ Initialization complete", "CORE", "INFO")

    def _init_pathfinder(self):
        """P1: Initialize PathFinder with lazy build support"""
        if not self.enable_pathfinder or not PathFinder:
            return
        
        try:
            alog(f"🧭 Initializing PathFinder...", "CORE", "INFO")
            # 1. Selection logic for PathFinder
            if isinstance(self.mutator, SmartMutator) and getattr(self.mutator, 'path_finder', None):
                 alog(f"♻️ Reusing PathFinder from Mutator", "CORE", "INFO")
                 self.path_finder = self.mutator.path_finder
            else:
                 # DualLevelPathFinder uses simplified initialization
                 self.path_finder = PathFinder(self.target_binary, config=None)
                 alog(f"💉 Injecting PathFinder into Mutator", "CORE", "INFO")
                 self.mutator.path_finder = self.path_finder

            # 2. Syscall Tree Loading (Phase 9: Closing Analysis Loop)
            tree_file = None
            # Check common locations — prefer JSON (canonical C export) over HTML
            potential_trees = [
                str(self.initial_trace) + ".tree.json",
                str(self.initial_trace) + ".tree.html",
                str(Path(self.initial_trace).with_suffix('')) + ".tree.json",
                str(Path(self.initial_trace).with_suffix('')) + ".tree.html",
                "/tmp/syscall_tree.json",
                "/tmp/syscall_tree.html",
                f"/tmp/syscall_tree_{os.getpid()}.json",
                f"/tmp/syscall_tree_{os.getpid()}.html",
            ]
            for pt in potential_trees:
                if os.path.exists(pt):
                    tree_file = pt
                    break
            # Glob fallback: pick most recent tree from a previous run.
            # C exports as .html (rr_tree_export_json writes an HTML bundle);
            # also check .json in case a future build changes the format.
            if tree_file is None:
                import glob as _glob
                candidates = _glob.glob("/tmp/syscall_tree_*.html") + _glob.glob("/tmp/syscall_tree_*.json")
                if candidates:
                    tree_file = max(candidates, key=os.path.getctime)
            
            if tree_file:
                alog(f"🌳 Found Syscall Tree: {tree_file}, performing precise mapping...", "CORE", "INFO")
                if self.path_finder.load_syscall_tree(tree_file):
                    alog(f"✅ Precise BB->Syscall mapping active ({len(self.path_finder.bb_to_syscall)} entries)", "CORE", "INFO")
                else:
                    alog(f"⚠️ Failed to load precise mapping from tree, falling back to heuristic", "CORE", "WARN")

            # 3. Static Analysis Augmentation (Phase C)
            if self.target_binary:
                cfg_cache = os.path.join("/tmp", f"static_cfg_{os.path.basename(self.target_binary)}.json")
                if not os.path.exists(cfg_cache):
                    alog(f"🔍 Running Static Analysis on {self.target_binary}...", "CORE", "INFO")
                    analyzer = StaticAnalyzer(self.target_binary)
                    if analyzer.analyze():
                        analyzer.save_results(cfg_cache)
                
                if os.path.exists(cfg_cache):
                    self.path_finder.load_static_cfg(cfg_cache)

            # 4. Component enablement
            if _HAS_RECIPE_POOL and RecipePool is not None:
                self.recipe_pool = RecipePool(max_active=50, retirement_threshold=100)
            
            alog(f"✅ PathFinder initialized (Lazy CFG mode enabled)", "CORE", "INFO")
        except Exception as e:
            alog(f"❌ PathFinder initialization failed: {e}", "CORE", "ERROR")
            self.path_finder = None
            self.recipe_pool = None
            import traceback
            traceback.print_exc()
        
        # If PathFinder is available, log its status
        if self.path_finder and self.path_finder.is_available():
            alog(f"✅ PathFinder enabled (Lazy CFG build mode)", "CORE", "INFO")
            if self.recipe_pool:
                alog(f"✅ RecipePool enabled (max_active=50)", "CORE", "INFO")
        elif self.path_finder and not self.path_finder.is_available():
            reason = getattr(self.path_finder, 'disabled_reason', 'unknown reason')
            alog(f"⚠️ PathFinder automatically disabled: {reason}", "CORE", "WARN")
            self.path_finder = None
            self.recipe_pool = None
        elif self.enable_pathfinder and not _HAS_PATH_FINDER:
            alog(f"⚠️ PathFinder unavailable (requires angr)", "CORE", "WARN")
            alog(f"  _HAS_PATH_FINDER={_HAS_PATH_FINDER}", "CORE", "WARN")

    def _ensure_evolution_engine(self, output_dir: str):
        """Initialize EvolutionEngine if not already done."""
        if not hasattr(self, 'evolution_engine') or self.evolution_engine is None:
            self.evolution_engine = EvolutionEngine(output_dir)
            self.target_profile = None
            self._init_re_recorder(output_dir)

    def _cleanup_orphan_qemu(self):
        """Kill orphaned (PPID=1) QEMU processes that leaked from previous runs."""
        my_pid = os.getpid()
        my_children = set()
        try:
            for pid_str in os.listdir('/proc'):
                if not pid_str.isdigit():
                    continue
                try:
                    ppid = int(open(f'/proc/{pid_str}/status').read().split('PPid:')[1].split()[0])
                    if ppid == my_pid:
                        my_children.add(int(pid_str))
                except Exception:
                    pass
        except Exception:
            pass
        try:
            pgrep = subprocess.run(
                ['pgrep', '-f', 'qemu-mips|qemu-arm|qemu-mipsel'],
                capture_output=True, text=True
            )
            killed = 0
            for qpid in [int(p) for p in pgrep.stdout.split() if p.strip()]:
                if qpid == my_pid or qpid in my_children:
                    continue
                try:
                    exe_name = os.readlink(f'/proc/{qpid}/exe').split('/')[-1]
                    if not exe_name.startswith('qemu-'):
                        continue
                    ppid = int(open(f'/proc/{qpid}/status').read().split('PPid:')[1].split()[0])
                    if ppid == 1:
                        os.kill(qpid, 9)
                        killed += 1
                except Exception:
                    continue
            if killed:
                alog(f"🧹 Killed {killed} orphaned QEMU processes", "CORE", "WARN")
        except Exception:
            pass

    def _check_executor_alive(self) -> bool:
        """Watchdog callback: Check if QEMU process is alive"""
        if not self.execution_engine:
            return True  # No engine yet, not an error
        if not self.execution_engine._qemu_ready:
            return True  # Intentionally between QEMU instances (transitioning)
        if self.execution_engine.process:
            return self.execution_engine.process.poll() is None
        return False

    def _restart_execution_engine(self):
        """Watchdog callback: Force restart QEMU"""
        alog("Watchdog triggering QEMU restart...", "CORE", "WARN")
        if self.execution_engine:
            try:
                self.execution_engine.stop_persistent_mode()
            except:
                pass 
        # Re-initialize engine
        self.execution_engine = QEMUExecutor(
            self.qemu_path, 
            self.target_binary, 
            target_args=self.target_args, # ✅ SAVE original args
            persistent_mode=True,
            log_file=os.path.join(self.output_dir, "qemu_debug.log"),
            ld_prefix=self.ld_prefix # ✅ FIX: Restore ld_prefix on restart
        )
        
        # 🔥 CRITICAL FIX: Update DynamicForkController with the NEW executor
        if self.dynamic_fork_controller:
            self.dynamic_fork_controller.executor = self.execution_engine
        # Re-wire watchdog so new executor can suppress during transitions
        if self.watchdog:
            self.execution_engine._watchdog = self.watchdog
            
        alog("QEMU Engine restarted by Watchdog", "CORE", "INFO")

    def _extract_covered_blocks(self) -> set:
        """
        Extracts covered basic blocks from the coverage bitmap
        
        Returns:
            A set of covered block addresses
        """
        covered = set()
        
        # Strategy A: Use PathFinder's precise mapping (High Accuracy)
        if self.path_finder and hasattr(self.path_finder, 'get_covered_bb_addresses'):
            covered = self.path_finder.get_covered_bb_addresses()
            if covered:
                alog(f"[FuzzingCore] _extract_covered_blocks: Using PathFinder ({len(covered)} BBs)", "DEBUG")
                return covered

        # Strategy B: Fallback to bitmap bits (Low Accuracy, Legacy)
        bits_set = 0
        for i, val in enumerate(self.coverage_tracker.global_bitmap):
            if val > 0:
                bits_set += 1
                # Heuristic: use bitmap index as block ID (very inaccurate)
                covered.add(i & 0xFFFF)
        
        if bits_set > 0:
            alog(f"[FuzzingCore] _extract_covered_blocks: Fallback mode, bits={bits_set}", "DEBUG")
        
        return covered

    def _select_coverage_driven_fork_points(self, trace: Trace, count: int) -> List[int]:
        """
        Selects coverage-driven fork points

        Strategy:
        1. If PathFinder is available, use syscalls near uncovered branches as fork points
        2. Otherwise, use an IO syscall rotation strategy as a fallback

        Parameters:
            trace: The current trace
            count: The number of fork points needed

        Returns:
            A list of fork point indices
        """
        fork_points = []

        # Strategy 1: Use PathFinder's uncovered branches
        if self.path_finder and hasattr(self.path_finder, 'uncovered_branches'):
            uncovered = self.path_finder.uncovered_branches
            if uncovered and len(uncovered) > 0:
                # PathFinder-guided fork point selection
                top_branches = uncovered[:count * 2] 
                for branch in top_branches:
                    if 'target_syscall_idx' in branch:
                        fork_points.append(branch['target_syscall_idx'])
                    elif 'from_syscall_idx' in branch:
                       fork_points.append(branch['from_syscall_idx'])

                    if len(fork_points) >= count:
                        break

        if fork_points:
                    alog(f"🎯 Using PathFinder-guided fork points: {fork_points[:count]}", "CORE", "INFO")
                    return fork_points[:count]

        # Strategy 2: Exploration Mode (Fallback for saturated graph)
        if self.path_finder and hasattr(self.path_finder, 'exploration_targets') and self.path_finder.exploration_targets:
            targets = self.path_finder.exploration_targets
            # Pick targets
            selected = random.sample(targets, min(len(targets), count))
            fork_points = [t['target_syscall_idx'] for t in selected]
            alog(f"🚀 Using Exploration Mode fork points: {fork_points}", "CORE", "INFO")
            return fork_points

        # Strategy 3: Blind Random Fallback (Last resort)
        # Use random Syscall Index as Fork point to explore possible hidden states
        alog(f"⚠️ PathFinder has no suggestions, enabling Random Exploration", "CORE", "WARN")
        
        # Assume trace has syscall_count attribute, or get it via trace.metadata
        # For simplicity, randomly select from 0 to 30 (assumption)
        limit = 20
        if hasattr(trace, 'metadata') and hasattr(trace.metadata, 'syscall_count'):
             limit = trace.metadata.syscall_count
        
        # Randomly select 'count' points
        random_points = sorted(random.sample(range(max(1, limit)), min(count, limit)))
        return random_points

    @staticmethod
    def _derive_arch(qemu_path: str) -> str:
        """Derive architecture string from QEMU binary name."""
        name = os.path.basename(qemu_path).lower()
        if 'aarch64' in name:   return 'arm64'
        if 'arm' in name:       return 'arm'
        if 'mipsel' in name:    return 'mips'   # little-endian MIPS → use mips map
        if 'mips' in name:      return 'mips'
        if 'x86_64' in name:    return 'x86_64'
        if 'i386' in name:      return 'i386'
        return 'auto'

    def _get_analyzer(self, trace_file: str):
        """Get or create TraceAnalyzer for a trace file (per-process cache)"""
        if trace_file in self.trace_analyzer_cache:
            return self.trace_analyzer_cache[trace_file]
        
        # ✅ Check SmartMutator cache (global to process)
        from .mutator import SmartMutator
        if trace_file in SmartMutator._trace_cache:
            analyzer = SmartMutator._trace_cache[trace_file]
            # Ensure arch matches even if cached (though it should)
            if hasattr(analyzer, 'arch') and analyzer.arch == 'auto' and self.arch != 'auto':
                analyzer.arch = self.arch
            self.trace_analyzer_cache[trace_file] = analyzer
            return analyzer
        
        from . import trace_analyzer
        # Pass derived arch to analyzer
        analyzer = trace_analyzer.TraceAnalyzer(trace_file, arch=self.arch)
        
        # 🔥 2026-01-22: Cap cache size to prevent OOM
        if len(self.trace_analyzer_cache) >= self.max_trace_cache_size:
            # Simple FIFO-ish clear (clear all to be safe and simple)
            alog(f"⚠️ Trace cache limit reached ({self.max_trace_cache_size}), clearing cache...", "CORE", "INFO")
            for a in self.trace_analyzer_cache.values():
                if hasattr(a, 'clear'):
                    a.clear()
            self.trace_analyzer_cache.clear()
            gc.collect()
            
        self.trace_analyzer_cache[trace_file] = analyzer
        return analyzer

    def _display_progress(self, force: bool = False):
        """Display fuzzing progress (every 100 executions or forced)"""
        if not force and self.stats.total_execs % 100 != 0:
            return
        
        cov_stats = self.coverage_tracker.get_stats()

        alog(f"\n{'━' * 60}", "STATS", "INFO")
        alog(f"Iteration: {self.stats.total_execs}", "STATS", "INFO")
        alog(f"{'━' * 60}", "STATS", "INFO")
        alog(f"Exec speed:  {self.stats.execs_per_sec:.1f} exec/s", "STATS", "INFO")

        # ✅ Compatible with SeedManagerAdapter and TraceManager
        if hasattr(self.trace_manager, 'trace_pool'):
            trace_count = len(self.trace_manager.trace_pool)
        elif hasattr(self.trace_manager, 'trace_to_seed_map'):
            trace_count = len(self.trace_manager.trace_to_seed_map)
        else:
            trace_count = 0
        alog(f"Trace pool:  {trace_count} traces", "STATS", "INFO")
        alog(f"Coverage:    {cov_stats['total_edges']} edges", "STATS", "INFO")
        alog(f"Paths found: {self.stats.paths_found}", "STATS", "INFO")
        alog(f"Crashes:     {self.stats.crashes_found} "
              f"({len(self.crash_detector.crashes)} unique)", "STATS", "INFO")
        
        time_since_last = time.time() - self.stats.last_new_path
        alog(f"Last path:   {time_since_last:.1f}s ago", "STATS", "INFO")
        alog(f"{'━' * 60}", "STATS", "INFO")
    
    def _triage_crash_online(self, trace, mutations: list, result, crash_id: str = '') -> str:
        """
        Immediately re-run the crash with two mutation subsets to determine exploitability.

        Variants:
          net_only  — only mutations on network socket fds (attacker-controlled data)
          file_only — only mutations on file fds (not attacker-controlled)

        Verdict:
          NETWORK-EXPLOITABLE  — net_only crashes → real vulnerability
          FILE-FD-ONLY         — file_only crashes → config/NVRAM dependency, not remote
          COMBINED-STATE       — only all_muts crashes → fuzzer artifact, false positive
          NOT-REPRODUCED       — nothing crashes (flaky or state-sensitive)

        The verdict is appended to the crash JSON so verify_crashes.py need not be
        re-run later.
        """
        if not mutations:
            return 'UNKNOWN'

        # Online triage blocks the main fuzzing loop and causes watchdog stalls (46s timeout).
        # Crash is already saved to disk; use batch_triage.py for offline analysis instead.
        return 'DEFERRED-OFFLINE'

    def _perform_cfg_analysis(self, trace: Trace, has_new_coverage: bool, trigger_reason: str, iteration_id: int):
        """Performs unified CFG/PathFinder analysis"""
        if not self.path_finder:
            return

        # 1. Iteration interval check
        interval = self.cfg_analysis_interval_iters
        elapsed = self.stats.total_execs - self.last_cfg_analysis_iter
        
        # 2. Time interval check
        elapsed_since_cfg = time.time() - self.last_cfg_analysis_time
        
        should_run_cfg = False
        if elapsed >= interval:
            should_run_cfg = True
        
        # Force run on new coverage (with a minimum safety interval to avoid thrashing)
        if has_new_coverage:
            if elapsed_since_cfg >= self.min_cfg_analysis_interval:
                should_run_cfg = True
            elif self.stats.total_execs < 10: # Allow frequent runs at the very beginning
                should_run_cfg = True

        # Check explicit time interval (e.g. 60s)
        if elapsed_since_cfg >= self.cfg_analysis_interval_time:
            should_run_cfg = True

        # 🔥 P1 Fix: Force runs on first iteration to ensure PathFinder is ready
        if self.stats.total_execs == 0:
            should_run_cfg = True

        if not should_run_cfg:
            return

        alog(f"[FuzzingCore] 🧭 Running CFG Analysis (Trigger: {trigger_reason})", "CORE")
        self.last_cfg_analysis_iter = self.stats.total_execs
        self.last_cfg_analysis_time = time.time()

        try:
            # Load syscall tree mapping (Auto-detect from HTML bundle)
            # Request a fresh tree dump from the live fork server parent before searching.
            # This is the only way to get an up-to-date tree during a long fuzzing session
            # (the C-side only exports at process exit otherwise).
            if hasattr(self, 'execution_engine') and self.execution_engine._qemu_ready:
                fresh_path = self.execution_engine.request_tree_export()
                if fresh_path:
                    alog(f"[FuzzingCore] Requested live tree export → {fresh_path}", "CORE")

            # Search order: 1. Per-process live export (freshest), 2. Output Dir, 3. /tmp legacy
            search_paths = [
                "/tmp/syscall_tree_*.json",   # per-process live exports from 'T' command
                os.path.join(self.output_dir, "latest_syscall_tree.html"),
                "/tmp/syscall_tree_*.html",
                "/tmp/syscall_tree.json"
            ]
            
            tree_file = None
            for pattern in search_paths:
                files = glob.glob(pattern) if '*' in pattern else ([pattern] if os.path.exists(pattern) else [])
                if files:
                    tree_file = max(files, key=os.path.getctime)
                    break
            
            if tree_file:
                tree_loaded = self.path_finder.load_syscall_tree(tree_file)
                if tree_loaded:
                    alog(f"[FuzzingCore] Loaded precise syscall tree mapping from {tree_file}", "CORE")
                    
                    # ✅ P3 Fix 2: If new coverage was found in the current round, directly mark nodes as covered based on the tree
                    # This eliminates reliance on inaccurate bitmap->PC mapping
                    if has_new_coverage:
                        marked = self.path_finder.mark_nodes_covered(tree_file)
                        if marked:
                            alog(f"[FuzzingCore] 🎯 PathFinder marked {marked} new nodes as covered based on tree", "CORE")
                else:
                    alog(f"[FuzzingCore] ⚠️ Failed to load syscall tree from {tree_file}", "WARN")
            else:
                alog(f"[FuzzingCore] ⚠️ Syscall tree file not found in search paths", "WARN")
            
            # Ensure CFG is ready
            if not self.path_finder.ensure_cfg_ready():
                alog(f"[FuzzingCore] Building PathFinder CFG from {trace.file_path}...", "CORE")
                analyzer = self._get_analyzer(trace.file_path)
                build_ok = self.path_finder.build_from_trace(trace.file_path, analyzer=analyzer)
            else:
                build_ok = True

            if build_ok:
                # Get covered blocks
                covered_blocks = self._extract_covered_blocks()
                if covered_blocks:
                    # Enhance with trace file
                    # ✅ Optimization: Prioritize searching for the most recently generated temporary trace file
                    # If the latest tree_file is found, its corresponding .bin and .bbl files are usually nearby
                    current_bb_trace = None
                    if tree_file and "syscall_tree_" in tree_file:
                        # Attempt to infer trace path from tree_file path
                        # E.g., /tmp/syscall_tree_123_4.html -> /tmp/trace_123_4.bin.bbl
                        base = tree_file.replace("syscall_tree_", "trace_").replace(".html", "")
                        potential_bbl = base + ".bin.bbl"
                        if os.path.exists(potential_bbl):
                            current_bb_trace = potential_bbl
                    
                    # Fallback to seed trace
                    if not current_bb_trace:
                        current_bb_trace = trace.file_path + ".bbl"
                    
                    if os.path.exists(current_bb_trace):
                        mapped = self.path_finder.enhance_from_trace_files(
                            syscall_trace_file="", # Unused
                            bb_trace_file=current_bb_trace,
                            covered_set=covered_blocks
                        )
                        if mapped:
                            alog(f"[FuzzingCore] 🔗 PathFinder enhanced {mapped} CFG nodes via {os.path.basename(current_bb_trace)}", "CORE")
                    
                    # Find uncovered branches
                    uncovered = self.path_finder.find_uncovered_branches(covered_blocks)
                    alog(f"[PathFinder] Debug: Found {len(uncovered)} uncovered branches", "DEBUG")
                    if uncovered:
                        new_recipes = self.path_finder.generate_recipes(uncovered, max_recipes=20)
                        alog(f"[FuzzingCore] PathFinder produced {len(new_recipes) if new_recipes else 0} recipes", "DEBUG")
                        if new_recipes:
                            if self.recipe_pool:
                                self.recipe_pool.add_recipes(new_recipes)
                                alog(f"[FuzzingCore] Added {len(new_recipes)} recipes to pool", "CORE")
                            
                            if isinstance(self.mutator, SmartMutator):
                                self.mutator.recipes.extend(new_recipes)
                                alog(f"[FuzzingCore] ✅ Injected {len(new_recipes)} recipes into SmartMutator", "CORE")
                    else:
                        # Fallback: Exploration Mode (Task #710)
                        # If graph is fully covered (no logical uncovered branches), force mutate covered syscalls
                        alog(f"[FuzzingCore] ⚠️ No uncovered branches (Graph saturated). activating Exploration Mode.", "CORE")
                        
                        # Generate "Self-Loop" targets for all covered syscalls to force state headers
                        exploration_targets = []
                        for idx, block in self.path_finder.syscall_blocks.items():
                            if block.is_covered:
                                # Create a dummy 'uncovered' entry that points to itself/generic
                                exploration_targets.append({
                                    'from_syscall_idx': idx,
                                    'to_syscall_idx': idx, # Self
                                    'from_syscall_name': block.syscall_name,
                                    'to_syscall_name': block.syscall_name,
                                    'type': 'exploration',
                                    'target_syscall_idx': idx,
                                    'has_syscall': True
                                })
                        
                        # ✅ Store in PathFinder for Fork Point Selection
                        self.path_finder.exploration_targets = exploration_targets

                        if exploration_targets:
                            # Pick random subset to avoid overwhelming
                            subset = random.sample(exploration_targets, min(len(exploration_targets), 10))
                            ex_recipes = self.path_finder.generate_recipes(subset, max_recipes=10)
                            if ex_recipes:
                                if isinstance(self.mutator, SmartMutator):
                                    self.mutator.recipes.extend(ex_recipes)
                                    alog(f"[FuzzingCore] 🚀 Injected {len(ex_recipes)} EXPLORATION recipes", "CORE")
        except Exception as e:
            alog(f"[FuzzingCore] ⚠️ PathFinder Analysis failed: {e}", "ERROR")

    def run_single_iteration(self, iteration_id: int = 0) -> IterationResult:
        """Runs a single fuzzing iteration"""
        # ✅ P2: Periodic Seed Import (Seed Loopback)
        if self.sync_dir and (self.stats.total_execs - self.last_seed_sync_iter >= self.seed_sync_interval):
            self.import_external_seeds()
            self.last_seed_sync_iter = self.stats.total_execs

        # ✅ Task #7: Record iteration start
        self.metrics.success_counts['total_iterations'] += 1
        self.total_iterations += 1

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 1: Trace Selection
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        trace = self.trace_manager.select_trace()
        if not trace:
            # ✅ Task #7: Record failure
            self.metrics.record_failure(
                reason=FailureReason.CONFIG_INVALID_TRACE,
                component="TraceManager",
                details="No available traces in pool",
                iteration=iteration_id
            )
            alog("⚠️  No available traces in pool", "CORE", "WARN")
            # ✅ Task #8: Return failure result
            return create_failure_result(
                iteration_id=iteration_id,
                status=IterationStatus.NO_TRACE,
                error_message="No available traces in pool",
                error_component="TraceManager"
            )
        
        # ✅ FIX: Update SmartMutator if the trace file has changed
        # This ensures that mutations are targeted based on the correct syscall sequence
        if isinstance(self.mutator, SmartMutator):
            current_mutator_trace = getattr(self.mutator, 'trace_file', None)
            if current_mutator_trace != trace.file_path:
                # alog(f"🔄 Updating Mutator for new trace: {trace.id} ({trace.file_path})", "CORE", "DEBUG")
                # Creating a new SmartMutator is efficient because it uses shared analyzer
                if hasattr(self.mutator, 'clear'):
                    self.mutator.clear()
                    
                analyzer = self._get_analyzer(trace.file_path)
                self.mutator = SmartMutator(
                    trace_file=trace.file_path,
                    target_binary=self.target_binary,
                    path_finder=self.path_finder,
                    analyzer=analyzer,
                    auth_boundary=self.auth_boundary  # ✅ FIX: preserve auth_boundary across trace switches
                )
                if self.dynamic_fork_controller:
                    self.dynamic_fork_controller.analyzer = analyzer
                    self.dynamic_fork_controller.mutator = self.mutator  # ✅ FIX: keep DFC mutator in sync
        # Step 2: Depth-First Exploration - Intelligent Fork Point Selection (Dynamic Fork Integration)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        
        # Dynamic Fork Integration: Delegate to controller if available
        if self.dynamic_fork_controller:
            # Multi-path exploration handles mutation, execution, and coverage analysis
            success = self.dynamic_fork_controller.explore_multi_path(trace, iteration_id)
            
            # Update total executions count in core as well
            if hasattr(self.dynamic_fork_controller, 'last_batch_execs'):
                batch_size = self.dynamic_fork_controller.last_batch_execs
                self.total_executions += batch_size
                
                # ✅ Synchronize execution count with TracePool (for current base trace)
                pool_trace = self.trace_pool.get_trace_by_id(trace.id)
                if pool_trace:
                    old_count = pool_trace.metadata.exec_count
                    pool_trace.metadata.exec_count += batch_size
                    alog(f"Sync trace {trace.id}: {old_count} -> {pool_trace.metadata.exec_count} (batch={batch_size})", "CORE", "DEBUG")
                    # Sync manifest for realtime observability
                    self.trace_pool.save_manifest()
                else:
                    alog(f"⚠️ Trace {trace.id} NOT FOUND in pool for sync!", "CORE", "WARN")
            
            if success:
                self.metrics.record_success('dynamic_fork_batch')
                # Unified CFG Analysis
                self._perform_cfg_analysis(trace, success, f"DynamicFork: {'NewCov' if success else 'Interval'}", iteration_id)
            
            # ✅ FIX: Display progress even in dynamic fork mode
            self._display_progress()
            
            return create_success_result(
                iteration_id=iteration_id,
                status=IterationStatus.SUCCESS,
                new_coverage=success
            )
            # crashes_found=0 # Crashes are handled by DynamicForkController via CrashDetector

        batch_size = int(os.environ.get('RR_BATCH_SIZE', 5))  # 🔥 Configurable batch_size

        # 🔥 Fix: Coverage-driven fork point selection
        fork_points = self._select_coverage_driven_fork_points(trace, batch_size)

        # Iteration result tracking
        has_any_success = False
        total_execs = 0
        total_mutations = 0
        new_coverage_found = False
        has_new_coverage = False  
        new_paths_found = 0
        crashes_found_count = 0
        result = None

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 3: Batch Execution - Group mutations by fork point
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        from collections import defaultdict
        fork_to_mutations = defaultdict(list)
        
        # Perform multiple mutations per fork point for efficiency (batching reduces QEMU restarts)
        mutations_per_fork = int(os.environ.get('RR_MUTATIONS_PER_FORK', 4))
        
        analyzer = self._get_analyzer(trace.file_path)
        for fork_point in fork_points:
            for _ in range(mutations_per_fork):
                m = self.mutator.mutate(trace, fork_point=fork_point, analyzer=analyzer)
                
                # 🔥 OPTION A: VALIDATOR HOOK (Dual-Level Mapping)
                # Intercepts and drops mutations that violate the Static CFG
                if m and self.enable_pathfinder and self.path_finder and hasattr(self.mutator, 'last_recipe_used'):
                    recipe = getattr(self.mutator, 'last_recipe_used', None)
                    # Only validate if the recipe explicitly targets a control flow transition (has known source/target)
                    if recipe and hasattr(recipe, 'source_branch') and hasattr(recipe, 'target_branch'):
                         # Validator Check (Phase A: Relax & Rank)
                         validation_score = self.path_finder.validate_transition(recipe.source_branch, recipe.target_branch)
                         
                         from .constants import VALIDATION_SCORE_INVALID, VALIDATION_SCORE_UNKNOWN
                         
                         if validation_score == VALIDATION_SCORE_INVALID:
                             # Absolute resource failure (Phase B) - Block it
                             alog(f"🛑 Validator BLOCKED invalid resource: {recipe.source_branch} -> {recipe.target_branch}", "CORE", "DEBUG")
                             continue
                         
                         elif validation_score == VALIDATION_SCORE_UNKNOWN:
                             # Unknown path (Exploration) - Allow but give lower priority/energy
                             # We can handle energy adjustment here or later in the executor
                             recipe.priority = max(1, recipe.priority // 2)
                             alog(f"🔍 Validator DETECTED unknown path (Exploring): {recipe.source_branch} -> {recipe.target_branch}", "CORE", "DEBUG")
                         
                         # If it's VALIDATION_SCORE_KNOWN (10), we proceed normally with high priority

                if m:
                    fork_to_mutations[fork_point].append(m)
        
        for fork_point, mutations_list in fork_to_mutations.items():
            if not mutations_list:
                continue
                
            total_mutations += len(mutations_list)
            
            # Record mutations in graph
            node_ids = []
            for i, muts in enumerate(mutations_list):
                 node_id = self.mutation_graph.add_mutation(
                    iteration=iteration_id,
                    mutation_index=i,
                    mutation_type='batch',
                    parent_trace_id=trace.id,
                )
                 node_ids.append(node_id)

            # Execute batch at this fork point
            results = self.execution_engine.execute_fork(trace.file_path, fork_point, mutations_list, 0, iteration_id)

            # ✅ Record successful fork operations (fix statistics bug)
            if results and len(results) > 0:
                self.metrics.success_counts['successful_forks'] += 1

            # Process results
            for result_idx, result in enumerate(results):
                if result is None:
                    continue

                # ✅ FIX: Map result back to its corresponding mutation
                mutations = mutations_list[result_idx] if result_idx < len(mutations_list) else []
                node_id = node_ids[result_idx] if result_idx < len(node_ids) else None

                self.stats.total_execs += 1
                self.stats.session_execs += 1
                # ✅ Synchronize execution count with TracePool
                pool_trace = self.trace_pool.get_trace_by_id(trace.id)
                if pool_trace:
                    pool_trace.metadata.exec_count += 1
                else:
                    trace.metadata.exec_count += 1  # Fallback
                total_execs += 1
                has_any_success = True

                # ✅ Task #7: Record successful mutation execution
                self.metrics.record_success('successful_mutations')

                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                # Step 4: Coverage Analysis
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                if result.coverage_bitmap:
                    new_cov_count = self.coverage_tracker.has_new_coverage(
                        result.coverage_bitmap
                    )

                    if new_cov_count > 0:
                        has_new_coverage = True
                        new_coverage_found = True
                        new_paths_found += 1
                        self.stats.paths_found += 1
                        self.stats.last_new_path = time.time()
                        alog(f"🎯 New coverage found! (Total edges: {self.coverage_tracker.get_stats()['total_edges']})", "CORE", "INFO")
                        
                        # ✅ Sync manifest for realtime observability
                        if self.trace_pool:
                            self.trace_pool.save_manifest()
                        
                        # ✅ Layer 5.5: Check for security sink hits
                        # We use the PathFinder's bb mapping if available to translate bitmap to sinks
                        if self.path_finder and hasattr(self.path_finder, 'get_hit_bbs'):
                             hit_bbs = self.path_finder.get_hit_bbs(result.coverage_bitmap)
                             sinks = self.security_watchdog.check_execution(hit_bbs)
                             if sinks:
                                 alog(f"🕵️ Security Watchdog: Sinks hit in new path: {sinks}", "CORE", "WARN")
                        
                        # ✅ Layer 6: Evaluate this specific mutation for evolution potential
                        if mutations:
                            # 注入进化引擎所需的元数据
                            result.new_coverage = new_cov_count
                            result.trace_id = trace.id
                            self.evolution_engine.evaluate_iteration(result, mutations)

                # Step 4.5: Record execution statistics
                analyzer = self._get_analyzer(trace.file_path)
                self.trace_manager.record_execution(
                    trace_id=trace.id,
                    trace_file=trace.file_path,
                    mutations=mutations,
                    has_new_coverage=has_new_coverage,
                    analyzer=analyzer
                )

                # Update stagnation detection status
                # 🔥 Fix: Use total_execs as global iteration counter (different from trace.exec_count)
                if isinstance(self.mutator, SmartMutator) and hasattr(self.mutator, 'update_stagnation_status'):
                    self.mutator.update_stagnation_status(
                        iteration=self.stats.total_execs,
                        has_new_coverage=has_new_coverage
                    )

                # Execution result notification
                coverage_stats = self.coverage_tracker.get_stats()
                self.mutation_graph.update_mutation_result(
                    node_id=node_id,
                    has_new_coverage=has_new_coverage,
                    new_edges=coverage_stats.get('new_edges_this_run', 0),
                    total_edges=coverage_stats.get('total_edges', 0),
                    crashed=getattr(result, 'crashed', False),
                    timed_out=getattr(result, 'timed_out', False),
                    exec_time=getattr(result, 'exec_time', 0.0)
                )
                
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                # Step 6: Crash Detection and Saving
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                if result.crashed:
                    saved_id = self.crash_detector.save_crash(result, trace, mutations)
                    if saved_id:
                        self.stats.crashes_found += 1
                        crashes_found_count += 1
                        print(f"[FuzzingCore] 💥 NEW UNIQUE CRASH FOUND! exit_code={result.qemu_exit_code}, signal={result.signal_number}")
                        self._triage_crash_online(trace, mutations, result, crash_id=saved_id)
                    else:
                        print(f"[FuzzingCore] 💥 Duplicate crash ignored (Stats consistency)")

                    if self.layer5_crash_analyzer:
                        qemu_status = {
                            'signal': result.signal_number,
                            'exit_code': result.qemu_exit_code,
                            'pc': getattr(result, 'pc', 0),
                            'fault_address': getattr(result, 'fault_address', None),
                            'backtrace': getattr(result, 'backtrace', [])
                        }
                        m_inst = mutations
                        if isinstance(m_inst, list) and len(m_inst) > 0:
                            sc_idx = getattr(m_inst[0], 'syscall_index', -1)
                            m_str_list = [str(m) for m in m_inst]
                        else:
                            sc_idx = getattr(m_inst, 'syscall_index', -1) if m_inst else -1
                            m_str_list = [str(m_inst)] if m_inst else []
                        mutation_recipe = {'syscall_index': sc_idx, 'mutations': m_str_list}
                        try:
                            crash_info = self.layer5_crash_analyzer.analyze_crash(
                                qemu_status=qemu_status,
                                mutation_recipe=mutation_recipe,
                                iteration=self.stats.total_execs
                            )
                            self.layer5_crash_analyzer.save_crash(crash_info)
                            if self.trace_pool:
                                self.trace_pool.save_manifest()
                        except Exception as e:
                            alog(f"⚠️ Layer5 Analysis failed (Core): {e}", "CORE", "ERROR")

                if result.timeout:
                    self.stats.timeouts += 1

        # ═════════════════════════════════════════════════════════════════
        # CFG-guided Fuzzing
        # ═════════════════════════════════════════════════════════════════
        if self.path_finder:
            should_run_cfg = False

            trigger_reason = None

            # 🔥 Debug: Print current status
            if self.stats.total_execs % 10 == 0:  # Print every 10 iterations
                alog(f"[FuzzingCore] 🔍 CFG Check: exec={self.stats.total_execs}, last={self.last_cfg_analysis_iter}, interval={self.cfg_analysis_interval_iters}", "DEBUG")

            # Condition 1: Iteration threshold reached
            interval = self.cfg_analysis_interval_iters
            elapsed = self.stats.total_execs - self.last_cfg_analysis_iter
            
            # 🔥 Debug: Log CFG status
            alog(f"[PathFinder] Status Check: elapsed={elapsed}, interval={interval}, has_new_cov={has_new_coverage}", "DEBUG")

            if elapsed >= interval:
                should_run_cfg = True
                trigger_reason = f"{elapsed} iterations"
            
            # 🔥 Force run on new coverage for verification
            if has_new_coverage:
                 should_run_cfg = True
                 trigger_reason = "New Coverage Found"

            # Condition 2: Time threshold reached
            elapsed_since_cfg = time.time() - self.last_cfg_analysis_time
            if elapsed_since_cfg >= self.cfg_analysis_interval_time:
                should_run_cfg = True
                trigger_reason = f"{elapsed_since_cfg:.0f} seconds"
            
            # Unified CFG Analysis (Regular Path)
            if should_run_cfg:
                self._perform_cfg_analysis(trace, has_new_coverage, trigger_reason, iteration_id)
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 5: Trace Saving (if interesting)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if has_new_coverage:
            # Currently reusing the same trace file (Stage 1 simplification)
            # Stage 2 will implement re-recording traces with mutations
            coverage_stats = self.coverage_tracker.get_stats()
            new_edges = coverage_stats.get('new_edges', set())

            coverage_info = {
                'has_new_edges': True,
                'new_edge_count': len(new_edges) if new_edges else 1,
                'total_unique_edges': coverage_stats['total_edges'],
                'edges': new_edges if new_edges else set()
            }

            self.trace_manager.add_trace(
                trace_file=trace.file_path,
                coverage_info=coverage_info,
                parent_id=trace.id,
                mutations=[
                    {
                        'syscall_index': m.syscall_index,
                        'cmd': m.cmd,
                        'arg_index': m.arg_index,
                        'data': m.data.hex() if isinstance(m.data, bytes) else m.data,
                        'offset': m.offset,
                        'size': m.size,
                        'mutation_type': getattr(m, 'mutation_type', 'unknown')
                    }
                    for m in mutations
                ]
            )

            # Update context for scheduling
            if hasattr(self.trace_manager, 'update_context'):
                self.trace_manager.update_context(
                    new_coverage=new_edges if new_edges else set(),
                    no_progress=False
                )
        else:
            if hasattr(self.trace_manager, 'update_context'):
                self.trace_manager.update_context(
                    new_coverage=set(),
                    no_progress=True
                )

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 5.5: Recipe Feedback (if recipe mode)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if self.recipe_pool and hasattr(self.mutator, 'last_recipe_used'):
            recipe_used = getattr(self.mutator, 'last_recipe_used', None)
            
            if recipe_used and result:
                # Check if recipe was successful
                if has_new_coverage:
                    # TODO: Check if the target branch was actually covered
                    # For now, any new coverage is considered partial success
                    self.recipe_pool.update_recipe_result(
                        recipe_used,
                        success=True,
                        new_coverage=1
                    )
                    
                    # Get recipe statistics
                    recipe_id = recipe_used.get('id', -1)
                    if recipe_id in self.recipe_pool.stats:
                        stats = self.recipe_pool.stats[recipe_id]
                        print(f"[FuzzingCore] ✅ Recipe {recipe_id} successful! "
                              f"(Success rate: {stats.success_rate*100:.1f}%)")
                else:
                    # Recipe failed to generate new coverage
                    self.recipe_pool.update_recipe_result(
                        recipe_used,
                        success=False,
                        new_coverage=0
                    )
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 5.6: Strategy Feedback (UCB1)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if hasattr(self.mutator, 'record_strategy_result') and hasattr(self.mutator, 'last_strategy_type'):
            strat = self.mutator.last_strategy_type
            if strat >= 0:
                coverage_stats = self.coverage_tracker.get_stats()
                new_edge_count = len(coverage_stats.get('new_edges', set())) if has_new_coverage else 0
                self.mutator.record_strategy_result(
                    strategy_type=strat,
                    new_edges=new_edge_count,
                    crashed=crashes_found_count > 0,
                )

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 7: Statistics Update and Display
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        self._display_progress()

        # ✅ Task #7: Record successful iteration
        self.metrics.record_success('successful_iterations')

        # ✅ Task #8: Return IterationResult
        if not has_any_success:
            # Complete failure: no successful executions
            return create_failure_result(
                iteration_id=iteration_id,
                status=IterationStatus.NO_MUTATIONS,
                error_message="No successful executions",
                error_component="Executor",
                trace_id=trace.id
            )
        else:
            # Success: at least one successful execution
            return create_success_result(
                iteration_id=iteration_id,
                new_coverage=new_coverage_found,
                new_paths=new_paths_found,
                crashes_found=crashes_found_count,
                execs_performed=total_execs,
                mutations_applied=total_mutations,
                trace_id=trace.id
            )
    
    def _start_realtime_visualizer(self):
        """
        Configures C-Side Syscall Tree Export
        (No longer starts Python Visualizer, instead QEMU C backend directly exports JSON)
        """
        try:
            # Set output path
            if self.enable_pathfinder:
                tree_output_path = Path(self.output_dir) / "latest_syscall_tree.html"
                os.environ["RR_TREE_OUTPUT"] = str(tree_output_path.absolute())
                alog(f"[FuzzingCore] 🌲 PathFinder Syscall Tree Configured: output={tree_output_path}", "CORE")

            if self.enable_tree_viz:
                if "RR_TRACE_PIPE" in os.environ:
                    del os.environ["RR_TRACE_PIPE"]
                alog(f"[FuzzingCore] 🎨 Visualizer enabled", "CORE")
            
        except Exception as e:
            alog(f"❌ Failed to configure syscall tree: {e}", "CORE", "ERROR")

    def _get_coverage_percentage(self):
        """Gets current coverage percentage"""
        try:
            stats = self.coverage_tracker.get_stats()
            return stats.get('bitmap_density', 0.0)
        except Exception:
            return 0.0

    def _init_re_recorder(self, output_dir: str):
        """Initializes the re-recording executor for evolution"""
        try:
            # We try to find a profile in the output directory or common locations
            # If the user started via fuzz_master, it should be in the config path
            # For verification, we often have the profile available.
            profile_path = Path(self.output_dir) / "profile.json"
            if not profile_path.exists():
                # Fallback to RAX30 default for this target
                profile_path = Path("fuzzing/config/targets/rax30.json")

            if profile_path.exists():
                self.target_profile = TargetProfile.from_json(str(profile_path))
                
                # Initialize SecurityWatchdog with static info
                static_json = Path(self.output_dir) / "static_cfg.json"
                if static_json.exists():
                    try:
                        with open(static_json, 'r') as f:
                            self.security_watchdog = SecurityWatchdog(static_cfg=json.load(f))
                    except: pass

                self.re_recorder = ReRecordingExecutor(
                    profile=self.target_profile,
                    qemu_path=self.qemu_path,
                    output_dir=str(self.output_dir)
                )
                alog(f"🧬 [Evolution] Re-recording engine initialized (Target: {self.target_profile.name})", "CORE")
            else:
                self.re_recorder = None
                alog("⚠️ [Evolution] No target profile found, re-recording disabled", "CORE", "WARN")
        except Exception as e:
            alog(f"❌ [Evolution] Failed to init re-recorder: {e}", "CORE", "ERROR")
            self.re_recorder = None

    def _perform_evolution_step(self):
        """Attempts to promote high-potential candidates to new base traces"""
        if not self.re_recorder:
            return

        candidate = self.evolution_engine.get_best_candidate()
        if not candidate:
            return

        alog(f"🧬 [Evolution] Found high-potential candidate! New Coverage: {candidate.new_coverage}, Score: {candidate.score:.2f}", "CORE")
        
        # Unique name for new trace
        output_name = f"evolved_{int(time.time())}_{candidate.trace_id}"
        trace_path = self.re_recorder.promote_candidate(candidate, output_name)
        
        if trace_path:
            # 1. Add to trace manager
            new_trace = self.trace_manager.add_trace(
                trace_file=trace_path,
                coverage_info={'has_new_edges': True, 'new_edge_count': candidate.new_coverage},
                parent_id=candidate.trace_id
            )
            # 2. Add to trace pool
            if new_trace:
                self.trace_pool.add_trace(new_trace, category='EVOLVED')
            
            # 3. Mark as processed
            self.evolution_engine.mark_promoted(candidate)
            alog(f"✨ [Evolution] Successfully promoted mutation to NEW BASE TRACE: {output_name}", "CORE", "INFO")
        else:
            alog(f"❌ [Evolution] Failed to promote candidate {candidate.trace_id}", "CORE", "WARN")
            # Mark it so we don't keep failing on the same one
            self.evolution_engine.mark_promoted(candidate)

    def import_external_seeds(self):
        """Scan sync_dir/queue for new seeds from other workers (Layer 4)"""
        if not self.sync_dir:
            return

        queue_dir = self.sync_dir / "queue"
        if not queue_dir.exists():
            return

        new_seeds_count = 0
        # Scan for all .bin files in sync queue
        try:
            for bin_file in queue_dir.glob("*.bin"):
                # Skip own seeds (already in pool)
                # FuzzMaster names seeds as {trace_id}_w{worker_id}.bin
                if f"_w{self.worker_id}.bin" in bin_file.name:
                    continue
                
                # Check if already imported
                if bin_file.name in self.imported_seeds:
                    continue

                # Import seed
                try:
                    # Add to trace manager
                    local_path = self.output_dir / "seeds_imported" / bin_file.name
                    local_path.parent.mkdir(exist_ok=True)
                    
                    if not local_path.exists():
                        import shutil
                        shutil.copy(bin_file, local_path)
                        # Also copy .bbl
                        bbl_file = bin_file.with_suffix(bin_file.suffix + ".bbl")
                        if bbl_file.exists():
                            shutil.copy(bbl_file, local_path.with_suffix(local_path.suffix + ".bbl"))

                    # Add to trace manager
                    # P7: Coverage info might be unknown, but we mark it as interesting to encourage exploration
                    self.trace_manager.add_trace(
                        trace_file=str(local_path),
                        coverage_info={'has_new_edges': True, 'new_edge_count': 1}, 
                        parent_id=f"worker_external_{bin_file.name}"
                    )
                    
                    self.imported_seeds.add(bin_file.name)
                    new_seeds_count += 1
                except Exception as e:
                    alog(f"Failed to import seed {bin_file.name}: {e}", "CORE", "WARN")

            if new_seeds_count > 0:
                alog(f"📥 Imported {new_seeds_count} external seeds from other workers", "CORE", "INFO")
        except Exception as e:
            alog(f"Error during seed import scan: {e}", "CORE", "ERROR")

    def run_advanced(self, stop_conditions: dict):
        """
        Runs the main fuzzing loop (advanced stop conditions version)

        Parameters:
            stop_conditions: Dictionary of stop conditions, including:
                - max_iterations: Maximum number of iterations
                - max_time: Maximum time (seconds)
                - max_crashes: Maximum number of crashes
                - max_paths: Maximum number of new paths
                - coverage_target: Coverage target (%)
                - no_progress_timeout: No progress timeout (seconds)
                - infinite: Whether to run indefinitely
        """
        # Compatible with old interface
        max_iterations = stop_conditions.get('max_iterations')
        max_time = stop_conditions.get('max_time')

        # New advanced stop conditions
        max_crashes = stop_conditions.get('max_crashes')
        max_paths = stop_conditions.get('max_paths')
        coverage_target = stop_conditions.get('coverage_target')
        no_progress_timeout = stop_conditions.get('no_progress_timeout')
        infinite_mode = stop_conditions.get('infinite', False)

        return self._run_with_conditions(
            max_iterations, max_time, max_crashes, max_paths,
            coverage_target, no_progress_timeout, infinite_mode
        )

    def run(self, max_iterations: Optional[int] = None, max_time: Optional[float] = None):
        """
        Runs the main fuzzing loop (backward compatible version)

        Parameters:
            max_iterations: Maximum number of iterations (None for unlimited)
            max_time: Maximum time (seconds) (None for unlimited)
        """
        return self._run_with_conditions(max_iterations, max_time)

    def _run_with_conditions(self, max_iterations=None, max_time=None, max_crashes=None,
                           max_paths=None, coverage_target=None, no_progress_timeout=None,
                           infinite_mode=False):
        """
        Execute actual fuzzing loop, supporting various stop conditions
        """
        # ✅ Check and Start Watchdog
        if self.watchdog and not self.watchdog.running:
             self.watchdog.start()

        # Display startup info
        alog(f"\n{'=' * 60}", "CORE", "INFO")
        alog(f"Starting fuzzing campaign", "CORE", "INFO")
        if infinite_mode:
            alog(f"  Mode: Infinite Run (until Ctrl+C)", "CORE", "INFO")
        else:
            if max_iterations:
                alog(f"  Max Iterations: {max_iterations}", "CORE", "INFO")
            if max_time:
                alog(f"  Max Time: {max_time}s", "CORE", "INFO")
            if max_crashes:
                alog(f"  Max Crashes: {max_crashes}", "CORE", "INFO")
            if max_paths:
                alog(f"  Max New Paths: {max_paths}", "CORE", "INFO")
            if coverage_target:
                alog(f"  Coverage Target: {coverage_target}%", "CORE", "INFO")
            if no_progress_timeout:
                alog(f"  No Progress Timeout: {no_progress_timeout}s", "CORE", "INFO")
        alog(f"{'=' * 60}\n", "CORE", "INFO")

        # Initialize variables
        iteration = self.total_iterations
        start_time = self.start_time
        last_progress_time = time.time()
        initial_paths = self.stats.paths_found
        initial_coverage = self._get_coverage_percentage()

        try:
            while True:
                # 🐶 Watchdog Kick
                if self.watchdog:
                     self.watchdog.kick()

                current_time = time.time()
                
                # 💾 Periodic Checkpoint Save
                if self.checkpoint_manager:
                    if current_time - self.last_checkpoint_time >= self.checkpoint_interval:
                        self.checkpoint_manager.save(self)
                        self.last_checkpoint_time = current_time

                # 🔥 Advanced stop condition check
                if not infinite_mode:
                    # Basic conditions
                    if max_iterations and iteration >= max_iterations:
                        alog(f"✅ Maximum iterations reached ({max_iterations})", "CORE", "INFO")
                        break

                    if max_time and (current_time - start_time) >= max_time:
                        alog(f"⏰ Maximum time reached ({max_time}s)", "CORE", "INFO")
                        break

                    # New advanced stop conditions
                    if max_crashes and self.stats.crashes_found >= max_crashes:
                        alog(f"🎯 Found enough crashes ({self.stats.crashes_found}/{max_crashes})", "CORE", "INFO")
                        break

                    if max_paths and (self.stats.paths_found - initial_paths) >= max_paths:
                        alog(f"Tracked enough new paths ({self.stats.paths_found - initial_paths}/{max_paths})", "CORE", "INFO")
                        break

                    if coverage_target:
                        current_coverage = self._get_coverage_percentage()
                        if current_coverage >= coverage_target:
                            alog(f"📊 Coverage target reached ({current_coverage:.1f}%/{coverage_target}%)", "STATS", "INFO")
                            break

                    if no_progress_timeout:
                        # Check for new progress
                        if self.stats.paths_found > initial_paths:
                            last_progress_time = current_time
                            initial_paths = self.stats.paths_found
                        elif (current_time - last_progress_time) >= no_progress_timeout:
                            alog(f"📉 No progress for {no_progress_timeout}s, stopping...", "CORE", "WARN")
                            break
                
                # Unified iteration entry point (handles both normal and dynamic fork)
                result = self.run_single_iteration(iteration_id=iteration)
                
                # ✅ Task #2: Promotion - Periodically attempt promotion
                if iteration > 0 and iteration % 100 == 0:
                    self._perform_evolution_step()

                # 🧹 Periodic SHM cleanup — sweep leaked /dev/shm/rr_fuzz_* files
                if iteration > 0 and iteration % 10 == 0:
                    from .shared_memory import FuzzSharedMemory
                    FuzzSharedMemory.cleanup_orphaned_shm()

                # 🧹 Periodic orphan QEMU cleanup — kill any stray qemu child processes
                if iteration > 0 and iteration % 50 == 0:
                    self._cleanup_orphan_qemu()
                
                if result and result.is_failure():
                    alog(f"⚠️  Iteration {iteration} failed: {result}", "CORE", "WARN")
                
                iteration += 1
                self.total_iterations = iteration
        
        except BaseException as e:
            if isinstance(e, KeyboardInterrupt):
                alog(f"User interrupted", "CORE", "WARN")
            else:
                alog(f"🛑 Fuzzer terminated by exception: {type(e).__name__}: {e}", "CORE", "ERROR")
                raise
        
        finally:
            # 🛑 Stop Watchdog
            if self.watchdog:
                 self.watchdog.stop()
            
            # 💾 Final Checkpoint Save
            if self.checkpoint_manager:
                alog(f"💾 Saving final checkpoint...", "CORE", "INFO")
                self.checkpoint_manager.save(self)

            alog(f"⏳ Waiting for components to finalize...", "CORE", "INFO")
            time.sleep(5)
            
            # Final statistics
            self._display_final_statistics()
    
    def _display_final_statistics(self):
        """Display final fuzzing statistics"""
        cov_stats = self.coverage_tracker.get_stats()
        trace_stats = self.trace_manager.get_statistics()
        exec_stats = self.execution_engine.get_statistics()
        
        alog(f"✅ Fuzzing loop completed. Preparing final report...", "CORE", "INFO")
        
        # Save final results (corpus, stats, etc.)
        self.save_final_results()
    
    def save_final_results(self):
        """Save final results to disk."""
        output_path = Path(self.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        self._display_progress(force=True)
        alog(f"💾 Saving final results...", "CORE", "INFO")
        
        # Save corpus (Layer 2)
        self.trace_manager.save_corpus(self.output_dir)
        
        # Save final statistics
        stats_file = output_path / "final_stats.json"
        with open(stats_file, 'w') as f:
            # Use default=list to convert any remaining sets to lists
            json.dump({
                'execution': {
                    'total_execs': self.stats.total_execs,
                    'execs_per_sec': self.stats.execs_per_sec,
                    'elapsed_time': self.stats.elapsed_time,
                    'crashes_found': self.stats.crashes_found,
                    'paths_found': self.stats.paths_found,
                    'timeouts': self.stats.timeouts
                },
                'start_time': self.start_time,
                'coverage': self.coverage_tracker.get_stats(),
                'traces': self.trace_manager.get_statistics(),
                'executor': self.execution_engine.get_statistics(),
                'metrics': self.metrics.to_dict(),
                'mutation_graph': self.mutation_graph.to_dict()
            }, f, indent=2, default=lambda o: list(o) if isinstance(o, set) else str(o))

        alog(f"  ✅ Statistics saved to {stats_file}", "CORE", "INFO")

        # ✅ Task #7: Save FuzzingMetrics detailed report
        metrics_report_file = output_path / "metrics_report.txt"
        with open(metrics_report_file, 'w') as f:
            f.write(self.metrics.generate_report())
        alog(f"  ✅ Metrics report saved to {metrics_report_file}", "CORE", "INFO")

        # ✅ Task #6: Save MutationDependencyGraph detailed report
        mutation_report_file = output_path / "mutation_analysis.txt"
        with open(mutation_report_file, 'w') as f:
            f.write(self.mutation_graph.generate_report())
        alog(f"  ✅ Mutation analysis report saved to {mutation_report_file}", "CORE", "INFO")

        # ✅ Task #6: Export complete mutation graph structure (for in-depth analysis)
        if self.mutation_graph.nodes:
            mutation_graph_file = output_path / "mutation_graph.json"
            self.mutation_graph.export_to_json(mutation_graph_file)
            alog(f"  ✅ Mutation graph structure saved to {mutation_graph_file}", "CORE", "INFO")
        
        # ═══════════════════════════════════════════════════════════
        # Layer 5: Monitoring & Analysis (Important!)
        # ═══════════════════════════════════════════════════════════
        
        if self.enable_monitoring:
            
            # Gather stats for final display
            cov_stats = self.coverage_tracker.get_stats()
            trace_stats = self.trace_manager.get_statistics()
            exec_stats = self.execution_engine.get_statistics()
            
            alog("\n" + "═"*70, "SUMMARY", "INFO")
            alog(f"{'🏁 Fuzzing Campaign Summary':^70}", "SUMMARY", "INFO")
            alog("═"*70, "SUMMARY", "INFO")
            
            # Row 1: Execution & Coverage
            # ✅ Fix: Use authoritative source for exec count
            final_total_execs = self.stats.total_execs
            if final_total_execs == 0:
                final_total_execs = exec_stats.get('total_executions', 0)
                if final_total_execs == 0:
                    final_total_execs = self.total_executions
            
            final_speed = self.stats.execs_per_sec
            if final_speed == 0 and final_total_execs > 0 and self.stats.elapsed_time > 0:
                final_speed = final_total_execs / self.stats.elapsed_time
            
            # If aggregated stats exist (e.g. from DynamicForkController updation)
            if hasattr(self.stats, 'aggregated_total_execs') and self.stats.aggregated_total_execs > 0:
                 final_total_execs = self.stats.aggregated_total_execs
                 if self.stats.elapsed_time > 0:
                     final_speed = final_total_execs / self.stats.elapsed_time

            alog(f" │ {'📊 Execution Metrics':<32} │ {'🎯 Coverage Metrics':<32} │", "SUMMARY", "INFO")
            alog(f" │ {'─'*32} │ {'─'*32} │", "SUMMARY", "INFO")
            alog(f" │ Total Execs : {final_total_execs:<18} │ Total Edges : {cov_stats['total_edges']:<18} │", "SUMMARY", "INFO")
            alog(f" │ Speed       : {final_speed:>.1f} exec/s       │ New Paths   : {self.stats.paths_found:<18} │", "SUMMARY", "INFO")
            alog(f" │ Duration    : {self.stats.elapsed_time:>.1f}s            │ Density     : {cov_stats['bitmap_density']:>.2f}%            │", "SUMMARY", "INFO")
            alog(" " + "─"*70, "SUMMARY", "INFO")
            
            # Row 2: Corpus & Reliability
            alog(f" │ {'📦 Corpus Health':<32} │ {'💥 Reliability Metrics':<32} │", "SUMMARY", "INFO")
            alog(f" │ {'─'*32} │ {'─'*32} │", "SUMMARY", "INFO")
            alog(f" │ Total Traces: {trace_stats['total_traces']:<18} │ Total Crashes: {self.stats.crashes_found:<17} │", "SUMMARY", "INFO")
            alog(f" │ Active      : {trace_stats['active_traces']:<18} │ Unique       : {len(self.crash_detector.crashes):<17} │", "SUMMARY", "INFO")
            alog(f" │ Saved       : {trace_stats['traces_saved']:<18} │ Crash Rate   : {exec_stats['crash_rate']:>.2%}            │", "SUMMARY", "INFO")
            alog("═"*70 + "\n", "SUMMARY", "INFO")
            
            # 1. CorpusManager: Persistent corpus
            if self.layer5_corpus_manager:
                try:
                    # Note: corpus_manager requires seed_queue object, simplified here
                    alog(f"  ✅ [Corpus] Manager Active (Manual save required)", "CORE", "INFO")
                except Exception as e:
                    alog(f"  ❌ [Corpus] Save Failed: {e}", "CORE", "ERROR")
            
            # 2. CrashAnalyzer: Generate crash report
            if self.layer5_crash_analyzer:
                try:
                    alog(f"  📊 [Analysis] Generating crash report...", "CORE", "INFO")
                    alog("  " + "─"*50, "CORE", "INFO")
                    
                    # Hack: Capture sys.stdout to redirect print_summary to alog
                    import io
                    from contextlib import redirect_stdout
                    f = io.StringIO()
                    with redirect_stdout(f):
                        self.layer5_crash_analyzer.print_summary(top_n=20, verbose=True)
                    
                    for line in f.getvalue().splitlines():
                        alog(f"  {line}", "CORE", "INFO")
                    
                    alog("  " + "─"*50, "CORE", "INFO")
                    
                    # Export crash report
                    crash_report = output_path / "crash_analysis.json"
                    self.layer5_crash_analyzer.export_to_file(crash_report, format='json')
                    alog(f"  ✅ [Report] Saved to: {crash_report}", "CORE", "INFO")
                except Exception as e:
                    alog(f"  ❌ [Analysis] Failed: {e}", "CORE", "ERROR")
            
            # 3. ⭐ C-Side Syscall Tree Export (HTML Bundle)
            tree_path = output_path / "latest_syscall_tree.html"
            if tree_path.exists():
                alog(f"  🌳 [Syscall Tree] HTML Bundle Exported", "CORE", "INFO")
                alog(f"     => file://{tree_path.absolute()}", "CORE", "INFO")
            else:
                # alog(f"  ⚠️  [Syscall Tree] Export Failed (File not found)", "CORE", "WARN")
                pass
            
            alog("\n" + "═"*60, "CORE", "INFO")
            alog(f"  📂 All artifacts saved to: {output_path}", "CORE", "INFO")
            alog("═"*60 + "\n", "CORE", "INFO")
            
            # ✅ Final Resource Cleanup
            if self.execution_engine:
                self.execution_engine.stop_persistent_qemu()
            
            # ✅ STOP LOGGER LAST
            if self.logger:
                alog("✅ Project cleanup complete. Goodbye!", "CORE", "INFO")
                self.logger.stop()
    
    def sync_pool_pruning(self):
        """Synchronizes TracePool pruning with TraceManager/SeedQueue"""
        removed_ids = self.trace_pool.prune_redundant_traces(max_per_category=20)
        if removed_ids:
            alog(f"🧹 Syncing pruning: removing {len(removed_ids)} traces from SeedQueue", "CORE", "INFO")
            for tid in removed_ids:
                try:
                    self.trace_manager.remove_trace(tid)
                except Exception as e:
                    alog(f"⚠️ Failed to remove trace {tid} from manager: {e}", "CORE", "DEBUG")
                    
    def gc_intermediate_data(self):
        """Cleanup old analysis files and logs to save disk space"""
        alog("🧹 Running Data GC...", "CORE", "INFO")
        count = 0
        try:
            # Cleanup .analyzer.pkl files not in current pool
            active_traces = set(self.trace_pool.traces.keys())
            for pkl in glob.glob(str(Path(self.output_dir) / "**/*.analyzer.pkl"), recursive=True):
                # Heuristic: if pkl name doesn't match any active trace ID or base name
                base_name = os.path.basename(pkl).split('.')[0]
                if base_name not in active_traces and "seed" not in base_name:
                    os.remove(pkl)
                    count += 1
            alog(f"✅ GC complete: Removed {count} orphaned analysis files", "CORE", "INFO")
        except Exception as e:
            alog(f"⚠️ GC failed: {e}", "CORE", "WARN")

    def cleanup(self):
        """Clean up resources (called on exit)"""
        alog("Cleaning up resources...", "CORE", "INFO")
        
        # Display final statistics if not already shown recently
        self._display_progress(force=True)
        
        # ✅ Fix: Gracefully stop persistent QEMU executor
        if hasattr(self, 'execution_engine') and self.execution_engine:
            if hasattr(self.execution_engine, 'stop_persistent_mode'):
                # New persistent executor
                self.execution_engine.stop_persistent_mode()
            elif hasattr(self.execution_engine, 'stop_persistent_qemu'):
                # Legacy executor
                self.execution_engine.stop_persistent_qemu()
        
        # Clean up shared coverage bitmap
        from .qemu_executor import QEMUExecutor
        QEMUExecutor.cleanup_shared_coverage()
        
        # Clean up CoverageTracker (release multiprocessing resources)
        if hasattr(self, 'coverage_tracker') and self.coverage_tracker:
            if hasattr(self.coverage_tracker, 'cleanup'):
                self.coverage_tracker.cleanup()
        
        alog("✅ Cleanup complete", "CORE", "INFO")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.cleanup()
        except:
            pass
