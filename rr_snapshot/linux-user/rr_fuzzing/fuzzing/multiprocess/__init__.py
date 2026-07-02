"""
RR-Fuzz Multi-process Fuzzing Module

This package contains components for multi-process parallel fuzzing:
- fuzz_master: Multi-process fuzzing coordinator
- corpus_manager: Corpus persistence and management
- crash_analyzer: Crash classification and deduplication
- energy_scheduler: Intelligent seed energy scheduling
- seed_queue_advanced: Energy-based advanced seed queue
- shared_resources: Multi-process shared memory and seed synchronization
- path_finder: Path finder (offline CFG analysis and recipe generation)
"""

# ✅ Fix: Lazy imports to avoid circular dependencies
# Do not import directly in __init__.py; let users import explicitly
# from .fuzz_master import FuzzMaster, WorkerConfig, WorkerStats
# from .shared_resources import SharedCoverage, WorkerSeedQueue
# from .recipe_pool import RecipePool, RecipeStats

# DualLevelPathFinder imported from conductor (the optimized version)
try:
    from conductor.dual_level_path_finder import DualLevelPathFinder as PathFinder
    _has_path_finder = True
except ImportError:
    # Fallback to local if conductor not in path
    try:
        from .dual_level_path_finder import DualLevelPathFinder as PathFinder
        _has_path_finder = True
    except ImportError:
        PathFinder = None
        _has_path_finder = False

__all__ = [
    # Module names (for use with: from multiprocess import module_name)
    'fuzz_master',
    'corpus_manager',
    'crash_analyzer',
    'energy_scheduler',
    'seed_queue_advanced',
    'shared_resources',
    'dual_level_path_finder',  # Update this
    'recipe_pool',
    'dynamic_fork_controller',
]

