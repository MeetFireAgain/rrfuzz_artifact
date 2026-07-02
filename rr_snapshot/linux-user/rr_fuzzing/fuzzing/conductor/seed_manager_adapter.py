#!/usr/bin/env python3
"""
Seed Manager Adapter
Provides compatibility layer between TraceManager and AdvancedSeedQueue
"""

import time
from typing import Optional, Dict, List, Set
from dataclasses import dataclass

# Import both implementations
from .trace_manager import TraceManager, Trace, TraceMetadata
from multiprocess.seed_queue_advanced import AdvancedSeedQueue, Seed, SeedPriority, FuzzContext
from conductor.async_logger import alog


class SeedManagerAdapter:
    """
    Adapter that wraps AdvancedSeedQueue to provide TraceManager-compatible interface.

    This allows gradual migration from TraceManager to AdvancedSeedQueue without
    breaking existing code.

    Design:
    - Implements TraceManager's public interface
    - Delegates to AdvancedSeedQueue internally
    - Converts between Trace and Seed objects
    """

    def __init__(self, initial_trace: Optional[str] = None, use_advanced: bool = True):
        """
        Initialize adapter

        Args:
            initial_trace: Path to initial seed trace
            use_advanced: If True, use AdvancedSeedQueue; if False, fallback to TraceManager
        """
        self.use_advanced = use_advanced

        if use_advanced:
            # Use advanced seed queue with energy scheduling
            self.queue = AdvancedSeedQueue(
                max_size=10000,
                dedup=True,
                use_advanced_scheduling=True
            )
            self.trace_to_seed_map: Dict[str, Seed] = {}
            self.trace_cache: Dict[str, Trace] = {} # ✅ Cache Trace objects to maintain identity
            self.seed_counter = 0

            alog("Using AdvancedSeedQueue with Energy Scheduler", "CORE", "INFO")
        else:
            # Fallback to original TraceManager
            self.queue = TraceManager(initial_trace=initial_trace)
            alog("Using TraceManager (fallback mode)", "CORE", "WARN")

        # Add initial trace if provided
        if initial_trace and use_advanced:
            self.add_initial_trace(initial_trace)

    def _trace_to_seed(self, trace: Trace) -> Seed:
        """Convert Trace object to Seed object"""
        # Extract coverage from coverage_info if available
        coverage = set()
        if hasattr(self, 'queue') and isinstance(self.queue, AdvancedSeedQueue):
            # Coverage will be added via add_trace method
            pass

        seed = Seed(
            seed_id=trace.id,
            trace_file=trace.file_path,
            coverage=coverage,
            priority=SeedPriority.NORMAL,
            energy=trace.metadata.energy,
            parent_id=trace.metadata.parent_trace_id,
            generation=0,  # Will be computed from parent chain
            crash=False,
            execution_count=trace.metadata.exec_count,
            new_coverage_count=trace.metadata.new_coverage_count,
            discovery_time=trace.metadata.creation_time,
            path_depth=0,  # Will be computed
            exec_time=0.0,  # Will be measured
        )

        return seed

    def _seed_to_trace(self, seed: Seed) -> Trace:
        """Convert Seed object to Trace object (with caching)"""
        if seed.seed_id in self.trace_cache:
            # ✅ Synchronize using max() to ensure restored values from TracePool survive
            trace = self.trace_cache[seed.seed_id]
            
            # Sync exec_count (source of truth can be either during transition)
            new_count = max(trace.metadata.exec_count, seed.execution_count)
            trace.metadata.exec_count = new_count
            seed.execution_count = new_count
            
            # Sync energy and other metadata
            trace.metadata.energy = max(trace.metadata.energy, seed.energy)
            seed.energy = trace.metadata.energy
            
            return trace

        metadata = TraceMetadata(
            creation_time=seed.discovery_time,
            parent_trace_id=seed.parent_id,
            mutation_applied=[],  # TODO: track mutations in Seed
            energy=seed.energy,
            exec_count=seed.execution_count,
            new_coverage_count=seed.new_coverage_count
        )

        trace = Trace(
            id=seed.seed_id,
            file_path=seed.trace_file or "",
            metadata=metadata
        )
        
        self.trace_cache[seed.seed_id] = trace
        return trace

    def add_initial_trace(self, trace_file: str):
        """Add initial seed trace (TraceManager-compatible)"""
        if self.use_advanced:
            seed_id = "trace_000"
            seed = Seed(
                seed_id=seed_id,
                trace_file=trace_file,
                coverage=set(),
                priority=SeedPriority.HIGH,
                energy=3.0,  # Match TraceManager's initial energy
                parent_id=None,
                generation=0,
                crash=False,
                execution_count=0,
                new_coverage_count=0,
                discovery_time=time.time(),
            )

            self.queue.add(seed)
            self.trace_to_seed_map[seed_id] = seed
            self.seed_counter = 1

            alog(f"Added initial seed: {seed_id}", "CORE", "INFO")
        else:
            self.queue.add_initial_trace(trace_file)

    def add_trace(self, trace_file: str, coverage_info: Dict,
                  parent_id: Optional[str] = None,
                  mutations: Optional[List] = None) -> Trace:
        """Add new trace (TraceManager-compatible)"""
        if self.use_advanced:
            # Create Seed object
            seed_id = f"trace_{self.seed_counter:06d}"
            self.seed_counter += 1

            # Extract coverage edges
            coverage_edges = set()
            if 'edges' in coverage_info:
                coverage_edges = set(coverage_info['edges'])
            elif 'bitmap' in coverage_info:
                # Extract non-zero indices from bitmap
                bitmap = coverage_info['bitmap']
                coverage_edges = {i for i, val in enumerate(bitmap) if val > 0}

            # Compute generation from parent
            generation = 0
            if parent_id and parent_id in self.trace_to_seed_map:
                parent_seed = self.trace_to_seed_map[parent_id]
                generation = parent_seed.generation + 1

            seed = Seed(
                seed_id=seed_id,
                trace_file=trace_file,
                coverage=coverage_edges,
                priority=SeedPriority.NORMAL,
                energy=1.0,  # Will be calculated by energy scheduler
                parent_id=parent_id,
                generation=generation,
                crash=coverage_info.get('crash', False),
                execution_count=0,
                new_coverage_count=coverage_info.get('new_edge_count', 0),
                discovery_time=time.time(),
            )

            # Add to queue (energy will be calculated internally)
            added = self.queue.add(seed)

            if added:
                self.trace_to_seed_map[seed_id] = seed

            # Return Trace object for compatibility
            return self._seed_to_trace(seed)
        else:
            return self.queue.add_trace(trace_file, coverage_info, parent_id, mutations)

    def select_trace(self) -> Optional[Trace]:
        """Select trace for fuzzing (TraceManager-compatible)"""
        if self.use_advanced:
            # Update fuzzing context
            context = FuzzContext(
                current_time=time.time(),
                total_execs=self.queue.stats['total_execs'],
                global_coverage=self.queue.context.global_coverage,
                no_new_coverage_count=self.queue.stats['no_new_coverage_count'],
            )

            # Pop seed from advanced queue
            seed = self.queue.pop(context)

            if seed is None:
                return None

            # Update execution count
            seed.execution_count += 1
            self.queue.stats['total_execs'] += 1

            # Convert to Trace
            trace = self._seed_to_trace(seed)

            alog(f"Selected seed: {seed.seed_id} (energy={seed.energy:.2f}, exec_count={seed.execution_count})", "CORE", "DEBUG")

            return trace
        else:
            return self.queue.select_trace()

    def get_trace_by_id(self, trace_id: str) -> Optional[Trace]:
        """Get trace by ID (TraceManager-compatible)"""
        alog(f"get_trace_by_id({trace_id}): cache_size={len(self.trace_cache)}", "DEBUG")
        if self.use_advanced:
            seed = self.queue.seed_map.get(trace_id)
            return self._seed_to_trace(seed) if seed else None
        else:
            return self.queue.get_trace_by_id(trace_id)

    def remove_trace(self, trace_id: str):
        """Remove trace from pool (TraceManager-compatible)"""
        if self.use_advanced:
            # AdvancedSeedQueue doesn't support direct removal
            # Remove from map only
            if trace_id in self.trace_to_seed_map:
                del self.trace_to_seed_map[trace_id]
        else:
            self.queue.remove_trace(trace_id)

    def get_statistics(self) -> Dict:
        """Get statistics (TraceManager-compatible)"""
        if self.use_advanced:
            return {
                'total_traces': self.queue.stats['total_added'],
                'trace_pool_size': self.queue.size(),
                'active_traces': len([s for s in self.queue.seeds if s.execution_count > 0]),
                'traces_saved': self.queue.stats['total_added'],
                'total_execs': self.queue.stats['total_execs'],
                'duplicates_rejected': self.queue.stats['duplicates_rejected'],
                'no_new_coverage_count': self.queue.stats['no_new_coverage_count'],
            }
        else:
            return self.queue.get_statistics()

    def update_context(self, new_coverage: Set[int], no_progress: bool = False):
        """Update fuzzing context (for advanced mode)"""
        if self.use_advanced:
            self.queue.context.global_coverage.update(new_coverage)
            if no_progress:
                self.queue.stats['no_new_coverage_count'] += 1
            else:
                self.queue.stats['no_new_coverage_count'] = 0

            # Update context in queue
            self.queue.update_context(
                global_coverage=new_coverage,
                new_coverage_found=bool(new_coverage)
            )

    def record_execution(self, trace_id: str, trace_file: str, mutations: list,
                         has_new_coverage: bool = False, **kwargs):
        """
        Record execution statistics (TraceManager-compatible)

        Args:
            trace_id: Trace ID
            trace_file: Trace file path
            mutations: List of mutations applied
            has_new_coverage: Whether new coverage was found
        """
        if self.use_advanced:
            # For advanced mode, we track executions in the seed itself
            # The execution count is already updated in select_trace()
            # Here we can update additional statistics if needed
            if trace_id in self.trace_to_seed_map:
                seed = self.trace_to_seed_map[trace_id]
                if has_new_coverage:
                    seed.new_coverage_count += 1
            # Update global stats
            if has_new_coverage:
                self.queue.stats['no_new_coverage_count'] = 0
            else:
                self.queue.stats['no_new_coverage_count'] += 1
            
            # ✅ Sync updated exec_count from Trace object back to Seed if available
            if trace_id in self.trace_cache:
                trace = self.trace_cache[trace_id]
                seed = self.trace_to_seed_map.get(trace_id)
                if seed:
                    new_count = max(trace.metadata.exec_count, seed.execution_count)
                    trace.metadata.exec_count = new_count
                    seed.execution_count = new_count
                    
                    trace.metadata.energy = max(trace.metadata.energy, seed.energy)
                    seed.energy = trace.metadata.energy
        else:
            # Delegate to TraceManager
            self.queue.record_execution(trace_id, trace_file, mutations, has_new_coverage)

    def save_corpus(self, output_dir: str):
        """Save corpus to output directory (TraceManager-compatible)"""
        if self.use_advanced:
            # AdvancedSeedQueue doesn't have save_corpus, but we can save metadata
            import os
            import json

            os.makedirs(output_dir, exist_ok=True)
            corpus_file = os.path.join(output_dir, "corpus_seeds.json")

            # Save metadata
            corpus_data = {
                'total_seeds': self.queue.size(),
                'statistics': self.queue.get_stats(),
                'seeds': [
                    {
                        'seed_id': seed.seed_id,
                        'trace_file': seed.trace_file,
                        'energy': seed.energy,
                        'execution_count': seed.execution_count,
                        'new_coverage_count': seed.new_coverage_count,
                        'generation': seed.generation,
                        'parent_id': seed.parent_id,
                    }
                    for seed in list(self.queue.seed_map.values())
                ]
            }

            with open(corpus_file, 'w') as f:
                json.dump(corpus_data, f, indent=2)

            # Save actual bin files to a corpus/ subdirectory
            import shutil
            seeds_dir = os.path.join(output_dir, "corpus")
            os.makedirs(seeds_dir, exist_ok=True)
            
            saved_count = 0
            for seed in self.queue.seed_map.values():
                if seed.trace_file and os.path.exists(seed.trace_file):
                    dest = os.path.join(seeds_dir, f"{seed.seed_id}.bin")
                    if not os.path.exists(dest):
                        shutil.copy(seed.trace_file, dest)
                        saved_count += 1
            
            alog(f"Saved corpus metadata to {corpus_file}", "CORE", "INFO")
            alog(f"Saved {saved_count} seeds to {seeds_dir}", "CORE", "INFO")
        else:
            self.queue.save_corpus(output_dir)
