import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from .trace_manager import Trace, TraceMetadata
from .async_logger import alog

class TracePool:
    """
    Enhanced Trace Storage & Lifecycle Manager (Layer 2)
    
    Responsibilities:
    1. Categorize traces: INITIAL (recorded), EVOLVED (mutated & re-recorded), PROMOTED (corpus).
    2. Track trace lineage (who evolved from whom).
    3. Maintain coverage-to-trace mapping for intelligent selection.
    """
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger("TracePool")
        self.traces: Dict[str, Trace] = {}
        self.categories: Dict[str, Set[str]] = {
            'INITIAL': set(),
            'EVOLVED': set(),
            'PROMOTED': set()
        }
        self.lineage: Dict[str, str] = {} # child_id -> parent_id
        
        # Stats
        self.global_coverage: Set[int] = set()
        self.last_added_id: Optional[str] = None

    def add_trace(self, trace: Trace, category: str = 'INITIAL', save: bool = True):
        """Adds a trace to the pool and updates categorization"""
        self.traces[trace.id] = trace
        
        if category in self.categories:
            self.categories[category].add(trace.id)
        
        if trace.metadata.parent_trace_id:
            self.lineage[trace.id] = trace.metadata.parent_trace_id
            
        self.last_added_id = trace.id
        # Update generation based on parent
        if trace.metadata.parent_trace_id in self.traces:
            parent = self.traces[trace.metadata.parent_trace_id]
            trace.metadata.generation = parent.metadata.generation + 1
        
        # Auto-save manifest for observability
        if save:
            self.save_manifest()

    def get_category_count(self) -> Dict[str, int]:
        return {cat: len(ids) for cat, ids in self.categories.items()}

    def get_trace_by_id(self, trace_id: str) -> Optional[Trace]:
        return self.traces.get(trace_id)

    def prune_redundant_traces(self, max_per_category: int = 20) -> List[str]:
        """
        Keeps the pool lean by removing redundant or low-value traces.
        Favors traces with higher execution counts or more recent generations.
        Returns the list of removed trace IDs.
        """
        all_removed = []
        for cat, ids in self.categories.items():
            if len(ids) <= max_per_category:
                continue
            
            self.logger.info(f"Pruning category {cat}: {len(ids)} -> {max_per_category}")
            # Sort by generation (depth) and exec_count (utility)
            sorted_ids = sorted(
                list(ids),
                key=lambda tid: (self.traces[tid].metadata.generation, self.traces[tid].metadata.exec_count),
                reverse=True
            )
            
            to_remove = sorted_ids[max_per_category:]
            for tid in to_remove:
                self.categories[cat].remove(tid)
                all_removed.append(tid)
                # Note: We keep them in self.traces memory for now to avoid breaking lineage,
                # but they won't be selected for fuzzing if we notify manager.
                
        self.save_manifest()
        return all_removed

    def save_manifest(self):
        """Saves a JSON manifest of the current trace pool status"""
        manifest_path = self.output_dir / "trace_pool_manifest.json"
        data = {
            'stats': self.get_category_count(),
            'lineage': self.lineage,
            'traces': [
                {
                    'id': tid,
                    'category': next((cat for cat, ids in self.categories.items() if tid in ids), 'UNKNOWN'),
                    'generation': t.metadata.generation,
                    'exec_count': t.metadata.exec_count,
                    'file': str(t.file_path)
                } for tid, t in self.traces.items()
            ]
        }
        with open(manifest_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        for t_data in data['traces']:
            alog(f"[TracePool] Manifest Saved: {t_data['id']} exec_count={t_data['exec_count']}", "DEBUG")

    def load_manifest(self, trace_manager: Any):
        """Loads trace pool state from manifest"""
        manifest_path = self.output_dir / "trace_pool_manifest.json"
        if not manifest_path.exists():
            return
            
        try:
            with open(manifest_path, 'r') as f:
                data = json.load(f)
            
            self.lineage = data.get('lineage', {})
            
            # Reconstruct categories
            for cat in self.categories:
                self.categories[cat] = set()
                
            for t_info in data.get('traces', []):
                tid = t_info['id']
                category = t_info.get('category', 'INITIAL')
                
                # Fetch full Trace object from TraceManager
                trace = trace_manager.get_trace_by_id(tid)
                if trace:
                    self.traces[tid] = trace
                    # Restore metadata from manifest
                    trace.metadata.generation = t_info.get('generation', 0)
                    trace.metadata.exec_count = t_info.get('exec_count', 0)
                    
                    if category in self.categories:
                        self.categories[category].add(tid)
            
            self.logger.info(f"✅ TracePool manifest loaded: {len(self.traces)} traces restored")
        except Exception as e:
            self.logger.error(f"❌ Failed to load TracePool manifest: {e}")

    def select_seeds_for_energy_scheduling(self) -> List[Trace]:
        """Returns all traces that should be considered for fuzzing"""
        # In this layer, we just provide the candidates. 
        # The EnergyScheduler will decide which one to pop.
        return list(self.traces.values())
