#!/usr/bin/env python3
"""
CoverageTracker - Enhanced Coverage Tracking

This module provides advanced coverage tracking including:
- Edge coverage tracking
- Hit count tracking (8-bit buckets like AFL)
- Hotspot analysis
- Coverage-guided mutation
- Stability tracking

For multi-process coverage, see shared_resources.py.
"""

from .constants import COVERAGE_MAP_SIZE
from collections import defaultdict
import struct
from .async_logger import alog
import time
import os
import threading


class CoverageTracker:
    """
    Enhanced Coverage Tracker
    
    Provides comprehensive coverage analysis including:
    - Edge discovery
    - Hit count tracking (AFL-style buckets)
    - Hotspot identification
    - Coverage-guided feedback
    - Stability metrics
    """
    
    # AFL-style hit count buckets
    HIT_COUNT_BUCKETS = [1, 2, 3, 4, 8, 16, 32, 128]

    def __init__(self, pid=None, shared_coverage=None):
        """
        Initializes the CoverageTracker.

        Args:
            pid (int, optional): Process ID. Defaults to current process ID.
            shared_coverage (SharedCoverage, optional): An instance of SharedCoverage for multi-process mode.
        """
        self.pid = pid if pid else os.getpid()
        self.shm_path = None  # Will be set on first read
        self.shm_base_name = "rr_coverage"

        # Thread-safe lock for concurrent access to global_bitmap and statistics
        self._lock = threading.Lock()

        # Multi-process shared coverage support
        self.shared_coverage = shared_coverage

        # Coverage bitmaps
        self.global_bitmap = bytearray(COVERAGE_MAP_SIZE)
        self.virgin_bits = bytearray([255] * COVERAGE_MAP_SIZE)  # AFL-style virgin map
        
        # Statistics
        self.new_edges_found = 0
        self.total_executions = 0
        self.edges_per_execution = []
        self.total_edges_cached = 0  # Cached total_edges to avoid re-calculation

        # Hit count tracking
        self.edge_hit_counts = defaultdict(int)  # edge_id -> total hits
        self.edge_first_seen = {}  # edge_id -> timestamp
        
        # Hotspot tracking
        self.hotspots = set()  # Frequently hit edges
        self.rare_edges = set()  # Rarely hit edges
        
        # Stability tracking
        self.stable_edges = set()  # Edges that always appear
        self.unstable_edges = set()  # Edges that appear/disappear
        
        # Coverage history
        self.coverage_history = []  # [(timestamp, total_edges)]
        self.last_new_coverage = time.time()
        
        # Stability phase tracking 
        self._is_stable_phase = False
        
    def read_coverage(self):
        """Read current coverage map"""
        try:
            with open(self.shm_path, 'rb') as f:
                # Skip 1-byte header (enabled flag)
                f.seek(1)
                return bytearray(f.read(64 * 1024))
        except FileNotFoundError:
            # Coverage may not be initialized yet
            return None
        except Exception as e:
            return None
    
    def _classify_hit_count(self, count):
        """Classify hit count into AFL-style buckets"""
        if count == 0:
            return 0
        for bucket in self.HIT_COUNT_BUCKETS:
            if count <= bucket:
                return bucket
        return 128
    
    def has_new_coverage(self, current_map):
        """
        Checks for new coverage or updated hit counts.

        This method identifies:
        1. Newly discovered edges (transition from 0 to non-zero hit count).
        2. Existing edges with increased hit counts that cross into new AFL-style buckets.

        The method is thread-safe and synchronizes with shared coverage in multi-process mode.
        """
        if not current_map or len(current_map) != COVERAGE_MAP_SIZE:
            return False

        # ✅ FIX: Handle memoryview with unsupported format by converting to bytes
        if isinstance(current_map, memoryview):
            current_map = current_map.tobytes()

        with self._lock:
            if self.shared_coverage and self.total_executions % 100 == 0:
                synced_edges = self.shared_coverage.sync_coverage()
                if synced_edges > 0:
                    # Update bitmap values and sync virgin bits
                    for i in range(COVERAGE_MAP_SIZE):
                        shared_val = self.shared_coverage.local_bitmap[i]
                        if shared_val > self.global_bitmap[i]:
                            # Update bitmap values and virgin bits without incrementing total_edges_cached
                            self.global_bitmap[i] = shared_val
                            if self.virgin_bits[i] > 0:
                                self.virgin_bits[i] = 0

            self.total_executions += 1
            new_coverage = False
            new_edges = 0
            current_edge_count = 0
            current_timestamp = time.time()
            
            debug_log_edges = []  # Sample of first 5 new edges for logging

            # Vectorized 64-bit chunk processing: iterates 8192 64-bit chunks
            # instead of 65536 bytes for significant speedup.
            
            longs = struct.unpack('<8192Q', current_map)
            global_longs = struct.unpack('<8192Q', self.global_bitmap)
            
            for k in range(8192):
                chunk_val = longs[k]
                
                # Fast path 1: Chunk is completely empty (very common in sparse maps)
                if chunk_val == 0:
                    continue 
                
                # Fast path 2: Chunk is identical to global bitmap (no new coverage possible)
                if chunk_val == global_longs[k]:
                    pass

                # If we are here, there's something interesting or we need to counting.
                base = k * 8
                for j in range(8):
                    idx = base + j
                    current_val = current_map[idx]  # Access original byte array (fast)

                    if current_val > 0:
                        current_edge_count += 1
                        old_val = self.global_bitmap[idx]

                        # New edge discovered
                        if old_val == 0:
                            new_edges += 1
                            new_coverage = True
                            self.total_edges_cached += 1
                            
                            self.global_bitmap[idx] = current_val
                            self.edge_first_seen[idx] = current_timestamp
                            self.last_new_coverage = current_timestamp

                            # Update virgin bits
                            if self.virgin_bits[idx] > 0:
                                self.virgin_bits[idx] = 0

                        # Check for hit count update
                        elif current_val > old_val:
                            old_bucket = self._classify_hit_count(old_val)
                            new_bucket = self._classify_hit_count(current_val)

                            if new_bucket > old_bucket:
                                new_coverage = True
                                self.global_bitmap[idx] = current_val

                                # Update virgin bits
                                if self.virgin_bits[idx] > 0:
                                    self.virgin_bits[idx] = 0

            # Update shared coverage for multi-process coordination
            if new_coverage and self.shared_coverage:
                self.shared_coverage.update_coverage(bytes(self.global_bitmap))

            # Record coverage history (using cached total_edges)
            if new_coverage:
                self.new_edges_found += new_edges
                self.coverage_history.append((current_timestamp, self.total_edges_cached))

            # Track edges per execution
            self.edges_per_execution.append(current_edge_count)
            
            # 🔥 Performance: Cap history lists to prevent memory exhaustion in long runs
            if len(self.edges_per_execution) > 10000:
                self.edges_per_execution = self.edges_per_execution[-10000:]
            if len(self.coverage_history) > 10000:
                self.coverage_history = self.coverage_history[-10000:]
            
            # Async Log summary every 50 executions (reduced frequency)
            if self.total_executions % 50 == 0 or new_coverage:
                # edges_after = sum(1 for b in self.global_bitmap if b > 0) # Expensive! Use cached.
                edges_after = self.total_edges_cached
                
                log_msg = (f"Exec #{self.total_executions}: "
                          f"Edges={current_edge_count}, New={new_edges}, "
                          f"Total={edges_after}")
                
                # Only log detail if new coverage found
                if new_coverage:
                    alog(f"Exec #{self.total_executions}: Edges={current_edge_count}, New={new_edges}, Total={edges_after} [NEW COV]", "COV")
                elif self.total_executions % 100 == 0: # Log keepalive every 100 iterations
                     alog(f"Exec #{self.total_executions}: LiveEdges={current_edge_count}, GlobalTotal={edges_after} (Bitmap: {edges_after})", "COV")

            # Periodic statistics update
            if self.total_executions % 500 == 0:
                self._update_hotspots()
                self._update_stability()

        # Return the number of newly discovered edges; if only a HitCount bucket update on an existing edge, count as 1 virtual new discovery
        return new_edges if new_edges > 0 else (1 if new_coverage else 0)
    
    def _update_hotspots(self):
        """Identify hotspots (frequently hit edges) and rare edges"""
        if not self.edge_hit_counts:
            return
        
        # Calculate average hit count
        total_hits = sum(self.edge_hit_counts.values())
        avg_hits = total_hits / len(self.edge_hit_counts)
        
        # Hotspots: edges hit > 10x average
        # Rare edges: edges hit < 0.1x average
        self.hotspots.clear()
        self.rare_edges.clear()
        
        for edge_id, hits in self.edge_hit_counts.items():
            if hits > avg_hits * 10:
                self.hotspots.add(edge_id)
            elif hits < avg_hits * 0.1:
                self.rare_edges.add(edge_id)
    
    def cleanup(self):
        """Clean up shared resources"""
        if self.shared_coverage and hasattr(self.shared_coverage, 'cleanup'):
            self.shared_coverage.cleanup()

    def _update_stability(self):
        """Track edge stability based on recent execution variance"""
        if len(self.edges_per_execution) < 10:
            return
        
        # Analyze last 10 executions
        recent_executions = self.edges_per_execution[-10:]
        avg_edges = sum(recent_executions) / len(recent_executions)
        variance = sum((x - avg_edges) ** 2 for x in recent_executions) / len(recent_executions)
        
        # Low variance indicates a stable coverage pattern
        if variance < avg_edges * 0.1:
            self._is_stable_phase = True
        else:
            self._is_stable_phase = False
        
    def get_interesting_edges(self):
        """
        Get edges that are interesting for mutation guidance.
        
        Returns:
            dict: {
                'rare': set of rare edge IDs,
                'recent': set of recently discovered edge IDs,
                'unstable': set of unstable edge IDs
            }
        """
        current_time = time.time()
        recent_threshold = current_time - 60  # Last 60 seconds
        
        recent_edges = {
            edge_id for edge_id, timestamp in self.edge_first_seen.items()
            if timestamp > recent_threshold
        }
        
        return {
            'rare': self.rare_edges.copy(),
            'recent': recent_edges,
            'unstable': self.unstable_edges.copy()
        }
    
    def get_coverage_trend(self):
        """
        Analyze coverage growth trend.
        
        Returns:
            dict: {
                'growing': bool,
                'stagnant': bool,
                'rate': float (edges per second)
            }
        """
        if len(self.coverage_history) < 2:
            return {'growing': False, 'stagnant': True, 'rate': 0.0}
        
        # Check if we've found new coverage recently
        time_since_last = time.time() - self.last_new_coverage
        stagnant = time_since_last > 300  # 5 minutes
        
        # Calculate growth rate
        if len(self.coverage_history) >= 2:
            first_time, first_edges = self.coverage_history[0]
            last_time, last_edges = self.coverage_history[-1]
            
            time_diff = last_time - first_time
            if time_diff > 0:
                rate = (last_edges - first_edges) / time_diff
            else:
                rate = 0.0
        else:
            rate = 0.0
        
        return {
            'growing': rate > 0,
            'stagnant': stagnant,
            'rate': rate
        }
    
    def get_stats(self):
        """
        Get comprehensive coverage statistics.

        Recalculates total_edges directly from the bitmap for precision.
        """
        with self._lock:
            # Force sync with shared memory if available
            if self.shared_coverage:
                 synced_edges = self.shared_coverage.sync_coverage()
                 if synced_edges > 0:
                     for i in range(COVERAGE_MAP_SIZE):
                         shared_val = self.shared_coverage.local_bitmap[i]
                         if shared_val > self.global_bitmap[i]:
                             self.global_bitmap[i] = shared_val
                             if self.virgin_bits[i] > 0:
                                 self.virgin_bits[i] = 0

            # Re-calculate total edges from bitmap for precision
            actual_total_edges = sum(1 for b in self.global_bitmap if b > 0)
            virgin_bits_count = sum(1 for b in self.virgin_bits if b == 255)

            trend = self.get_coverage_trend()

            return {
                'total_edges': actual_total_edges,
                'new_edges_this_run': self.new_edges_found,
                'bitmap_density': actual_total_edges * 100.0 / COVERAGE_MAP_SIZE,
                'virgin_bits': virgin_bits_count,
                'virgin_bits_percent': virgin_bits_count * 100.0 / COVERAGE_MAP_SIZE,
                'total_executions': self.total_executions,
                'hotspots': len(self.hotspots),
                'rare_edges': len(self.rare_edges),
                'stable_edges': len(self.stable_edges),
                'unstable_edges': len(self.unstable_edges),
                'coverage_trend': trend,
                'avg_edges_per_exec': sum(self.edges_per_execution) / len(self.edges_per_execution) if self.edges_per_execution else 0
            }
    
    def should_prioritize_exploration(self):
        """
        Determine if exploration should be prioritized over exploitation.
        
        Returns True if:
        - Coverage is still growing
        - Many virgin bits remain
        - New coverage was recently found
        """
        stats = self.get_stats()
        trend = stats['coverage_trend']
        
        # Prioritize exploration if:
        # 1. Coverage is growing
        # 2. > 50% virgin bits remain
        # 3. Found new coverage in last 60 seconds
        time_since_last = time.time() - self.last_new_coverage
        
        return (trend['growing'] or 
                stats['virgin_bits_percent'] > 50 or 
                time_since_last < 60)
    
    def get_bitmap(self) -> bytes:
        """Export coverage bitmap for checkpoint persistence"""
        with self._lock:
            return bytes(self.global_bitmap)
    
    def set_bitmap(self, bitmap_data: bytes):
        """Restore coverage bitmap from checkpoint"""
        if len(bitmap_data) != COVERAGE_MAP_SIZE:
            raise ValueError(f"Invalid bitmap size: {len(bitmap_data)} (expected {COVERAGE_MAP_SIZE})")
        
        with self._lock:
            self.global_bitmap = bytearray(bitmap_data)
            # Recalculate total_edges_cached
            self.total_edges_cached = sum(1 for b in self.global_bitmap if b > 0)
            # Reset virgin bits for restored edges
            for i in range(COVERAGE_MAP_SIZE):
                if self.global_bitmap[i] > 0:
                    self.virgin_bits[i] = 0

