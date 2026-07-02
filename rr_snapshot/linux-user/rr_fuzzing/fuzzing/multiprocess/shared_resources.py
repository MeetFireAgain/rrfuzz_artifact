#!/usr/bin/env python3
"""
Shared Resources for Multi-Process Fuzzing

This module implements shared resources for inter-process communication:
1. SharedCoverage: Shared coverage bitmap using multiprocessing.Array (process-safe)
2. WorkerSeedQueue: Per-worker seed queue with sync mechanism
"""

import os
import mmap
import time
import pickle
import random
import hashlib
import multiprocessing as mp
from pathlib import Path
from typing import List, Set, Optional, Any, Dict
from dataclasses import dataclass

# Coverage bitmap size (64KB standard)
COVERAGE_MAP_SIZE = 64 * 1024


@dataclass
class SeedMetadata:
    """Seed metadata (parsed from filename)"""
    seed_id: str
    seq: int
    new_edges: int
    depth: int
    
    @staticmethod
    def parse_filename(filename: str) -> Optional['SeedMetadata']:
        """
        Parse seed filename
        Format: id_{seq:06d}_cov_{new_edges}_depth_{depth}
        """
        try:
            parts = filename.split('_')
            if len(parts) < 6:
                return None
            
            seq = int(parts[1])
            new_edges = int(parts[3])
            depth = int(parts[5])
            
            return SeedMetadata(
                seed_id=filename,
                seq=seq,
                new_edges=new_edges,
                depth=depth
            )
        except:
            return None


class SharedCoverage:
    """
    Shared Coverage Bitmap (Based on multiprocessing.Array - process-safe)

    Multiple processes share a coverage bitmap via multiprocessing.Array, achieving:
    1. Atomic updates to the global bitmap when a worker finds new coverage
    2. Periodic synchronization from global to local bitmap
    3. Use of process locks to ensure atomicity, no race conditions
    """

    # Class-level shared resources (shared across all instances)
    _shared_array = None
    _lock = None
    _revision = None # Global revision counter (mp.Value)

    @classmethod
    def _create_shared_resources(cls):
        """Create shared resources (should be called in parent process)"""
        return {
            # ✅ Performance: Disable internal lock since we use an explicit global lock
            'array': mp.Array('B', COVERAGE_MAP_SIZE, lock=False),
            'lock': mp.Lock(),
            'revision': mp.Value('L', 0)
        }

    def __init__(self, worker_id: int = 0, shared_objects: Optional[Dict] = None):
        """
        Initialize shared coverage

        Args:
            worker_id: Worker ID
            shared_objects: Optional dict containing 'array', 'lock', 'revision'
        """
        if shared_objects:
            self.shared_array = shared_objects['array']
            self.lock = shared_objects['lock']
            self.revision = shared_objects['revision']
        else:
            # Fallback for solo/legacy mode
            if SharedCoverage._shared_array is None:
                res = SharedCoverage._create_shared_resources()
                SharedCoverage._shared_array = res['array']
                SharedCoverage._lock = res['lock']
                SharedCoverage._revision = res['revision']
            
            self.shared_array = SharedCoverage._shared_array
            self.lock = SharedCoverage._lock
            self.revision = SharedCoverage._revision

        self.worker_id = worker_id
        # Local copy (reduce lock contention, fast query)
        self.local_bitmap = bytearray(COVERAGE_MAP_SIZE)
        self.local_revision = 0 # Last synced revision

        print(f"[SharedCoverage] Worker {worker_id} initialized (Shared Mode: {shared_objects is not None})")
    
    def sync_coverage(self) -> int:
        """
        Sync from global bitmap to local copy (process-safe)
        Uses vectorized 64-bit comparisons for performance.

        Returns:
            Number of newly discovered edges
        """
        # Fast path: Skip lock if global revision hasn't changed
        if self.revision.value == self.local_revision:
            return 0

        import struct
        new_edges = 0

        # Use process lock to protect read
        with self.lock:
            # Check revision again inside lock to avoid race conditions
            if self.revision.value == self.local_revision:
                return 0
                
            # ✅ Optimized: Use memoryview for fast buffer access
            global_view = memoryview(self.shared_array)
            local_view = memoryview(self.local_bitmap)
            
            # Vectorized comparison using struct
            global_longs = struct.unpack('<8192Q', global_view)
            local_longs = struct.unpack('<8192Q', local_view)
            
            for k in range(8192):
                if global_longs[k] == local_longs[k]:
                    continue
                
                # Update chunk
                base = k * 8
                for j in range(8):
                    idx = base + j
                    g_byte = global_view[idx]
                    l_byte = local_view[idx]
                    
                    if g_byte > l_byte:
                        new_edges += 1
                        local_view[idx] = g_byte
            
            # Sync complete, update local revision
            self.local_revision = self.revision.value

        return new_edges
    
    def update_coverage(self, exec_bitmap: bytes) -> int:
        """
        Update global coverage using execution bitmap
        Uses vectorized 64-bit comparisons for performance.
        
        Args:
            exec_bitmap: Coverage bitmap generated by execution
            
        Returns:
            Number of newly discovered edges
        """
        import struct
        if len(exec_bitmap) > COVERAGE_MAP_SIZE:
            exec_bitmap = exec_bitmap[:COVERAGE_MAP_SIZE]
        
        # Fast check: If the entire block is identical to local, skip local-to-global sync
        # This check is FAST and done outside the lock.
        if exec_bitmap == self.local_bitmap:
            return 0

        new_edges = 0
        
        # Use process lock to ensure atomicity (eliminate race conditions)
        with self.lock:
            # Re-check against local after lock is acquired (another sync might have happened)
            if exec_bitmap == self.local_bitmap:
                return 0
            
            # ✅ Optimized: Use memoryview for fast buffer access
            global_view = memoryview(self.shared_array)
            local_view = memoryview(self.local_bitmap)
            exec_view = memoryview(exec_bitmap)
                
            exec_longs = struct.unpack('<8192Q', exec_view)
            local_longs = struct.unpack('<8192Q', local_view)

            for k in range(8192):
                if exec_longs[k] == local_longs[k]:
                    continue
                
                # Check byte-by-byte and update global
                base = k * 8
                for j in range(8):
                    idx = base + j
                    e_byte = exec_view[idx]
                    l_byte = local_view[idx]
                    
                    if e_byte > l_byte:
                        local_view[idx] = e_byte
                        
                        # Update global if better
                        if e_byte > global_view[idx]:
                            global_view[idx] = e_byte
                            new_edges += 1
            
            # If we updated global, increment revision
            if new_edges > 0:
                with self.revision.get_lock():
                    self.revision.value += 1
                self.local_revision = self.revision.value # Keep local in sync
        
        return new_edges
    
    def get_coverage_count(self) -> int:
        """Get current coverage count (performs sync first)"""
        self.sync_coverage()
        return sum(1 for b in self.local_bitmap if b > 0)
    
    @classmethod
    def cleanup(cls):
        """Clean up shared resources"""
        cls._shared_array = None
        cls._lock = None
        cls._revision = None
        
    def __del__(self):
        """Destructor"""
        try:
            self.cleanup()
        except:
            pass


class WorkerSeedQueue:
    """
    Worker Seed Queue Management
    
    Each worker has its own private queue, periodically importing high-quality seeds from other workers.
    
    Strategy:
    1. Local priority: 80% time processing local seeds
    2. Periodic sync: Sync from others every 100 iterations
    3. Smart import: Only import high-quality seeds (new_edges > threshold)
    4. Deduplication: Avoid re-importing identical seeds
    """
    
    def __init__(
        self,
        worker_id: int,
        sync_dir: Path,
        num_workers: int
    ):
        """
        Initialize Worker Seed Queue
        
        Args:
            worker_id: Worker ID
            sync_dir: Synchronization directory
            num_workers: Total number of workers
        """
        self.worker_id = worker_id
        self.sync_dir = sync_dir
        self.num_workers = num_workers
        
        # Private queue directory
        self.my_dir = sync_dir / "queue" / f"worker{worker_id}"
        self.my_dir.mkdir(parents=True, exist_ok=True)
        
        # Imported seeds (deduplication)
        self.imported_seeds: Set[str] = set()
        
        # Sync counter
        self.sync_counter = 0
        self.SYNC_INTERVAL = 100  # Synchronize every 100 iterations
        
        # Seed sequence number
        self.seq = 0
        
        # Statistics
        self.imported_count = 0
        self.avg_depth = 0
    
    def should_sync(self) -> bool:
        """Decide if sync is needed"""
        self.sync_counter += 1
        return self.sync_counter % self.SYNC_INTERVAL == 0
    
    def sync_with_others(self) -> List[Any]:
        """
        Import new seeds from other workers
        
        Returns:
            List of imported seeds
        """
        imported_seeds = []
        
        # Scan all other worker directories
        for other_worker_id in range(self.num_workers):
            if other_worker_id == self.worker_id:
                continue  # Skip self
            
            other_worker_dir = self.sync_dir / "queue" / f"worker{other_worker_id}"
            if not other_worker_dir.exists():
                continue
            
            # Found new seeds
            for seed_file in other_worker_dir.iterdir():
                seed_id = seed_file.name
                
                # Avoid duplicate import
                if seed_id in self.imported_seeds:
                    continue
                
                # Parse seed metadata
                metadata = SeedMetadata.parse_filename(seed_id)
                if not metadata:
                    continue
                
                # Import strategy: only import high quality seeds
                if self._should_import(metadata):
                    try:
                        seed = self._load_seed(seed_file)
                        if seed:
                            imported_seeds.append(seed)
                            self.imported_seeds.add(seed_id)
                            self.imported_count += 1
                    except:
                        pass
                
                # Limit single import count
                if len(imported_seeds) >= 50:
                    break
            
            if len(imported_seeds) >= 50:
                break
        
        return imported_seeds
    
    def _should_import(self, metadata: SeedMetadata) -> bool:
        """
        Decide if a seed should be imported
        
        Strategy:
        1. High new coverage seeds (new_edges > 5)
        2. High depth seeds (depth > avg)
        3. Random sampling (10% probability)
        """
        # Strategy 1: High coverage
        if metadata.new_edges > 5:
            return True
        
        # Strategy 2: Deep path
        if self.avg_depth > 0 and metadata.depth > self.avg_depth:
            return True
        
        # Strategy 3: Random sampling (diversity)
        if random.random() < 0.1:
            return True
        
        return False
    
    def _load_seed(self, seed_file: Path) -> Optional[Any]:
        """Load seed file"""
        try:
            with open(seed_file, 'rb') as f:
                return pickle.load(f)
        except:
            # If not in pickle format, return as raw bytes
            try:
                with open(seed_file, 'rb') as f:
                    return f.read()
            except:
                return None
    
    def save_seed(
        self,
        seed: Any,
        new_edges: int,
        depth: int
    ) -> Path:
        """
        Save new seed to private directory
        
        Args:
            seed: Seed object
            new_edges: Number of new edges discovered
            depth: Path depth
        
        Returns:
            Saved file path
        """
        # Generate filename
        seed_id = f"id_{self.seq:06d}_cov_{new_edges}_depth_{depth}"
        seed_path = self.my_dir / seed_id
        
        # Atomic write (write to tmp then rename)
        temp_path = seed_path.with_suffix('.tmp')
        
        try:
            with open(temp_path, 'wb') as f:
                pickle.dump(seed, f)
            
            # Atomic rename
            temp_path.rename(seed_path)
            
            self.seq += 1
            
            # Update average depth
            self._update_avg_depth(depth)
            
            return seed_path
        
        except Exception as e:
            # Clean up tmp file
            if temp_path.exists():
                temp_path.unlink()
            raise e
    
    def _update_avg_depth(self, depth: int):
        """Update average depth (moving average)"""
        alpha = 0.1  # Smoothing factor
        self.avg_depth = alpha * depth + (1 - alpha) * self.avg_depth
    
    def get_queue_size(self) -> int:
        """Get queue size"""
        return len(list(self.my_dir.iterdir()))
    
    def load_all_seeds(self) -> List[Any]:
        """Load all local seeds"""
        seeds = []
        for seed_file in self.my_dir.iterdir():
            seed = self._load_seed(seed_file)
            if seed:
                seeds.append(seed)
        return seeds


class WorkStealingQueue:
    """
    Work Stealing Queue
    
    When a worker's local queue is empty, it can 'steal' work from other workers.
    """
    
    def __init__(
        self,
        worker_id: int,
        sync_dir: Path,
        num_workers: int
    ):
        self.worker_id = worker_id
        self.sync_dir = sync_dir
        self.num_workers = num_workers
    
    def steal_from_others(self) -> Optional[Any]:
        """
        Steal work from others
        
        Returns:
            Stolen seed, or None if failed
        """
        # Randomly choose a victim worker
        victim_id = random.choice([
            w for w in range(self.num_workers)
            if w != self.worker_id
        ])
        
        victim_dir = self.sync_dir / "queue" / f"worker{victim_id}"
        if not victim_dir.exists():
            return None
        
        # Get victim's seeds
        seed_files = list(victim_dir.iterdir())
        if not seed_files:
            return None
        
        # Randomly steal one
        stolen_file = random.choice(seed_files)
        
        try:
            with open(stolen_file, 'rb') as f:
                return pickle.load(f)
        except:
            return None


def test_shared_coverage():
    """Test SharedCoverage"""
    print("Testing SharedCoverage...")

    # Create coverage for two workers (shared multiprocessing.Array)
    worker0 = SharedCoverage(worker_id=0)
    worker1 = SharedCoverage(worker_id=1)

    # Worker 0 discovers new coverage
    test_bitmap = bytearray(COVERAGE_MAP_SIZE)
    test_bitmap[0] = 0xFF
    test_bitmap[1] = 0xAA

    new_edges = worker0.update_coverage(bytes(test_bitmap))
    print(f"Worker 0 found {new_edges} new edges")

    # Worker 1 synchronizes
    new_edges = worker1.sync_coverage()
    print(f"Worker 1 synced {new_edges} new edges")

    # Verify
    assert worker1.local_bitmap[0] == 0xFF
    assert worker1.local_bitmap[1] == 0xAA

    print("✓ SharedCoverage test passed (multiprocessing.Array)")


def test_worker_seed_queue():
    """Test WorkerSeedQueue"""
    import tempfile
    import shutil
    
    print("Testing WorkerSeedQueue...")
    
    # Create temporary directory
    temp_dir = Path(tempfile.mkdtemp())
    (temp_dir / "queue").mkdir()
    
    try:
        # Create queues for two workers
        worker0_queue = WorkerSeedQueue(0, temp_dir, 2)
        worker1_queue = WorkerSeedQueue(1, temp_dir, 2)
        
        # Worker 0 saves seeds
        test_seed = b"test_seed_data"
        worker0_queue.save_seed(test_seed, new_edges=10, depth=50)
        worker0_queue.save_seed(test_seed, new_edges=5, depth=30)
        
        print(f"Worker 0 queue size: {worker0_queue.get_queue_size()}")
        
        # Worker 1 synchronizes
        imported = worker1_queue.sync_with_others()
        print(f"Worker 1 imported {len(imported)} seeds")
        
        print("✓ WorkerSeedQueue test passed")
    
    finally:
        shutil.rmtree(temp_dir)


if __name__ == '__main__':
    test_shared_coverage()
    test_worker_seed_queue()

