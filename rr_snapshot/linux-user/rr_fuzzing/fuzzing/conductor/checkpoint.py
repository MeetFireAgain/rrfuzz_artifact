#!/usr/bin/env python3
"""
CheckpointManager - State Persistence for Fuzzing Campaigns

Enables saving and restoring the entire fuzzer state to disk, allowing
campaigns to survive crashes, reboots, or planned shutdowns.
"""

import os
import json
import time
import shutil
from pathlib import Path
from typing import Dict, Any, Optional
from .async_logger import alog


class CheckpointManager:
    """
    Manages disk-based state persistence for FuzzingCore.
    
    Saves:
    - Fuzzing Statistics (stats.json)
    - Seed Queue State (queue_state.json)
    - Coverage Bitmap (coverage.bin)
    """
    
    def __init__(self, output_dir: str, max_checkpoints: int = 3):
        """
        Initialize CheckpointManager
        
        Args:
            output_dir: Base directory for fuzzing outputs
            max_checkpoints: Maximum number of checkpoint backups to keep (default: 3)
        """
        self.output_dir = Path(output_dir)
        self.checkpoint_dir = self.output_dir / ".checkpoint"
        self.max_checkpoints = max_checkpoints
        
    def save(self, core_instance) -> bool:
        """
        Save entire fuzzing state to disk
        
        Args:
            core_instance: FuzzingCore instance
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create checkpoint directory if it doesn't exist
            self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
            
            alog("💾 Saving checkpoint...", "CHECKPOINT", "INFO")
            start_time = time.time()
            
            # 1. Save Statistics
            self._save_statistics(core_instance)
            
            # 2. Save Queue State
            self._save_queue_state(core_instance)
            
            # 3. Save Coverage Bitmap
            self._save_coverage(core_instance)
            
            # 4. Save metadata (timestamp, iteration count)
            self._save_metadata(core_instance)
            
            # 5. Save TracePool Manifest (Key for Phase 4)
            if hasattr(core_instance, 'trace_pool') and core_instance.trace_pool:
                core_instance.trace_pool.save_manifest()
            
            elapsed = time.time() - start_time
            alog(f"✅ Checkpoint saved in {elapsed:.2f}s", "CHECKPOINT", "INFO")
            
            # 🗑️ Rotate old checkpoints
            self._rotate_checkpoints()
            
            return True
            
        except Exception as e:
            alog(f"❌ Failed to save checkpoint: {e}", "CHECKPOINT", "ERROR")
            import traceback
            traceback.print_exc()
            return False
    
    def load(self, core_instance) -> bool:
        """
        Load fuzzing state from disk
        
        Args:
            core_instance: FuzzingCore instance
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.checkpoint_dir.exists():
                alog("No checkpoint found", "CHECKPOINT", "INFO")
                return False
            
            alog("📂 Loading checkpoint...", "CHECKPOINT", "INFO")
            start_time = time.time()
            
            # 1. Load Statistics
            self._load_statistics(core_instance)
            
            # 2. Load Queue State
            self._load_queue_state(core_instance)
            
            # 3. Load Coverage Bitmap
            self._load_coverage(core_instance)
            
            # 4. Load metadata
            metadata = self._load_metadata()
            
            # 5. Load TracePool Manifest (Key for Phase 4)
            if hasattr(core_instance, 'trace_pool') and core_instance.trace_pool:
                # Need trace_manager to link Trace objects
                if hasattr(core_instance, 'trace_manager'):
                    core_instance.trace_pool.load_manifest(core_instance.trace_manager)
            
            elapsed = time.time() - start_time
            alog(f"✅ Checkpoint loaded in {elapsed:.2f}s", "CHECKPOINT", "INFO")
            alog(f"   Resuming from iteration {metadata.get('iteration', 0)}", "CHECKPOINT", "INFO")
            return True
            
        except Exception as e:
            alog(f"❌ Failed to load checkpoint: {e}", "CHECKPOINT", "ERROR")
            import traceback
            traceback.print_exc()
            return False
    
    def _save_statistics(self, core):
        """Save fuzzing statistics sync'd from all components"""
        stats_file = self.checkpoint_dir / "stats.json"
        
        # Source of truth for iterations: core.total_iterations or metrics
        total_iterations = getattr(core, 'total_iterations', 0)
        if total_iterations == 0 and hasattr(core, 'metrics'):
            total_iterations = core.metrics.success_counts.get('total_iterations', 0)
            
        # Source of truth for executions: Aggregated from all sources
        total_executions = getattr(core, 'total_executions', 0)
        if hasattr(core, 'stats'):
            total_executions = max(total_executions, getattr(core.stats, 'total_execs', 0))
        if hasattr(core, 'execution_engine'):
            total_executions = max(total_executions, getattr(core.execution_engine, 'total_executions', 0))
        
        stats = {
            "total_executions": total_executions,
            "total_iterations": total_iterations,
            "start_time": getattr(core, 'start_time', time.time()),
            "crashes": getattr(core.crash_detector, 'crash_count', 0) if hasattr(core, 'crash_detector') else 0,
            "paths_found": getattr(core.stats, 'paths_found', 0) if hasattr(core, 'stats') else 0,
            "total_edges": getattr(core.coverage_tracker, 'total_edges_cached', 0) if hasattr(core, 'coverage_tracker') else 0,
        }
        
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
    
    def _load_statistics(self, core):
        """Load fuzzing statistics"""
        stats_file = self.checkpoint_dir / "stats.json"
        
        if not stats_file.exists():
            return
        
        with open(stats_file, 'r') as f:
            stats = json.load(f)
        
        # Restore attributes
        core.total_executions = stats.get("total_executions", 0)
        core.total_iterations = stats.get("total_iterations", 0)
        core.start_time = stats.get("start_time", time.time())
        
        # sync to sub-components
        if hasattr(core, 'execution_engine'):
            core.execution_engine.total_executions = core.total_executions
            
        if hasattr(core, 'stats'):
            core.stats.total_execs = core.total_executions
            core.stats.paths_found = stats.get("paths_found", 0)
            core.stats.start_time = core.start_time

        if hasattr(core, 'metrics'):
            core.metrics.success_counts['total_iterations'] = core.total_iterations
            core.metrics.start_time = core.start_time
        
        if hasattr(core, 'crash_detector'):
            core.crash_detector.crash_count = stats.get("crashes", 0)
    
    def _save_queue_state(self, core):
        """Save seed queue state"""
        queue_file = self.checkpoint_dir / "queue_state.json"
        
        queue_data = {
            "traces": [],
            "current_index": 0
        }
        
        # Save TraceManager state
        if hasattr(core, 'trace_manager'):
            tm = core.trace_manager
            queue_data["traces"] = list(tm.traces.keys()) if hasattr(tm, 'traces') else []
        
        with open(queue_file, 'w') as f:
            json.dump(queue_data, f, indent=2)
    
    def _load_queue_state(self, core):
        """Load seed queue state"""
        queue_file = self.checkpoint_dir / "queue_state.json"
        
        if not queue_file.exists():
            return
        
        with open(queue_file, 'r') as f:
            queue_data = json.load(f)
        
        # Restore trace list (actual trace files should already exist in output_dir)
        # We just verify they exist
        if hasattr(core, 'trace_manager'):
            expected_traces = queue_data.get("traces", [])
            alog(f"   Found {len(expected_traces)} traces in checkpoint", "CHECKPOINT", "DEBUG")
    
    def _save_coverage(self, core):
        """Save coverage bitmap to disk"""
        cov_file = self.checkpoint_dir / "coverage.bin"
        
        if not hasattr(core, 'coverage_tracker'):
            return
        
        # Get the bitmap from CoverageTracker
        bitmap = core.coverage_tracker.get_bitmap()
        if bitmap:
            with open(cov_file, 'wb') as f:
                f.write(bitmap)
    
    def _load_coverage(self, core):
        """Load coverage bitmap from disk"""
        cov_file = self.checkpoint_dir / "coverage.bin"
        
        if not cov_file.exists():
            return
        
        if not hasattr(core, 'coverage_tracker'):
            return
        
        with open(cov_file, 'rb') as f:
            bitmap = f.read()
        
        # Restore the bitmap
        core.coverage_tracker.set_bitmap(bitmap)
        alog(f"   Restored coverage bitmap ({len(bitmap)} bytes)", "CHECKPOINT", "DEBUG")
    
    def _save_metadata(self, core):
        """Save checkpoint metadata"""
        meta_file = self.checkpoint_dir / "metadata.json"
        
        metadata = {
            "timestamp": time.time(),
            "iteration": getattr(core, 'total_iterations', 0),
            "version": "1.0"
        }
        
        with open(meta_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load checkpoint metadata"""
        meta_file = self.checkpoint_dir / "metadata.json"
        
        if not meta_file.exists():
            return {}
        
        with open(meta_file, 'r') as f:
            return json.load(f)
    
    def exists(self) -> bool:
        """Check if a checkpoint exists"""
        return (self.checkpoint_dir / "metadata.json").exists()
    
    def _rotate_checkpoints(self):
        """
        Rotate old checkpoints, keeping only the latest N backups.
        Archived checkpoints are stored as .checkpoint.bak.TIMESTAMP
        """
        if self.max_checkpoints <= 0:
            return  # Rotation disabled
        
        # Find all backup directories
        backup_pattern = ".checkpoint.bak.*"
        backups = sorted(
            [p for p in self.output_dir.glob(backup_pattern) if p.is_dir()],
            key=lambda p: p.stat().st_mtime,
            reverse=True  # Newest first
        )
        
        # If we have too many backups, delete the oldest ones
        if len(backups) >= self.max_checkpoints:
            to_delete = backups[self.max_checkpoints - 1:]  # Keep max_checkpoints-1 (current one will be added)
            for old_backup in to_delete:
                try:
                    shutil.rmtree(old_backup)
                    alog(f"🗑️ Removed old checkpoint: {old_backup.name}", "CHECKPOINT", "DEBUG")
                except Exception as e:
                    alog(f"⚠️ Failed to remove {old_backup.name}: {e}", "CHECKPOINT", "WARN")
        
        # Archive current checkpoint
        if self.checkpoint_dir.exists():
            timestamp = int(time.time())
            backup_name = f".checkpoint.bak.{timestamp}"
            backup_path = self.output_dir / backup_name
            
            try:
                # Copy (not move) current checkpoint to backup
                shutil.copytree(self.checkpoint_dir, backup_path)
                alog(f"💾 Archived checkpoint: {backup_name}", "CHECKPOINT", "DEBUG")
            except Exception as e:
                alog(f"⚠️ Failed to archive checkpoint: {e}", "CHECKPOINT", "WARN")
    
    def clean(self):
        """Remove checkpoint directory"""
        if self.checkpoint_dir.exists():
            shutil.rmtree(self.checkpoint_dir)
            alog("🗑️  Checkpoint cleaned", "CHECKPOINT", "INFO")
