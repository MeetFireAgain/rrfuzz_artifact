import os
import time
import logging
import signal
from pathlib import Path
from typing import Optional
from .fuzzing_core import FuzzingCore

class CampaignManager:
    """
    Orchestrator for long-running fuzzing campaigns (Phase 4).
    Handles persistence, pruning, and health monitoring.
    """
    def __init__(self, core: FuzzingCore, iteration_limit: int = 1000000):
        self.core = core
        self.iteration_limit = iteration_limit
        self.output_dir = Path(core.output_dir)
        self.logger = logging.getLogger("CampaignManager")
        
        # Stability parameters
        self.last_heartbeat_iter = 0
        self.last_heartbeat_time = time.time()
        self.stuck_threshold_seconds = 60
        
        # Maintenance intervals
        self.pruning_interval = 500  # iters
        self.snapshot_interval = 2000 # iters

    def run(self):
        """Starts the long-term fuzzing campaign"""
        self.logger.info(f"🚀 Launching long-term campaign (Limit: {self.iteration_limit} iters)")
        
        try:
            start_iter = getattr(self.core, 'total_iterations', 0)
            for iteration in range(start_iter, self.iteration_limit):
                # 1. Run fuzzing iteration
                result = self.core.run_single_iteration(iteration_id=iteration)
                
                # 2. Update heartbeat
                self.last_heartbeat_iter = iteration
                self.last_heartbeat_time = time.time()
                
                # 3. Periodic Maintenance: Evolution
                if iteration > 0 and iteration % 100 == 0:
                    self.core._perform_evolution_step()
                
                # 4. Periodic Maintenance: Pruning & GC
                if iteration > 0 and iteration % self.pruning_interval == 0:
                    self.core.sync_pool_pruning()
                    self.core.gc_intermediate_data()
                
                # ✅ 4.5. Periodic Snapshot/Checkpoint Save
                if iteration > 0 and iteration % self.snapshot_interval == 0:
                    if hasattr(self.core, 'checkpoint_manager') and self.core.checkpoint_manager:
                        self.logger.info(f"💾 Saving campaign snapshot at iteration {iteration}...")
                        self.core.checkpoint_manager.save(self.core)
                
                # 5. Stability Watchdog
                if iteration % 10 == 0:
                    self._check_stability()
                
        except KeyboardInterrupt:
            self.logger.info("Interrupt received, stopping campaign...")
        except Exception as e:
            self.logger.error(f"💥 Campaign crashed due to unhandled exception: {e}", exc_info=True)
        finally:
            self.core.cleanup()

    def _check_stability(self):
        """Monitors for hangs or low-performance periods"""
        elapsed = time.time() - self.last_heartbeat_time
        if elapsed > self.stuck_threshold_seconds:
            self.logger.warning(f"⚠️ Fuzzer seems stuck (No iteration for {elapsed:.1f}s). Restarting fork server...")
            # Trigger fork server restart
            if hasattr(self.core.execution_engine, 'stop_fork_server'):
                self.core.execution_engine.stop_fork_server()
            self.last_heartbeat_time = time.time() # Reset clock
