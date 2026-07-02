#!/usr/bin/env python3
"""
Fuzzing Watchdog - System Health Monitoring

Responsibilities:
1. Monitor QEMU process status, detect dead processes
2. Monitor Fuzzing loop heartbeat, detect main loop blocking
3. Handle timeout restart logic
"""

import time
import threading
import os
import signal
import subprocess
from typing import Optional, Callable
from .async_logger import alog

class FuzzingWatchdog:
    """Fuzzing System Watchdog"""
    
    def __init__(self, 
                 executor_check_func: Callable[[], bool], 
                 restart_func: Callable[[], None],
                 timeout_seconds: int = 120,
                 check_interval: int = 5):
        """
        Initialize Watchdog
        
        Args:
            executor_check_func: Callback function to check if Executor is alive
            restart_func: Callback function to restart Executor
            timeout_seconds: Timeout threshold for stalled detection (seconds)
            check_interval: Check interval (seconds)
        """
        self.check_func = executor_check_func
        self.restart_func = restart_func
        self.timeout = timeout_seconds
        self.interval = check_interval
        
        self.last_activity = time.time()
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._suppressed = False  # Set True during intentional QEMU resets
        
    def start(self):
        """Start monitoring thread"""
        if self.running:
            return
            
        self.running = True
        self._stop_event.clear()
        self.last_activity = time.time()
        
        self._thread = threading.Thread(target=self._monitor_loop, name="FuzzingWatchdog")
        self._thread.daemon = True
        self._thread.start()
        alog(f"Watchdog started (timeout={self.timeout}s)", "WATCHDOG", "INFO")
        
    def stop(self):
        """Stop monitoring"""
        if not self.running:
            return
            
        self.running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        alog("Watchdog stopped", "WATCHDOG", "INFO")
        
    def kick(self):
        """Kick the dog: update last activity time"""
        self.last_activity = time.time()

    def suppress(self):
        """Temporarily suppress Watchdog during intentional QEMU resets."""
        self._suppressed = True
        self.kick()  # Reset activity timer so stall detector doesn't fire

    def resume(self):
        """Resume Watchdog after intentional QEMU reset completes."""
        self._suppressed = False
        self.kick()

    def _monitor_loop(self):
        """Monitoring loop"""
        while self.running and not self._stop_event.is_set():
            try:
                if self._suppressed:
                    self._stop_event.wait(self.interval)
                    continue

                # 1. Check if Executor process exists
                if not self.check_func():
                    alog("⚠️ QEMU process died unexpectedly!", "WATCHDOG", "WARN")
                    self._trigger_recovery("Process Death")
                    
                # 2. Check last activity time (Stall detection)
                elapsed = time.time() - self.last_activity
                if elapsed > self.timeout:
                    alog(f"⚠️ Fuzzing stalled for {elapsed:.1f}s (Timeout={self.timeout}s)", "WATCHDOG", "WARN")
                    self._trigger_recovery("Stalled")
                    
            except Exception as e:
                alog(f"Error in watchdog loop: {e}", "WATCHDOG", "ERROR")
                
            # Sleep
            self._stop_event.wait(self.interval)
            
    def _trigger_recovery(self, reason: str):
        """Trigger recovery process"""
        alog(f"🚨 Triggering recovery routine (Reason: {reason})", "WATCHDOG", "WARN")
        try:
            self.restart_func()
            alog("✅ Recovery routine completed", "WATCHDOG", "INFO")
            # Reset timer
            self.kick()
        except Exception as e:
            alog(f"❌ Recovery failed: {e}", "WATCHDOG", "ERROR")
