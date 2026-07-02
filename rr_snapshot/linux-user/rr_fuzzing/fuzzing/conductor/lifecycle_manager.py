import os
import subprocess
import signal
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from .target_profile import TargetProfile

class TargetLifecycleManager:
    """
    Manages the lifecycle of a target service (startup, stopping, health checks).
    Handles environment patching and QEMU orchestration.
    """
    def __init__(self, profile: TargetProfile, qemu_path: str):
        self.profile = profile
        self.qemu_path = qemu_path
        self.logger = logging.getLogger("LifecycleManager")
        self.current_process = None

    def patch_environment(self):
        """Applies configuration patches specified in the profile"""
        rootfs = Path(self.profile.rootfs_path)
        for patch in self.profile.config_patches:
            src = rootfs / patch['source']
            dst = Path(patch['target'])
            
            if not src.exists():
                self.logger.warning(f"Patch source {src} not found, skipping.")
                continue
                
            self.logger.info(f"Patching {src} -> {dst}")
            with open(src, 'r') as f:
                content = f.read()
                
            for k, v in patch['replacements'].items():
                v = v.replace("{{ROOTFS}}", str(rootfs))
                content = content.replace(k, v)
                
            dst.parent.mkdir(parents=True, exist_ok=True)
            with open(dst, 'w') as f:
                f.write(content)

    def get_execution_env(self, mode: str, trace_file: Optional[str] = None) -> Dict[str, str]:
        """Generates the environment variables for a QEMU run"""
        env = os.environ.copy()
        env.update(self.profile.env)
        env['QEMU_LD_PREFIX'] = self.profile.ld_prefix
        
        if mode == 'record':
            env['RR_MODE'] = 'record'
            env['RR_ENABLED'] = '1'
            if trace_file:
                env['RR_TRACE_FILE'] = trace_file
        elif mode == 'fuzzing':
            env['RR_MODE'] = 'fuzzing'
            env['RR_ENABLED'] = '1'
            
        return env

    def start_service(self, mode: str, trace_file: Optional[str] = None, log_file: Optional[str] = None) -> subprocess.Popen:
        """Starts the target service in the specified mode"""
        env = self.get_execution_env(mode, trace_file)
        
        # Binary resolution
        orig_cmd = self.profile.start_command
        binary = orig_cmd[0]
        if not binary.startswith("/"):
            binary = str(Path(self.profile.rootfs_path) / binary)
            
        cmd = [self.qemu_path, "-L", self.profile.rootfs_path, binary] + orig_cmd[1:]
        
        self.logger.info(f"Starting target ({mode}): {' '.join(cmd)}")
        
        stdout = open(log_file, "w") if log_file else subprocess.DEVNULL
        self.current_process = subprocess.Popen(cmd, env=env, stdout=stdout, stderr=stdout)
        return self.current_process

    def stop_service(self, timeout: int = 5):
        """Safely stops the target service"""
        if not self.current_process:
            return
            
        self.logger.info("Stopping target service...")
        self.current_process.send_signal(signal.SIGINT)
        try:
            self.current_process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.current_process.kill()
            self.current_process.wait()
        
        self.current_process = None

    def check_health(self) -> bool:
        """Checks if the service is responsive (e.g., via network probe)"""
        if self.profile.target_port:
            import socket
            try:
                with socket.create_connection(("127.0.0.1", self.profile.target_port), timeout=1):
                    return True
            except:
                return False
        return True # Default to True if no port defined
