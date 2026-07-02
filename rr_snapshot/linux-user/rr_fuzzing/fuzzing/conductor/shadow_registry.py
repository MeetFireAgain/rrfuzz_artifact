#!/usr/bin/env python3
"""
ShadowRegistry - Resource Dependency Tracker for RR-Fuzz

Tracks system resources (File Descriptors, Socket types, Memory regions)
during trace analysis and provides valid resource candidates for mutation.
"""

import random
from typing import List, Dict, Set, Optional, Any
try:
    from .async_logger import alog
except ImportError:
    from async_logger import alog

class ShadowRegistry:
    """
    Manages a "Shadow State" of resources found in the trace.
    Helps Mutator avoid generating invalid resources (e.g., -EBADF).
    """
    
    def __init__(self):
        # Resource pools
        self.active_fds: Dict[int, Dict[str, Any]] = {} # fd -> metadata
        self.all_found_fds: Set[int] = {0, 1, 2} # Standard IO
        
        # Metadata examples: {'filename': '...', 'type': 'socket', 'index': 123}
        
    def register_syscall(self, sc_info: Any):
        """
        Incrementally update the registry based on a syscall.
        Should be called while iterating through the trace.
        """
        # 1. Handle FD creation
        if getattr(sc_info, 'creates_fd', False) and sc_info.created_fd > 2:
            fd = sc_info.created_fd
            metadata = {
                'name': sc_info.name,
                'index': sc_info.index,
                'filename': self._extract_filename(sc_info)
            }
            self.active_fds[fd] = metadata
            self.all_found_fds.add(fd)
            
        # 2. Handle FD closing
        elif sc_info.name == 'close' and sc_info.args:
            fd = sc_info.args[0]
            if fd in self.active_fds:
                del self.active_fds[fd]
                
    def _extract_filename(self, sc_info: Any) -> str:
        """Extract filename from syscall arg_data if available."""
        if sc_info.name in ['open', 'openat']:
            idx = 1 if sc_info.name == 'openat' else 0
            if hasattr(sc_info, 'arg_data') and idx in sc_info.arg_data:
                try:
                    data = sc_info.arg_data[idx]
                    return data.split(b'\x00')[0].decode('utf-8', errors='ignore')
                except:
                    return "unknown"
        return "unknown"

    def get_random_valid_fd(self, exclude_stdlib: bool = True) -> int:
        """
        Returns a random currently active and valid FD.
        If no FDs are active, falls back to standard IO (0, 1, 2).
        """
        choices = list(self.active_fds.keys())
        
        if exclude_stdlib:
            choices = [fd for fd in choices if not self._is_stdlib_fd(fd)]
            
        if not choices:
            # Fallback to standard IO or 3 (first non-std FD)
            return random.choice([0, 1, 2])
            
        return random.choice(choices)
    
    def _is_stdlib_fd(self, fd: int) -> bool:
        """Check if an FD belongs to a system library or runtime file."""
        meta = self.active_fds.get(fd)
        if not meta:
            return False
        filename = meta.get('filename', '')
        return any(lib in filename for lib in ["/lib/", "/usr/lib/", "ld.so.cache"])

    def is_fd_valid(self, fd: int) -> bool:
        """Check if an FD is currently active in the shadow registry."""
        return fd in self.active_fds or fd in {0, 1, 2}

    def sync_to_index(self, syscalls: List[Any], target_index: int):
        """
        Replay trace up to target_index to synchronize the shadow state.
        Args:
            syscalls: List of SyscallRecord objects from trace.
            target_index: The index to synchronize up to (inclusive).
        """
        self.reset()
        for sc in syscalls:
            if sc.index > target_index:
                break
            self.register_syscall(sc)
            
    def get_active_fds(self) -> List[int]:
        """Returns a list of currently active FD numbers."""
        return list(self.active_fds.keys())

    def reset(self):
        """Clear the registry."""
        self.active_fds.clear()
        self.all_found_fds = {0, 1, 2}
