#!/usr/bin/env python3
"""
SyscallBlock - Syscall Block Data Structure

SyscallBlock represents all basic blocks between one syscall execution point
and the next. Used for syscall-level control flow analysis in dual-level CFG architecture.
"""

from typing import List, Dict, Any, Optional


class SyscallBlock:
    """Represents a syscall execution block"""

    def __init__(self, syscall_index: int, syscall_name: str):
        """
        Args:
            syscall_index: Index in the trace
            syscall_name: Syscall name (e.g., "read", "write")
        """
        self.syscall_index = syscall_index
        self.syscall_name = syscall_name

        # All contained BBs
        self.bb_addrs: List[int] = []

        # Syscall argument info
        self.syscall_args: Dict[str, Any] = {}
        self.syscall_retval: int = 0

        # Control flow info
        self.successors: List['SyscallBlock'] = []  # Successor syscall blocks
        self.predecessors: List['SyscallBlock'] = []

        # Coverage info
        self.is_covered: bool = False
        self.execution_count: int = 0

    def contains_bb(self, bb_addr: int) -> bool:
        """Check if contains a specific BB"""
        return bb_addr in self.bb_addrs

    def add_bb(self, bb_addr: int):
        """Add a BB to this syscall block"""
        if bb_addr not in self.bb_addrs:
            self.bb_addrs.append(bb_addr)

    def add_successor(self, successor: 'SyscallBlock'):
        """Add successor block"""
        if successor not in self.successors:
            self.successors.append(successor)

    def add_predecessor(self, predecessor: 'SyscallBlock'):
        """Add predecessor block"""
        if predecessor not in self.predecessors:
            self.predecessors.append(predecessor)

    def __repr__(self) -> str:
        return (f"SyscallBlock(idx={self.syscall_index}, "
                f"name={self.syscall_name}, bbs={len(self.bb_addrs)}, "
                f"covered={self.is_covered})")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (for serialization)"""
        return {
            'syscall_index': self.syscall_index,
            'syscall_name': self.syscall_name,
            'bb_count': len(self.bb_addrs),
            'bb_addrs': self.bb_addrs,
            'syscall_args': self.syscall_args,
            'syscall_retval': self.syscall_retval,
            'is_covered': self.is_covered,
            'execution_count': self.execution_count,
            'successors': [s.syscall_index for s in self.successors],
            'predecessors': [p.syscall_index for p in self.predecessors],
        }
