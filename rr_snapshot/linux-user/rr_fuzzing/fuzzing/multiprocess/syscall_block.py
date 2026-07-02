#!/usr/bin/env python3
"""
SyscallBlock - Syscall block data structure

SyscallBlock represents all basic blocks between one syscall execution point
and the next syscall execution point. Used for syscall-level control-flow
analysis in the dual-level CFG architecture.
"""

from typing import List, Dict, Any, Optional


class SyscallBlock:
    """表示一个syscall执行块"""

    def __init__(self, syscall_index: int, syscall_name: str):
        """
        Args:
            syscall_index: 在trace中的索引
            syscall_name: 系统调用名称（如 "read", "write"）
        """
        self.syscall_index = syscall_index
        self.syscall_name = syscall_name

        # 包含的所有BBs
        self.bb_addrs: List[int] = []

        # syscall参数信息
        self.syscall_args: Dict[str, Any] = {}
        self.syscall_retval: int = 0

        # 控制流信息
        self.successors: List['SyscallBlock'] = []  # 后继syscall blocks
        self.predecessors: List['SyscallBlock'] = []

        # 覆盖率信息
        self.is_covered: bool = False
        self.execution_count: int = 0

    def contains_bb(self, bb_addr: int) -> bool:
        """检查是否包含某个BB"""
        return bb_addr in self.bb_addrs

    def add_bb(self, bb_addr: int):
        """添加一个BB到此syscall block"""
        if bb_addr not in self.bb_addrs:
            self.bb_addrs.append(bb_addr)

    def add_successor(self, successor: 'SyscallBlock'):
        """添加后继block"""
        if successor not in self.successors:
            self.successors.append(successor)

    def add_predecessor(self, predecessor: 'SyscallBlock'):
        """添加前驱block"""
        if predecessor not in self.predecessors:
            self.predecessors.append(predecessor)

    def __repr__(self) -> str:
        return (f"SyscallBlock(idx={self.syscall_index}, "
                f"name={self.syscall_name}, bbs={len(self.bb_addrs)}, "
                f"covered={self.is_covered})")

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于序列化）"""
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
