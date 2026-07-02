#!/usr/bin/env python3
"""
Fuzzing Core Data Types

This module defines standardized dataclasses for core fuzzing concepts,
replacing ad-hoc dictionaries and loose classes to improve type safety
and maintainability.
"""

from dataclasses import dataclass, field
from typing import Optional, Union, Any, List
import struct
try:
    from .constants import FUZZ_INSTRUCTION_DATA
except ImportError:
    from constants import FUZZ_INSTRUCTION_DATA

@dataclass
class MutationRecipe:
    """
    Represents a specific mutation strategy derived from trace analysis or PathFinder.
    Typically used to guide the Mutator to perform specific actions.
    """
    # The source of the transition (e.g., branch address)
    source_branch: int
    
    # The target destination (e.g., target branch address)
    target_branch: int
    
    # The system call index in the trace where this mutation should occur
    syscall_index: int
    
    # The type of mutation to apply (e.g., 'flip_branch', 'force_path')
    mutation_type: str
    
    # Optional human-readable description
    description: str = ""
    
    # Priority of this recipe (higher is more important)
    priority: int = 10
    
    def to_dict(self) -> dict:
        """Convert back to dictionary for legacy compatibility if needed."""
        return {
            'source_branch': self.source_branch,
            'target_branch': self.target_branch,
            'syscall_index': self.syscall_index,
            'mutation_type': self.mutation_type,
            'description': self.description,
            'priority': self.priority
        }

@dataclass
class FuzzInstruction:
    """
    Represents a single fuzzing instruction sent to the QEMU engine via shared memory.
    
    Matches the C-side structure in rr_framework.h:
    typedef struct {
        fuzz_cmd_type_t cmd;        // uint32
        uint32_t syscall_index;     // uint32
        uint32_t arg_index;         // uint32
        uint32_t offset;            // uint32
        uint32_t size;              // uint32
        uint32_t data_len;          // uint32
        uint8_t data[4096];         // 🔥 Updated to 4K
    } FuzzInstruction;
    """
    syscall_index: int
    cmd: int
    arg_index: int
    data: Union[bytes, int]
    offset: int = 0
    size: Optional[int] = None
    mutation_type: str = 'unknown' # Metadata for tracking, not packed
    
    def __post_init__(self):
        """Ensure consistency after initialization."""
        if self.size is None:
            if isinstance(self.data, bytes):
                self.size = len(self.data)
            else:
                self.size = 8  # Default for integer types (packed as q/Q)

    def pack(self) -> bytes:
        """
        Pack into binary format matching the C struct.
        Returns 4120 bytes.
        """
        data_bytes = self.data if isinstance(self.data, bytes) else struct.pack('q', self.data)
        data_len = len(data_bytes)
        
        # Pad to 4096 bytes (FUZZ_INSTRUCTION_DATA)
        padded_data = data_bytes + b'\x00' * (FUZZ_INSTRUCTION_DATA - data_len)
        
        # Pack fields matches C struct order:
        # cmd, syscall_index, arg_index, offset, size, data_len, data
        return struct.pack('IIIIII4096s', 
                          self.cmd,
                          self.syscall_index,
                          self.arg_index,
                          self.offset,
                          self.size,
                          data_len,
                          padded_data)

    @property
    def struct_size(self) -> int:
        """Returns the fixed size of the C structure (4120 bytes)."""
        return 24 + 4096
