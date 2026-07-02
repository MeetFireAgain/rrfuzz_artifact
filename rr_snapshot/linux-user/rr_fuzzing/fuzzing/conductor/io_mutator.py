#!/usr/bin/env python3
"""
IO Return Value Mutator - Specialized for mutating return values of IO syscalls

This mutator addresses a critical issue:
- Programs like buffer_overflow have branches that depend on the size of read()'s return value
- Current random mutation only modifies arguments, not return values
- Need to generate targeted return values to trigger different branches

Author: RR-Fuzz Team
Date: 2025-11-14
"""

import random
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

try:
    from .async_logger import alog
except ImportError:
    # Fallback if accessed via direct script run or path issues
    def alog(msg, *args, **kwargs):
        print(f"[{args[0] if args else 'LOG'}] {msg}")


@dataclass
class IOMutation:
    """Mutation for an IO system call"""
    syscall_index: int
    mutation_type: str
    new_return_value: int
    buffer_content: Optional[bytes] = None
    description: str = ""


class IOReturnValueMutator:
    """IO Return Value Mutator

    Core functionality:
    1. Identify IO syscalls (read, write, recv, send, etc.)
    2. Generate targeted return value mutations
    3. Generate test cases for different return value ranges
    """

    def __init__(self):
        self.io_syscall_names = [
            'read', 'write', 'recv', 'send', 'recvfrom',
            'sendto', 'recvmsg', 'sendmsg', 'getrandom',
            'pread64', 'pwrite64', 'readv', 'writev',
            'preadv', 'pwritev', 'sendmmsg', 'recvmmsg'
        ]

        # Typical return value strategies
        self.return_value_strategies = {
            'boundary': [0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257],
            'powers_of_2': [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096],
            'incremental': list(range(0, 100, 5)),  # 0, 5, 10, 15, ..., 95
            # Aggressive overflow values including boundary-adjacent and large offsets
            'buffer_overflow': [
                # Near 32-byte boundary (catches off-by-one)
                30, 31, 32, 33, 34,
                # Near 64-byte boundary
                62, 63, 64, 65, 66,
                # Near 128-byte boundary
                126, 127, 128, 129, 130,
                # Obvious overflow range
                45, 50, 55, 60, 70, 80, 90, 100,
                # Large overflow
                150, 200, 250, 256, 300, 400, 500, 512, 600, 700, 800, 900, 1000,
                # Extreme values
                1024, 2048, 4096
            ],
            'error_injection': [-1, -2, -9, -13, -14, -32, -104, -111] # EPERM, EIO, EBADF, EACCES, EFAULT, EPIPE, ECONNRESET, ECONNREFUSED
        }

    def identify_io_syscalls(self, trace, analyzer: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Identify IO syscalls in the trace

        Args:
            trace: Trace object containing file_path
            analyzer: Existing TraceAnalyzer instance (optional)

        Returns:
            List of IO syscall information
        """
        io_syscalls = []

        # Parse trace file to retrieve syscall sequence
        if not analyzer:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent / "analysis"))
            import trace_analyzer
            # Parse trace file
            analyzer = trace_analyzer.TraceAnalyzer(trace.file_path)

        if not analyzer or not analyzer.syscalls:
            return io_syscalls

        for idx, syscall in enumerate(analyzer.syscalls):
            # Access record attributes
            syscall_name = getattr(syscall, 'name', '')
            if syscall_name in self.io_syscall_names:
                retval = getattr(syscall, 'retval', 0)

                # Filter read() calls that are likely not user inputs
                # Heuristic rules:
                # The 200-byte limit was harmful. Removed to allow fuzzing deep protocol logic.
                # Heuristic: only skip if it's explicitly identified as a library file by Mutator's FD tracking.
                # (But here we don't have the map yet, so we allow all and let Mutator.mutate filter if needed)
                pass

                io_syscalls.append({
                    'index': idx,
                    'name': syscall_name,
                    'original_return': retval,
                    'is_input': syscall_name in ['read', 'recv', 'recvfrom', 'recvmsg', 'getrandom']
                })

        return io_syscalls

    def generate_mutations_for_io(
        self,
        io_syscall: Dict[str, Any],
        strategy: str = 'buffer_overflow'
    ) -> List[IOMutation]:
        """Generate mutations for a single IO syscall

        Args:
            io_syscall: IO syscall information
            strategy: Mutation strategy ('boundary', 'powers_of_2', 'incremental', 'buffer_overflow')

        Returns:
            List of IOMutation objects
        """
        mutations = []
        syscall_index = io_syscall['index']
        syscall_name = io_syscall['name']
        original_return = io_syscall['original_return']

        # Select return value strategy
        if strategy in self.return_value_strategies:
            return_values = self.return_value_strategies[strategy]
        else:
            return_values = self.return_value_strategies['boundary']

        # For input syscalls (read, recv, etc.), generate corresponding buffer content
        is_input = io_syscall['is_input']

        for new_ret in return_values:
            # Skip entries that match the original return value
            if new_ret == original_return:
                continue

            # Generate buffer content (for input syscalls)
            buffer_content = None
            if is_input and new_ret > 0:
                # Generate buffer of specified size
                # Use various fill patterns
                fill_patterns = [
                    b'A' * new_ret,  # All A's
                    b'B' * new_ret,  # All B's
                    bytes(range(256)) * (new_ret // 256 + 1),  # Incrementing pattern
                    bytes([random.randint(0, 255) for _ in range(new_ret)])  # Random
                ]
                buffer_content = random.choice(fill_patterns)[:new_ret]

            mutation = IOMutation(
                syscall_index=syscall_index,
                mutation_type='io_return_value',
                new_return_value=new_ret,
                buffer_content=buffer_content,
                description=f"{syscall_name} @{syscall_index}: ret {original_return}->{new_ret}"
            )
            mutations.append(mutation)

        return mutations

    def generate_all_mutations(
        self,
        trace,
        max_mutations_per_io: int = 10,
        analyzer: Optional[Any] = None
    ) -> List[IOMutation]:
        """Generate mutations for all IO syscalls in the trace

        Args:
            trace: Trace object
            max_mutations_per_io: Maximum mutations per IO syscall
            analyzer: Existing TraceAnalyzer instance (optional)

        Returns:
            List of IOMutation objects
        """
        all_mutations = []

        # Identify IO syscalls
        io_syscalls = self.identify_io_syscalls(trace, analyzer=analyzer)

        if not io_syscalls:
            return all_mutations

        # Generate mutations for each IO syscall
        for io_syscall in io_syscalls:
            # Select strategy based on syscall type
            if io_syscall['name'] in ['read', 'recv', 'recvfrom']:
                # Read syscalls - use buffer_overflow strategy
                mutations = self.generate_mutations_for_io(io_syscall, 'buffer_overflow')
            else:
                # Other IO syscalls - use boundary strategy
                mutations = self.generate_mutations_for_io(io_syscall, 'boundary')

            # Randomly mix in error injection strategy
            if random.random() < 0.3: # 30% chance to also inject errors
                mutations.extend(self.generate_mutations_for_io(io_syscall, 'error_injection'))

            # Limit the number of mutations per IO syscall
            if len(mutations) > max_mutations_per_io:
                mutations = random.sample(mutations, max_mutations_per_io)

            all_mutations.extend(mutations)

        return all_mutations

    def prioritize_mutations(
        self,
        mutations: List[IOMutation],
        coverage_feedback: Optional[Dict] = None
    ) -> List[IOMutation]:
        """Prioritize mutations

        Args:
            mutations: List of mutations
            coverage_feedback: Coverage feedback (optional)

        Returns:
            Sorted list of mutations
        """
        # Employ diverse strategies for testing various return value sizes
        #
        # Strategy: group mutations, randomly select from each group to ensure all ranges are covered
        #
        # Groups:
        # 1. Small values (0-20): test boundaries, negatives, etc.
        # 2. Medium values (20-70): near buffer boundary
        # 3. Large values (70-200): obvious overflow
        # 4. Very large values (200+): extreme overflow

        def priority_score(m: IOMutation) -> int:
            val = m.new_return_value

            # Use random offset to ensure diversity
            base_score = random.randint(0, 30)

            # Assign base score based on value range (ensure every range has a chance)
            if val == 0 or val == 1:
                # Boundary values - always high priority
                return 200 + base_score
            elif 1 < val <= 20:
                # Small value range
                return 100 + base_score
            elif 20 < val <= 70:
                # Medium value range (near buffer size)
                return 150 + base_score
            elif 70 < val <= 200:
                # Large value range (obvious overflow)
                return 180 + base_score
            elif val < 0:
                # Error injection - high priority!
                return 190 + base_score
            else:
                # Very large values (extreme overflow)
                return 160 + base_score

        return sorted(mutations, key=priority_score, reverse=True)


# Convenience function: compatible with existing mutator interface

def generate_io_mutations(trace, max_mutations: int = 50) -> List[Dict[str, Any]]:
    """Generate IO mutations (compatible with existing interface)

    Args:
        trace: Trace object
        max_mutations: Maximum number of mutations

    Returns:
        List of mutation dictionaries (compatible with existing mutator format)
    """
    mutator = IOReturnValueMutator()

    # Generate all mutations
    io_mutations = mutator.generate_all_mutations(trace, max_mutations_per_io=10)

    # Sort by priority
    io_mutations = mutator.prioritize_mutations(io_mutations)

    # Limit total count
    if len(io_mutations) > max_mutations:
        io_mutations = io_mutations[:max_mutations]

    # Convert to dictionary format (compatible with existing interface)
    result = []
    for m in io_mutations:
        mut_dict = {
            'type': 'io_return_value',
            'syscall_index': m.syscall_index,
            'new_return_value': m.new_return_value,
            'description': m.description
        }

        if m.buffer_content:
            mut_dict['buffer_content'] = m.buffer_content

        result.append(mut_dict)

    return result


if __name__ == '__main__':
    # Test code
    print("IO Return Value Mutator")
    print("=" * 60)

    # Simulate a simple trace
    class MockSyscall:
        def __init__(self, name, ret):
            self.name = name
            self.ret = ret

    class MockTrace:
        def __init__(self):
            self.syscalls = [
                MockSyscall('brk', 0),
                MockSyscall('read', 11),  # seed trace: read returns 11 bytes
                MockSyscall('write', 11),
                MockSyscall('close', 0)
            ]

    trace = MockTrace()

    # Test mutator
    mutator = IOReturnValueMutator()

    print("1. Identify IO syscalls:")
    io_syscalls = mutator.identify_io_syscalls(trace)
    for io in io_syscalls:
        print(f"  - {io}")
    print()

    print("2. Generate mutations:")
    mutations = mutator.generate_all_mutations(trace, max_mutations_per_io=8)
    print(f"  Generated {len(mutations)} mutations")
    for i, m in enumerate(mutations[:5]):
        print(f"  [{i+1}] {m.description}")
    print()

    print("3. Priority ordering:")
    mutations = mutator.prioritize_mutations(mutations)
    print(f"  Top 5 mutations after sorting:")
    for i, m in enumerate(mutations[:5]):
        print(f"  [{i+1}] {m.description} (ret={m.new_return_value})")
