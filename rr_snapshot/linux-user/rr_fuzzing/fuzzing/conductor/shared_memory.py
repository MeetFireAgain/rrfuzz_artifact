#!/usr/bin/env python3
"""
FuzzSharedMemory - Shared Memory Management

This module manages the shared memory region used for IPC between the
Python fuzzing conductor and the QEMU process.

The shared memory layout matches the C-side structure:
    - Header: magic, sequence, count, checksum, flags, reserved
    - Instructions: array of FuzzInstruction
"""

import os
import mmap
import struct
from pathlib import Path
from typing import List
from .constants import (
    FUZZ_MAGIC, FUZZ_MAX_INSTRUCTIONS, FUZZ_MAX_VARIANTS, FUZZ_SHM_SIZE,
    FUZZ_FLAG_CAPTURE_SEED
)


class FuzzSharedMemory:
    """Shared Memory Manager"""
    
    def __init__(self, shm_name, size=FUZZ_SHM_SIZE, fallback_dir: str = None):
        # Ensure shm_name doesn't contain /dev/shm/ prefix
        # QEMU's shm_open() expects just the name, not the full path
        if shm_name.startswith("/dev/shm/"):
            shm_name = shm_name[9:]  # Remove "/dev/shm/" prefix
        elif shm_name.startswith("/"):
            shm_name = shm_name[1:]  # Remove leading "/"
        
        self.shm_name = shm_name
        self.shm_path = f"/dev/shm/{shm_name}"
        self.size = size
        self.shm_fd = None
        self.mem = None
        self.sequence = 0  # Sequence number counter
        self.mode = "posix"  # posix | file
        self.fallback_path: Path = None
        self._fallback_dir = Path(
            fallback_dir
            or os.environ.get("RR_SHM_FALLBACK_DIR")
            or (Path.cwd() / ".rr_shm_fallback")
        )
    
    def create(self):
        """Create shared memory"""
        # Use /dev/shm (Linux shared memory)
        # Use self.shm_path instead of recreating it
        
        try:
            # Create or open shared memory file
            self.shm_fd = os.open(self.shm_path, os.O_CREAT | os.O_RDWR, 0o666)
            os.ftruncate(self.shm_fd, self.size)
            
            # Map to memory
            self.mem = mmap.mmap(self.shm_fd, self.size)
            
            print(f"[Conductor] Created shared memory: {self.shm_path} ({self.size} bytes)")
            print(f"[Conductor] Shared memory name for QEMU: {self.shm_name}")
            self.mode = "posix"
        except PermissionError:
            # Sandboxed environments may forbid /dev/shm writes; fall back to file-backed mmap.
            self._create_file_backed_region()
        return self

    def _create_file_backed_region(self):
        """Create a regular file based shared memory fallback"""
        self.mode = "file"
        self._fallback_dir.mkdir(parents=True, exist_ok=True)
        self.fallback_path = (self._fallback_dir / f"{self.shm_name}.bin").resolve()
        fd = os.open(self.fallback_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.ftruncate(fd, self.size)
        self.shm_fd = fd
        self.mem = mmap.mmap(self.shm_fd, self.size)
        print(f"[Conductor] ⚠️  /dev/shm unavailable, using file-backed shared memory: {self.fallback_path}")

    def get_env_value(self) -> str:
        """Value to be passed via RR_SHARED_MEMORY for QEMU side."""
        if self.mode == "file" and self.fallback_path:
            return f"file:{self.fallback_path}"
        return self.shm_name
    
    def write_fork_request(self, 
                          fork_point: int = 0,
                          mutation_variants: List[List] = None,
                          depth: int = 0,
                          iteration_id: int = 0):
        """
        Unified fork request writing method (replaces all legacy methods)
        
        Args:
            fork_point: 0=start from beginning, N=mid-point fork
            mutation_variants: None/empty=single execution, [v1,v2,...]=batch fork
            depth: Nesting depth (0=top-level, 1=level-1 nesting, ...)
            iteration_id: Current iteration number (for Visualizer)
        
        Scenario Mapping:
            - Legacy write_instructions: fork_request(fork_point=0, variants=[[inst1,inst2]], depth=0)
            - Legacy write_batch_variants: fork_request(fork_point=0, variants=[v1,v2,v3], depth=0)
            - Legacy write_checkpoint_variants: fork_request(fork_point=N, variants=[v1,v2,v3], depth=0)
            - Nested fork: fork_request(fork_point=N, variants=[v1,v2,v3], depth=1)
        """
        if not self.mem:
            raise RuntimeError("Shared memory not created")
        
        if mutation_variants is None:
            mutation_variants = [[]]  # Empty mutation list

        num_variants = len(mutation_variants)

        # ✅ Boundary check 1: Check if number of variants exceeds limit
        if num_variants > FUZZ_MAX_VARIANTS:
            raise ValueError(
                f"Too many variants: {num_variants} (max {FUZZ_MAX_VARIANTS}). "
                f"This would overflow FuzzSharedMemory.variants[{FUZZ_MAX_VARIANTS}] array."
            )

        # ✅ Boundary check 2: Check if instruction count per variant exceeds limit
        for i, instructions in enumerate(mutation_variants):
            if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
                raise ValueError(
                    f"Variant {i} has too many instructions: {len(instructions)} "
                    f"(max {FUZZ_MAX_INSTRUCTIONS}). "
                    f"This would overflow FuzzVariant.instructions[{FUZZ_MAX_INSTRUCTIONS}] array."
                )
        
        # Increment sequence
        self.sequence += 1
        
        # Checksum
        checksum = FUZZ_MAGIC ^ self.sequence ^ num_variants ^ fork_point ^ depth
        
        # Calculate structure sizes and offsets
        # FuzzInstruction packing format: IIIIII4096s (24 + 4096 = 4120 bytes)
        inst_pack_format = 'IIIIII4096s'
        inst_size = struct.calcsize(inst_pack_format)
        
        # Header layout in C:
        # magic(4), sequence(4), num_variants(4), checksum(4), iteration_id(4), reserved_1(4),
        # fork_point(4), current_depth(4), reserved_2(4) = 36 bytes
        header_base_size = 36 
        
        # FuzzVariant layout in C:
        # instruction_count(4) + PADDING(4) + crash_pc(8) + instructions[16](16 * 4120) 
        # = 16 + 65920 = 65936 bytes (8-byte aligned)
        variant_struct_size = 16 + FUZZ_MAX_INSTRUCTIONS * inst_size
        
        # FuzzSharedMemory layout:
        # Header(36) + instructions[16](65920) + PADDING(4) + variants[5](variants array)
        # Note: PADDING(4) is needed to align 'variants' array on 8-byte boundary due to uint64_t in FuzzVariant
        variant_array_offset = header_base_size + FUZZ_MAX_INSTRUCTIONS * inst_size + 4
        
        # Prepare header parts
        header_part1 = struct.pack('III', FUZZ_MAGIC, self.sequence, num_variants)
        header_part2 = struct.pack('IIIII', iteration_id, 0, fork_point, depth, 0)
        
        # 1. First write variant data
        for variant_idx, instructions in enumerate(mutation_variants):
            variant_offset = variant_array_offset + variant_idx * variant_struct_size
            self.mem.seek(variant_offset)
            # Write instruction_count (4 bytes)
            self.mem.write(struct.pack('I', len(instructions)))
            
            # Clear crash_pc (8 bytes, at offset 8)
            self.mem.seek(variant_offset + 8)
            self.mem.write(struct.pack('Q', 0))
            
            inst_sub_offset = variant_offset + 16 # Instructions start at offset 16
            for inst in instructions:
                self.mem.seek(inst_sub_offset)
                self.mem.write(inst.pack())
                inst_sub_offset += inst_size
        
        # 2. Write non-checksum parts of Header
        self.mem.seek(0)
        self.mem.write(header_part1)
        self.mem.seek(16) # skip checksum(12-16)
        self.mem.write(header_part2)
        
        # 3. Ensure data is flushed to memory
        self.mem.flush()
        
        # 4. Finally write checksum as "commit" operation
        self.mem.seek(12)
        self.mem.write(struct.pack('I', checksum))
        self.mem.flush()
        
        print(f"[SharedMemory] Fork request: fork_point={fork_point}, "
              f"variants={num_variants}, depth={depth}, iteration={iteration_id}")
        for i, variant in enumerate(mutation_variants):
            if variant:  # only print non-empty variants
                print(f"  Variant {i}: {len(variant)} instructions")

    def read_crash_pc(self, variant_idx: int) -> int:
        """
        Read the crash PC for a specific variant.
        
        Args:
            variant_idx: Variant index
            
        Returns:
            Program counter (int)
        """
        if not self.mem:
            return 0
            
        # Offset calculation must match write_fork_request
        inst_pack_format = 'IIIIII4096s'
        inst_size = struct.calcsize(inst_pack_format)
        header_base_size = 36
        variant_array_offset = header_base_size + FUZZ_MAX_INSTRUCTIONS * inst_size + 4
        variant_struct_size = 16 + FUZZ_MAX_INSTRUCTIONS * inst_size
        
        # PC is at offset 8 within FuzzVariant
        pc_offset = variant_array_offset + (variant_idx * variant_struct_size) + 8
        
        try:
            self.mem.seek(pc_offset)
            pc_bytes = self.mem.read(8)
            return struct.unpack('Q', pc_bytes)[0]
        except Exception as e:
            print(f"[SharedMemory] Failed to read crash PC: {e}")
            return 0
            
    def clear_crash_pc(self, variant_idx: int):
        """Clear crash PC for a variant"""
        if not self.mem:
            return
            
        inst_pack_format = 'IIIIII4096s'
        inst_size = struct.calcsize(inst_pack_format)
        header_base_size = 36
        variant_array_offset = header_base_size + FUZZ_MAX_INSTRUCTIONS * inst_size + 4
        variant_struct_size = 16 + FUZZ_MAX_INSTRUCTIONS * inst_size
        
        pc_offset = variant_array_offset + (variant_idx * variant_struct_size) + 8
        
        try:
            self.mem.seek(pc_offset)
            self.mem.write(struct.pack('Q', 0))
        except:
            pass
    
    def close(self):
        """Close shared memory"""
        try:
            if self.mem:
                self.mem.close()
                self.mem = None
        except:
            pass
        
        try:
            if self.shm_fd:
                os.close(self.shm_fd)
                self.shm_fd = None
        except:
            pass
        
    def unlink(self):
        """Remove backing file (if any)"""
        target = None
        if self.mode == "file" and self.fallback_path:
            target = str(self.fallback_path)
        elif self.mode == "posix":
            target = self.shm_path
        
        if not target:
            return
        
        try:
            if os.path.exists(target):
                os.unlink(target)
        except FileNotFoundError:
            pass
        except Exception as exc:
            print(f"[Conductor] ⚠️  Failed to unlink shared memory '{target}': {exc}")
            
    @staticmethod
    def cleanup_orphaned_shm():
        """
        Scan /dev/shm for orphaned rr_fuzz_* and rr_coverage_* files.
        Removes them if the associated PID is no longer running.
        """
        import glob
        import re
        
        shm_patterns = ["/dev/shm/rr_fuzz_*", "/dev/shm/rr_coverage_*"]
        removed_count = 0
        
        for pattern in shm_patterns:
            for shm_path in glob.glob(pattern):
                try:
                    # Extract PID from filename (e.g., rr_fuzz_1234_...)
                    match = re.search(r'_(?P<pid>\d+)(?:_|$)', os.path.basename(shm_path))
                    if match:
                        pid = int(match.group('pid'))
                        
                        # Check if PID is alive
                        try:
                            os.kill(pid, 0)
                        except OSError:
                            # PID is dead, safe to remove
                            print(f"[Cleanup] Removing orphaned SHM: {shm_path} (PID {pid} is dead)")
                            os.unlink(shm_path)
                            removed_count += 1
                except Exception as e:
                    print(f"[Cleanup] Error checking {shm_path}: {e}")
                    
        if removed_count > 0:
            print(f"[Cleanup] Successfully removed {removed_count} orphaned SHM objects.")
        return removed_count

    def __del__(self):
        """Ensure resources are released on object destruction"""
        try:
            self.close()
        except:
            pass
