#!/usr/bin/env python3
"""
AFL Enhanced Mutator - AFL-style systematic mutation
Adds AFL core concepts on top of the existing SmartMutator
"""

import os
import struct
import random
from typing import List, Dict, Any, Optional, Tuple
try:
    from .mutator import SmartMutator
    from .instruction import FuzzInstruction
    from .constants import *
except ImportError:
    # Standalone/Test mode
    from mutator import SmartMutator
    from instruction import FuzzInstruction
    from constants import *
import subprocess
import re

class AFLStage:
    """AFL mutation stage enumeration"""
    BITFLIP_1_1 = "bitflip_1_1"     # Flip every 1 bit
    BITFLIP_2_1 = "bitflip_2_1"     # Flip every 2 bits
    BITFLIP_4_1 = "bitflip_4_1"     # Flip every 4 bits
    BITFLIP_8_8 = "bitflip_8_8"     # Flip every byte
    BITFLIP_16_8 = "bitflip_16_8"   # Flip every 2 bytes
    BITFLIP_32_8 = "bitflip_32_8"   # Flip every 4 bytes

    ARITH_8 = "arith_8"             # 8-bit arithmetic
    ARITH_16 = "arith_16"           # 16-bit arithmetic
    ARITH_32 = "arith_32"           # 32-bit arithmetic

    INTEREST_8 = "interest_8"       # 8-bit interesting values
    INTEREST_16 = "interest_16"     # 16-bit interesting values
    INTEREST_32 = "interest_32"     # 32-bit interesting values

    EXTRAS_UO = "extras_uo"         # User-provided extras
    EXTRAS_AO = "extras_ao"         # Auto-extracted extras

    HAVOC = "havoc"                 # Random mutation (using existing strategies)
    SPLICE = "splice"               # Splice mode

class AFLEnhancedMutator(SmartMutator):
    """
    AFL Enhanced Mutator

    Core concepts:
    1. Preserve all advantages of SmartMutator (syscall semantics, argument correlation)
    2. Add AFL's systematic exploration stages
    3. Find the balance between AFL stages and smart mutation
    """

    def __init__(self, trace_file, recipe_file=None, target_binary=None, path_finder=None):
        super().__init__(trace_file, recipe_file, target_binary, path_finder)

        # AFL-related state
        self.afl_enabled = True
        self.current_stage = AFLStage.BITFLIP_1_1
        self.stage_progress = 0
        self.stage_max = 0
        self.stage_finds = 0  # Number of new paths found in this stage

        # AFL stage statistics
        self.stage_stats = {
            stage: {"executions": 0, "finds": 0, "time": 0.0}
            for stage in [
                AFLStage.BITFLIP_1_1, AFLStage.BITFLIP_2_1, AFLStage.BITFLIP_4_1,
                AFLStage.BITFLIP_8_8, AFLStage.BITFLIP_16_8, AFLStage.BITFLIP_32_8,
                AFLStage.ARITH_8, AFLStage.ARITH_16, AFLStage.ARITH_32,
                AFLStage.INTEREST_8, AFLStage.INTEREST_16, AFLStage.INTEREST_32,
                AFLStage.EXTRAS_UO, AFLStage.EXTRAS_AO,
                AFLStage.HAVOC, AFLStage.SPLICE
            ]
        }

        # AFL constants
        self.INTERESTING_8 = [
            -128, -1, 0, 1, 16, 32, 64, 100, 127
        ]

        self.INTERESTING_16 = [
            -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767
        ]

        self.INTERESTING_32 = [
            -2147483648, -100663046, -32769, 32768, 65535, 65536,
            100663045, 2147483647
        ]

        # Current seed data cache
        self.current_seed_data = None
        self.current_target_index = None

        # Dictionary data
        self.dictionary = []
        self._extract_dictionary_tokens(target_binary)

        print("[AFLMutator] ✅ Initialized with AFL-style systematic exploration")

    def mutate(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """
        Main mutation entry point, overrides SmartMutator's mutate method

        Args:
            trace: Trace object (unused, uses internal candidates)
            fork_point: Syscall index of fork point (optional)
        """
        # Get current iteration count (simplified: use some trace identifier)
        iteration = getattr(self, '_iteration_count', 0)
        self._iteration_count = iteration + 1

        return self.build_instructions_afl_enhanced(iteration, fork_point=fork_point)

    def build_instructions_afl_enhanced(self, iteration: int, fork_point: Optional[int] = None) -> List[FuzzInstruction]:
        """
        AFL-enhanced instruction building

        Strategy:
        1. First 80% of iterations: use AFL systematic exploration
        2. Last 20% of iterations: use SmartMutator's smart mutation
        3. Stagnant state: mix both methods
        """

        # Decide whether to use AFL or smart mutation
        use_afl = self._should_use_afl_stage(iteration)

        if use_afl and self.afl_enabled:
            return self._build_afl_instructions(iteration, fork_point)
        else:
            # Use original SmartMutator logic
            return super().build_instructions(iteration, fork_point)

    def _should_use_afl_stage(self, iteration: int) -> bool:
        """Determine whether to use AFL stage"""

        # Stagnant state: 50% AFL, 50% smart mutation
        if self.is_stagnant:
            return random.choice([True, False])

        # Early stage: primarily use AFL systematic exploration
        if iteration < 100:
            return random.random() < 0.8  # 80% AFL

        # Middle stage: balanced use
        elif iteration < 500:
            return random.random() < 0.6  # 60% AFL

        # Late stage: primarily use smart mutation
        else:
            return random.random() < 0.3  # 30% AFL

    def _filter_candidates_for_fork_point(self, fork_point: Optional[int]):
        """Filter candidates suitable for the current fork point"""
        # Simplified: return all candidates
        if hasattr(self, 'pure_candidates') and self.pure_candidates:
            return self.pure_candidates
        return []

    def _build_afl_instructions(self, iteration: int, fork_point: Optional[int] = None) -> List[FuzzInstruction]:
        """
        Build AFL-style instructions
        """

        # Select target candidate
        valid_candidates = self._filter_candidates_for_fork_point(fork_point)
        if not valid_candidates:
            print("[AFLMutator] ⚠️  No valid candidates for AFL mutation")
            return []

        # Randomly select one candidate as target
        target_candidate = random.choice(valid_candidates)
        self.current_target_index = target_candidate.index

        # Get seed data (simplified: use fixed seed)
        self.current_seed_data = self._get_seed_data_for_candidate(target_candidate)

        # Generate mutations based on current stage
        afl_instructions = []

        if self.current_stage.startswith("bitflip"):
            afl_instructions = self._generate_bitflip_instructions(target_candidate)
        elif self.current_stage.startswith("arith"):
            afl_instructions = self._generate_arithmetic_instructions(target_candidate)
        elif self.current_stage.startswith("interest"):
            afl_instructions = self._generate_interesting_instructions(target_candidate)
        elif self.current_stage == AFLStage.HAVOC:
            # Havoc stage: use existing smart mutation strategies
            afl_instructions = super().build_instructions(iteration, fork_point)
        elif self.current_stage == AFLStage.EXTRAS_AO:
             afl_instructions = self._generate_extras_ao_instructions(target_candidate)

        # Advance stage
        self._advance_afl_stage()

        return afl_instructions

    def _get_seed_data_for_candidate(self, candidate) -> bytes:
        """Get seed data for a candidate"""
        # Simplified implementation: return some base data
        if candidate.name in ['read', 'recv', 'recvfrom']:
            # Input-type syscalls: return typical input data
            return b"Hello, World! This is test input data for fuzzing."
        elif candidate.name in ['write', 'send', 'sendto']:
            # Output-type syscalls: return formatted data
            return b"Output data: %s %d %x"
        else:
            # Others: return generic data
            return b"AAAABBBBCCCCDDDD"

    def _generate_bitflip_instructions(self, target_candidate) -> List[FuzzInstruction]:
        """Generate bit-flip instructions (AFL core)"""
        instructions = []
        seed_data = self.current_seed_data

        if self.current_stage == AFLStage.BITFLIP_1_1:
            # 1/1 bit flip: flip every single bit
            instructions = self._bitflip_1_1(target_candidate, seed_data)
        elif self.current_stage == AFLStage.BITFLIP_2_1:
            # 2/1 bit flip: flip 2 consecutive bits
            instructions = self._bitflip_2_1(target_candidate, seed_data)
        elif self.current_stage == AFLStage.BITFLIP_4_1:
            # 4/1 bit flip: flip 4 consecutive bits
            instructions = self._bitflip_4_1(target_candidate, seed_data)
        elif self.current_stage == AFLStage.BITFLIP_8_8:
            # 8/8 bit flip: flip entire byte
            instructions = self._bitflip_8_8(target_candidate, seed_data)

        return instructions

    def _bitflip_1_1(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 1/1 bit flip"""
        instructions = []

        # Limit mutation count to avoid explosion (C-side FuzzVariant.instructions[32] limit)
        max_mutations = min(len(seed_data) * 8, 32)  # Max 32 mutations

        for bit_idx in range(max_mutations):
            byte_idx = bit_idx // 8
            bit_in_byte = bit_idx % 8

            if byte_idx >= len(seed_data):
                break

            # Create mutated data
            mutated_data = bytearray(seed_data)
            mutated_data[byte_idx] ^= (1 << bit_in_byte)

            # Create FLIP_BITS instruction (reuse existing instruction format)
            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_FLIP_BITS,
                arg_index=1,  # Usually the buffer argument
                data=bytes(mutated_data)
            )

            instructions.append(instruction)

        print(f"[AFLMutator] 🔀 Generated {len(instructions)} 1/1 bitflip mutations")
        return instructions

    def _bitflip_2_1(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 2/1 bit flip"""
        instructions = []
        max_mutations = min(len(seed_data) * 8 - 1, 32)

        for bit_idx in range(max_mutations):
            byte_idx = bit_idx // 8
            bit_in_byte = bit_idx % 8

            if byte_idx >= len(seed_data) or bit_in_byte >= 7:
                continue

            mutated_data = bytearray(seed_data)

            # Flip 2 consecutive bits
            mutated_data[byte_idx] ^= (3 << bit_in_byte)  # 3 = 0b11

            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_FLIP_BITS,
                arg_index=1,
                data=bytes(mutated_data)
            )

            instructions.append(instruction)

        print(f"[AFLMutator] 🔀 Generated {len(instructions)} 2/1 bitflip mutations")
        return instructions

    def _bitflip_4_1(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 4/1 bit flip"""
        instructions = []
        max_mutations = min(len(seed_data) * 8 - 3, 16)

        for bit_idx in range(max_mutations):
            byte_idx = bit_idx // 8
            bit_in_byte = bit_idx % 8

            if byte_idx >= len(seed_data) or bit_in_byte >= 5:
                continue

            mutated_data = bytearray(seed_data)

            # Flip 4 consecutive bits
            mutated_data[byte_idx] ^= (15 << bit_in_byte)  # 15 = 0b1111

            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_FLIP_BITS,
                arg_index=1,
                data=bytes(mutated_data)
            )

            instructions.append(instruction)

        print(f"[AFLMutator] 🔀 Generated {len(instructions)} 4/1 bitflip mutations")
        return instructions

    def _bitflip_8_8(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 8/8 bit flip (byte flip)"""
        instructions = []

        for byte_idx in range(min(len(seed_data), 32)):
            mutated_data = bytearray(seed_data)

            # Flip entire byte
            mutated_data[byte_idx] ^= 0xFF

            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_FLIP_BITS,
                arg_index=1,
                data=bytes(mutated_data)
            )

            instructions.append(instruction)

        print(f"[AFLMutator] 🔀 Generated {len(instructions)} 8/8 bitflip mutations")
        return instructions

    def _generate_arithmetic_instructions(self, target_candidate) -> List[FuzzInstruction]:
        """Generate arithmetic mutation instructions"""
        instructions = []
        seed_data = self.current_seed_data

        if self.current_stage == AFLStage.ARITH_8:
            instructions = self._arithmetic_8(target_candidate, seed_data)
        elif self.current_stage == AFLStage.ARITH_16:
            instructions = self._arithmetic_16(target_candidate, seed_data)
        elif self.current_stage == AFLStage.ARITH_32:
            instructions = self._arithmetic_32(target_candidate, seed_data)

        return instructions

    def _arithmetic_8(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 8-bit arithmetic mutation"""
        instructions = []

        for byte_idx in range(min(len(seed_data), 16)):
            original_byte = seed_data[byte_idx]

            # AFL arithmetic range: ±1 to ±35
            for delta in range(-35, 36):
                if delta == 0:
                    continue

                new_value = (original_byte + delta) & 0xFF
                if new_value == original_byte:
                    continue

                mutated_data = bytearray(seed_data)
                mutated_data[byte_idx] = new_value

                # Use INTERESTING_VALUES instruction
                instruction = FuzzInstruction(
                    syscall_index=target_candidate.index,
                    cmd=FUZZ_CMD_INTERESTING_VALUES,
                    arg_index=1,
                    data=struct.pack('B', new_value)
                )

                instructions.append(instruction)

        print(f"[AFLMutator] 🔢 Generated {len(instructions)} 8-bit arithmetic mutations")
        return instructions

    def _arithmetic_16(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 16-bit arithmetic mutation"""
        instructions = []

        for byte_idx in range(0, min(len(seed_data) - 1, 16), 2):
            # Little-endian and big-endian
            for endian in ['little', 'big']:
                original_value = int.from_bytes(
                    seed_data[byte_idx:byte_idx+2],
                    byteorder=endian
                )

                for delta in [-35, -1, 1, 35]:  # Simplified range
                    new_value = (original_value + delta) & 0xFFFF
                    if new_value == original_value:
                        continue

                    new_bytes = new_value.to_bytes(2, byteorder=endian)

                    instruction = FuzzInstruction(
                        syscall_index=target_candidate.index,
                        cmd=FUZZ_CMD_INTERESTING_VALUES,
                        arg_index=1,
                        data=new_bytes
                    )

                    instructions.append(instruction)

        print(f"[AFLMutator] 🔢 Generated {len(instructions)} 16-bit arithmetic mutations")
        return instructions

    def _arithmetic_32(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 32-bit arithmetic mutation"""
        instructions = []

        for byte_idx in range(0, min(len(seed_data) - 3, 8), 4):
            for endian in ['little', 'big']:
                original_value = int.from_bytes(
                    seed_data[byte_idx:byte_idx+4],
                    byteorder=endian
                )

                for delta in [-35, -1, 1, 35]:
                    new_value = (original_value + delta) & 0xFFFFFFFF
                    if new_value == original_value:
                        continue

                    new_bytes = new_value.to_bytes(4, byteorder=endian)

                    instruction = FuzzInstruction(
                        syscall_index=target_candidate.index,
                        cmd=FUZZ_CMD_INTERESTING_VALUES,
                        arg_index=1,
                        data=new_bytes
                    )

                    instructions.append(instruction)

        print(f"[AFLMutator] 🔢 Generated {len(instructions)} 32-bit arithmetic mutations")
        return instructions

    def _generate_interesting_instructions(self, target_candidate) -> List[FuzzInstruction]:
        """Generate interesting value instructions"""
        instructions = []

        if self.current_stage == AFLStage.INTEREST_8:
            instructions = self._interesting_8(target_candidate)
        elif self.current_stage == AFLStage.INTEREST_16:
            instructions = self._interesting_16(target_candidate)
        elif self.current_stage == AFLStage.INTEREST_32:
            instructions = self._interesting_32(target_candidate)

        return instructions

    def _interesting_8(self, target_candidate) -> List[FuzzInstruction]:
        """AFL 8-bit interesting values"""
        instructions = []

        for value in self.INTERESTING_8:
            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_INTERESTING_VALUES,
                arg_index=1,
                data=struct.pack('b', value)
            )
            instructions.append(instruction)

        print(f"[AFLMutator] ⭐ Generated {len(instructions)} 8-bit interesting value mutations")
        return instructions

    def _interesting_16(self, target_candidate) -> List[FuzzInstruction]:
        """AFL 16-bit interesting values"""
        instructions = []

        for value in self.INTERESTING_16:
            for endian in ['little', 'big']:
                instruction = FuzzInstruction(
                    syscall_index=target_candidate.index,
                    cmd=FUZZ_CMD_INTERESTING_VALUES,
                    arg_index=1,
                    data=value.to_bytes(2, byteorder=endian, signed=True)
                )
                instructions.append(instruction)

        print(f"[AFLMutator] ⭐ Generated {len(instructions)} 16-bit interesting value mutations")
        return instructions

    def _interesting_32(self, target_candidate) -> List[FuzzInstruction]:
        """AFL 32-bit interesting values"""
        instructions = []

        for value in self.INTERESTING_32:
            for endian in ['little', 'big']:
                instruction = FuzzInstruction(
                    syscall_index=target_candidate.index,
                    cmd=FUZZ_CMD_INTERESTING_VALUES,
                    arg_index=1,
                    data=value.to_bytes(4, byteorder=endian, signed=True)
                )
                instructions.append(instruction)

        print(f"[AFLMutator] ⭐ Generated {len(instructions)} 32-bit interesting value mutations")
        return instructions

    def _advance_afl_stage(self):
        """Advance AFL stage"""
        self.stage_progress += 1

        # Check if current stage is complete
        if self._is_stage_complete():
            self._next_afl_stage()

    def _is_stage_complete(self) -> bool:
        """Determine if the current stage is complete"""
        # Simplified: switch after executing each stage a certain number of times
        stage_limits = {
            AFLStage.BITFLIP_1_1: 50,
            AFLStage.BITFLIP_2_1: 30,
            AFLStage.BITFLIP_4_1: 20,
            AFLStage.BITFLIP_8_8: 10,
            AFLStage.ARITH_8: 40,
            AFLStage.ARITH_16: 30,
            AFLStage.ARITH_32: 20,
            AFLStage.INTEREST_8: 10,
            AFLStage.INTEREST_16: 20,
            AFLStage.INTEREST_32: 20,
            AFLStage.HAVOC: 100,
        }

        limit = stage_limits.get(self.current_stage, 50)
        return self.stage_progress >= limit

    def _next_afl_stage(self):
        """Switch to the next AFL stage"""
        stage_sequence = [
            AFLStage.BITFLIP_1_1, AFLStage.BITFLIP_2_1, AFLStage.BITFLIP_4_1,
            AFLStage.BITFLIP_8_8, AFLStage.BITFLIP_16_8, AFLStage.BITFLIP_32_8,
            AFLStage.ARITH_8, AFLStage.ARITH_16, AFLStage.ARITH_32,
            AFLStage.INTEREST_8, AFLStage.INTEREST_16, AFLStage.INTEREST_32,
            AFLStage.HAVOC
        ]

        try:
            current_idx = stage_sequence.index(self.current_stage)
            next_idx = (current_idx + 1) % len(stage_sequence)
            self.current_stage = stage_sequence[next_idx]
        except ValueError:
            self.current_stage = AFLStage.BITFLIP_1_1

        self.stage_progress = 0
        print(f"[AFLMutator] 🔄 Advanced to stage: {self.current_stage}")

    def record_stage_feedback(self, found_new_coverage: bool):
        """Record stage feedback"""
        stage = self.current_stage
        self.stage_stats[stage]["executions"] += 1

        if found_new_coverage:
            self.stage_stats[stage]["finds"] += 1
            self.stage_finds += 1

    def get_afl_stats(self) -> Dict[str, Any]:
        """Get AFL statistics"""
        return {
            "current_stage": self.current_stage,
            "stage_progress": self.stage_progress,
            "stage_finds": self.stage_finds,
            "stage_stats": self.stage_stats.copy()
        }

    def print_afl_stats(self):
        """Print AFL statistics"""
        print(f"\n[AFLMutator] 📊 AFL Stage Statistics:")
        print(f"  Current stage: {self.current_stage}")
        print(f"  Stage progress: {self.stage_progress}")
        print(f"  Stage finds: {self.stage_finds}")

        for stage, stats in self.stage_stats.items():
            if stats["executions"] > 0:
                find_rate = stats["finds"] / stats["executions"] * 100
                print(f"  {stage}: {stats['executions']} execs, {stats['finds']} finds ({find_rate:.1f}%)")

    # Override parent class method to use AFL-enhanced version
    def build_instructions(self, iteration: int, fork_point: Optional[int] = None) -> List[FuzzInstruction]:
        """Override parent class method to use AFL-enhanced version"""
        return self.build_instructions_afl_enhanced(iteration, fork_point)

    def _extract_dictionary_tokens(self, target_binary):
        """Extract dictionary tokens from the target binary"""
        if not target_binary or not os.path.exists(target_binary):
            print("[AFLMutator] ⚠️ Target binary not provided or not found, skipping dictionary extraction")
            return

        try:
            print(f"[AFLMutator] 📖 Extracting dictionary tokens from {target_binary}...")
            # Use the strings command to extract
            result = subprocess.run(['strings', target_binary], capture_output=True, text=True, check=True)
            strings = result.stdout.splitlines()

            # Filter and process
            count = 0
            for s in strings:
                s = s.strip()
                # Keep strings with length between 3 and 32
                if 3 <= len(s) <= 32:
                    # Convert to bytes
                    try:
                        token = s.encode('utf-8')
                        if token not in self.dictionary:
                            self.dictionary.append(token)
                            count += 1
                    except:
                        pass

            # Hard-code common Magic Bytes as supplementary entries
            common_magics = [
                b"HTTP/1.1", b"GET", b"POST", b"Host:", b"User-Agent:",
                b"Content-Length:", b"Content-Type:", b"Connection:",
                b"admin", b"password", b"root", b"123456",
                b"soap:Envelope", b"urn:schemas",
                b"ABC", b"XYZ", b"MAGIC" # Common test case entries
            ]

            for m in common_magics:
                if m not in self.dictionary:
                    self.dictionary.append(m)
                    count += 1

            print(f"[AFLMutator] ✅ Extracted {count} tokens. Total dictionary size: {len(self.dictionary)}")

            # Limit dictionary size, randomly keep 200, plus the latest 50
            if len(self.dictionary) > 500:
                 import random
                 self.dictionary = random.sample(self.dictionary, 500)
                 print(f"[AFLMutator] ✂️ Dictionary truncated to 500 items")

        except Exception as e:
             print(f"[AFLMutator] ❌ Failed to extract dictionary: {e}")

    def _generate_extras_ao_instructions(self, target_candidate) -> List[FuzzInstruction]:
        """Generate auto-dictionary (Extras Auto) mutation instructions"""
        instructions = []
        if not self.dictionary:
            return []

        seed_data = self.current_seed_data
        if not seed_data or len(seed_data) == 0:
            return []

        # Try to generate 5-10 dictionary mutations
        num_mutations = random.randint(5, 10)

        for _ in range(num_mutations):
            token = random.choice(self.dictionary)

            # Strategy 1: Overwrite
            # Randomly select a position to insert the token
            if len(seed_data) >= len(token):
                pos = random.randint(0, len(seed_data) - len(token))

                new_data = bytearray(seed_data)
                # Complex Overwrite
                for k in range(len(token)):
                    new_data[pos + k] = token[k]

                instruction = FuzzInstruction(
                    syscall_index=target_candidate.index,
                    cmd=FUZZ_CMD_REPLACE_BUFFER, # Use REPLACE_BUFFER to carry the full payload
                    arg_index=1,
                    data=bytes(new_data)
                )
                instructions.append(instruction)

            # Strategy 2: Insert - simplified here as replacing the entire buffer with "Token"
            # or "Prefix + Token + Suffix"
            # Due to current instruction set limitations, primarily use REPLACE_BUFFER
            if random.random() < 0.3:
                 instruction = FuzzInstruction(
                    syscall_index=target_candidate.index,
                    cmd=FUZZ_CMD_REPLACE_BUFFER,
                    arg_index=1,
                    data=token # Use the token directly as content
                )
                 instructions.append(instruction)

        print(f"[AFLMutator] 📖 Generated {len(instructions)} dictionary mutations (EXTRAS_AO)")
        return instructions
