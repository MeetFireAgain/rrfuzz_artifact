"""
RR-Fuzz Conductor Module - Layer 1 & 2 Components

Architecture aligned with DETAILED_ARCHITECTURE.md:

Layer 1 - Trace Storage:
  - TraceManager: Trace pool management and selection
  - Trace: Single trace object representation

Layer 2 - Core Fuzzing:
  - FuzzingCore: Main fuzzing loop coordinator
  - QEMUExecutor: QEMU process execution engine
  - BaseMutator: Simple random mutation
  - SmartMutator: Intelligent trace-aware mutation
  - CoverageTracker: Coverage tracking and analysis
  
Support Components:
  - FuzzInstruction: Mutation instruction representation
  - FuzzSharedMemory: IPC shared memory management
  - InitPhaseDetector: Initialization phase detection
  - constants: All constant definitions
"""

# Layer 1: Trace Storage
from .trace_manager import TraceManager, Trace, TraceMetadata

# Layer 2: Core Fuzzing Components
from .fuzzing_core import FuzzingCore, FuzzingStatistics, CrashDetector
from .qemu_executor import QEMUExecutor, ExecutionResult
from .mutator import BaseMutator, SmartMutator

# Support Components
from .constants import *
from .init_detector import InitPhaseDetector
from .instruction import FuzzInstruction
from .coverage import CoverageTracker
from .shared_memory import FuzzSharedMemory
from .bb_trace_parser import BBTraceParser, BBEntry

__all__ = [
    # ===== Layer 1: Trace Storage =====
    'TraceManager', 'Trace', 'TraceMetadata',
    
    # ===== Layer 2: Core Fuzzing =====
    'FuzzingCore', 'FuzzingStatistics', 'CrashDetector',
    'QEMUExecutor', 'ExecutionResult',
    'BaseMutator', 'SmartMutator',
    
    # ===== Support Components =====
    'InitPhaseDetector', 'FuzzInstruction', 'CoverageTracker',
    'FuzzSharedMemory', 'BBTraceParser', 'BBEntry',
    
    # ===== Constants =====
    'FUZZ_CMD_NONE', 'FUZZ_CMD_MUTATE_ARG', 'FUZZ_CMD_REPLACE_BUFFER',
    'FUZZ_CMD_MUTATE_FLAGS', 'FUZZ_CMD_BOUNDARY_VALUE',
    'FUZZ_CMD_MUTATE_AUX_BUFFER', 'FUZZ_CMD_FLIP_BITS',
    'FUZZ_CMD_TRUNCATE', 'FUZZ_CMD_EXTEND', 'FUZZ_CMD_INTERESTING_VALUES',
    'FUZZ_CMD_LIGHT_MUTATION', 'FUZZ_CMD_OVERWRITE_AT_OFFSET',
    'FUZZ_MAGIC', 'FUZZ_MAX_INSTRUCTIONS', 'FUZZ_INSTRUCTION_DATA',
    'FUZZ_SHM_SIZE', 'COVERAGE_MAP_SIZE', 'FUZZ_FLAG_CAPTURE_SEED',
    'INIT_SYSCALLS', 'INIT_PHASE_THRESHOLD', 'IMPORTANT_SYSCALLS',
]

