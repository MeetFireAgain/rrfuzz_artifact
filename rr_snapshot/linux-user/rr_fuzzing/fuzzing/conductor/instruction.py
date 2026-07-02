#!/usr/bin/env python3
"""
FuzzInstruction - Fuzzing instruction representation

Backward compatibility shim.
Refer to .types.FuzzInstruction for the actual implementation.
"""

try:
    from .conductor_types import FuzzInstruction
except ImportError:
    from conductor_types import FuzzInstruction
