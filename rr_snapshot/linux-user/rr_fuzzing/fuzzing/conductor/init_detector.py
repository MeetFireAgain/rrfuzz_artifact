#!/usr/bin/env python3
"""
InitPhaseDetector - Adaptive Initialization Phase Detection

This module provides intelligent detection of program initialization phase
to avoid mutating critical setup syscalls that could crash the program.

Strategies:
1. Detect mmap burst completion (dynamic library loading)
2. Detect first I/O operation (read/write/open)
3. Detect initialization syscall density region end
4. Detect syscall pattern change (from initialization to main loop)
5. Detect repeating syscall sequences (main loop start)
6. Statistical feature-based intelligent decision
"""

from typing import List, Dict, Optional
from .constants import INIT_SYSCALLS


class InitPhaseDetector:
    """
    Adaptive Initialization Phase Detector (Enhanced Version)
    
    Detects when the program's initialization phase ends to avoid mutating
    critical initialization syscalls.
    
    Strategies (Enhanced):
    1. Detect mmap sequence completion (dynamic library loading)
    2. Detect first I/O operation (read/write/open)
    3. Detect initialization syscall density region end
    4. NEW: Detect syscall pattern change (from initialization to main loop)
    5. NEW: Detect repeating syscall sequences (main loop start)
    6. NEW: Statistical feature-based intelligent decision
    """
    
    def __init__(self, mode='adaptive', static_threshold=25):
        """
        Args:
            mode: 'adaptive' (adaptive), 'static' (fixed threshold), 'disabled' (no skip)
            static_threshold: Threshold for static mode
        """
        self.mode = mode
        self.static_threshold = static_threshold
        self.init_phase_end = None
        self.metrics = {}
        self.confidence = 0.0  # Detection confidence
    
    def detect(self, syscalls: List[Dict]) -> int:
        """
        Detect initialization phase end position
        
        Args:
            syscalls: syscall list [{'index': 0, 'name': 'brk', ...}, ...]
        
        Returns:
            Syscall index where initialization phase ends (safe to fuzz after)
        """
        if self.mode == 'disabled':
            return 0  # Don't skip any syscall
        
        if self.mode == 'static':
            return self.static_threshold
        
        # === Adaptive Detection (Enhanced) ===
        if self.init_phase_end is not None:
            return self.init_phase_end  # Use cached result
        
        end_points = []
        confidence_scores = {}
        
        # Strategy 1: Detect mmap burst end
        mmap_end = self._detect_mmap_burst_end(syscalls)
        if mmap_end is not None:
            end_points.append(('mmap_burst', mmap_end))
            confidence_scores['mmap_burst'] = 0.7  # High confidence
        
        # Strategy 2: Detect first I/O operation
        first_io = self._detect_first_io(syscalls)
        if first_io is not None:
            end_points.append(('first_io', first_io))
            confidence_scores['first_io'] = 0.8  # Very high confidence
        
        # Strategy 3: Detect initialization syscall burst end
        init_burst_end = self._detect_init_burst_end(syscalls)
        if init_burst_end is not None:
            end_points.append(('init_burst', init_burst_end))
            confidence_scores['init_burst'] = 0.6  # Medium confidence
        
        # Strategy 4: Detect syscall pattern change (NEW)
        pattern_change = self._detect_pattern_change(syscalls)
        if pattern_change is not None:
            end_points.append(('pattern_change', pattern_change))
            confidence_scores['pattern_change'] = 0.75  # High confidence
        
        # Strategy 5: Detect repeating sequences (main loop start) (NEW)
        loop_start = self._detect_loop_start(syscalls)
        if loop_start is not None:
            end_points.append(('loop_start', loop_start))
            confidence_scores['loop_start'] = 0.85  # Very high confidence
        
        # Strategy 6: Statistical feature-based intelligent decision (NEW)
        statistical_end = self._detect_by_statistics(syscalls)
        if statistical_end is not None:
            end_points.append(('statistical', statistical_end))
            confidence_scores['statistical'] = 0.65  # Medium confidence
        
        # Intelligent decision: Combine multiple strategies
        if end_points:
            # Use weighted voting mechanism
            weighted_scores = {}
            for strategy, index in end_points:
                weight = confidence_scores.get(strategy, 0.5)
                if index not in weighted_scores:
                    weighted_scores[index] = 0
                weighted_scores[index] += weight
            
            # Select index with highest weight
            best_index = max(weighted_scores.items(), key=lambda x: x[1])
            self.init_phase_end = best_index[0]
            self.confidence = best_index[1] / len(end_points)  # Normalize confidence
            
            self.metrics['detection_points'] = end_points
            self.metrics['confidence_scores'] = confidence_scores
            self.metrics['final_threshold'] = self.init_phase_end
            self.metrics['confidence'] = self.confidence
            
            print(f"[InitPhaseDetector] Detected init phase end at index {self.init_phase_end}")
            print(f"  Detection points: {end_points}")
            print(f"  Confidence: {self.confidence*100:.1f}%")
        else:
            # Fallback to static threshold
            self.init_phase_end = self.static_threshold
            self.confidence = 0.3  # Low confidence
            self.metrics['fallback'] = True
            print(f"[InitPhaseDetector] Auto-detection failed, using fallback: {self.static_threshold}")
        
        return self.init_phase_end
    
    def _detect_mmap_burst_end(self, syscalls: List[Dict]) -> Optional[int]:
        """Detect mmap burst end (usually dynamic library loading complete)"""
        mmap_indices = [sc['index'] for sc in syscalls if sc['name'] == 'mmap']
        
        if len(mmap_indices) < 3:
            return None
        
        # Find last mmap burst
        # Define "burst": mmap within 10 consecutive syscalls
        last_mmap_idx = mmap_indices[-1]
        for i in range(len(syscalls) - 1, -1, -1):
            if syscalls[i]['name'] == 'mmap':
                last_mmap_idx = syscalls[i]['index']
                break
        
        # Return 5th syscall after last mmap (leave safety margin)
        return min(last_mmap_idx + 5, len(syscalls) - 1)
    
    def _detect_first_io(self, syscalls: List[Dict]) -> Optional[int]:
        """Detect first I/O operation (program starts actual work)"""
        io_syscalls = {'read', 'write', 'open', 'openat', 'close'}
        
        for sc in syscalls:
            if sc['name'] in io_syscalls:
                # Return index of first I/O syscall
                return max(0, sc['index'])
        
        return None
    
    def _detect_init_burst_end(self, syscalls: List[Dict]) -> Optional[int]:
        """Detect initialization syscall density region end"""
        init_syscalls = INIT_SYSCALLS
        
        # Count init syscalls in each 10-syscall window
        window_size = 10
        max_init_idx = 0
        
        for i in range(0, len(syscalls), window_size):
            window = syscalls[i:i+window_size]
            init_count = sum(1 for sc in window if any(init_sc in sc['name'] for init_sc in init_syscalls))
            
            # If window has >50% init syscalls, still in initialization phase
            if init_count >= window_size * 0.5:
                max_init_idx = i + window_size
        
        return max_init_idx if max_init_idx > 0 else None
    
    def _detect_pattern_change(self, syscalls: List[Dict]) -> Optional[int]:
        """
        Detect syscall pattern change (NEW strategy)
        
        Initialization phase typically has specific syscall patterns (mmap, brk, mprotect, etc.),
        main loop phase has different patterns (read, write, computation operations, etc.)
        """
        if len(syscalls) < 20:
            return None
        
        # Define typical initialization phase syscalls
        init_pattern_syscalls = {'mmap', 'brk', 'mprotect', 'munmap', 'arch_prctl'}
        # Define typical main loop phase syscalls
        main_pattern_syscalls = {'read', 'write', 'poll', 'select', 'epoll_wait', 'recvfrom', 'sendto'}
        
        window_size = 15
        last_transition_idx = 0
        
        for i in range(0, len(syscalls) - window_size, 5):  # Slide every 5 syscalls
            window = syscalls[i:i+window_size]
            
            init_count = sum(1 for sc in window if sc['name'] in init_pattern_syscalls)
            main_count = sum(1 for sc in window if sc['name'] in main_pattern_syscalls)
            
            # If main loop pattern syscalls dominate, initialization ends
            if main_count > init_count and main_count >= window_size * 0.3:
                last_transition_idx = i
                break
        
        return last_transition_idx if last_transition_idx > 0 else None
    
    def _detect_loop_start(self, syscalls: List[Dict]) -> Optional[int]:
        """
        Detect repeating syscall sequences (main loop start) (NEW strategy)
        
        Main loop typically repeats the same syscall sequence,
        e.g.: read -> process -> write -> read -> ...
        """
        if len(syscalls) < 30:
            return None
        
        # Extract syscall name sequence
        names = [sc['name'] for sc in syscalls]
        
        # Find repeating subsequences (length 3-8)
        for pattern_len in range(3, 9):
            for start_idx in range(10, min(50, len(names) - pattern_len * 2)):
                pattern = names[start_idx:start_idx + pattern_len]
                
                # Check if this pattern repeats later
                search_start = start_idx + pattern_len
                search_end = min(start_idx + pattern_len * 5, len(names))
                
                for check_idx in range(search_start, search_end - pattern_len + 1):
                    if names[check_idx:check_idx + pattern_len] == pattern:
                        # Found repeat! Return start position of first pattern
                        return start_idx
        
        return None
    
    def _detect_by_statistics(self, syscalls: List[Dict]) -> Optional[int]:
        """
        Statistical feature-based intelligent decision (NEW strategy)
        
        Analyze syscall statistical feature changes:
        1. Syscall diversity (entropy)
        2. Call frequency
        3. Return value patterns
        """
        if len(syscalls) < 30:
            return None
        
        # Calculate "diversity score" for each window
        window_size = 10
        diversity_scores = []
        
        for i in range(0, len(syscalls) - window_size, 5):
            window = syscalls[i:i+window_size]
            unique_names = set(sc['name'] for sc in window)
            
            # Diversity score = unique syscall count / window size
            diversity = len(unique_names) / window_size
            diversity_scores.append((i, diversity))
        
        if not diversity_scores:
            return None
        
        # Initialization phase typically has low diversity (repeated mmap, etc.)
        # Main loop phase has high diversity (various operations)
        # Find point where diversity significantly increases
        threshold_diversity = 0.5
        for i, (idx, diversity) in enumerate(diversity_scores):
            if diversity >= threshold_diversity:
                # Found diversity increase point
                # Return safe position before this point
                return max(0, idx - 5)
        
        return None

