#!/usr/bin/env python3
"""
Advanced Energy Scheduler for Coverage-Guided Fuzzing

This module implements an advanced energy scheduling system that intelligently
allocates fuzzing resources (energy) to seeds based on multiple factors.
"""

import math
import random
import time
from collections import Counter
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class FuzzContext:
    """Fuzzing context information"""
    current_time: float
    total_execs: int
    global_coverage: set
    no_new_coverage_count: int = 0

    def in_exploration_phase(self) -> bool:
        """Determine whether we are in the exploration phase"""
        # In the early stage or after a long period without new coverage, we are in exploration phase
        return self.total_execs < 1000 or self.no_new_coverage_count > 500


class AdvancedEnergyScheduler:
    """
    Advanced energy scheduler

    Computes energy values for seeds based on multiple factors, enabling intelligent resource allocation:
    1. Coverage freshness (40%) - Prioritize seeds that recently discovered new coverage
    2. Path depth (20%) - Deep paths may trigger deep-seated bugs
    3. Execution speed (15%) - Fast seeds allow faster iteration
    4. Input entropy (15%) - High-entropy inputs explore more states
    5. Crash potential (10%) - Historical crash correlation

    Dynamically adjusts the exploration-vs-exploitation balance.
    """

    def __init__(
        self,
        coverage_weight: float = 0.40,
        depth_weight: float = 0.30,
        speed_weight: float = 0.10,
        entropy_weight: float = 0.10,
        crash_weight: float = 0.10,
    ):
        """
        Initialize energy scheduler

        Args:
            coverage_weight: Coverage freshness weight
            depth_weight: Path depth weight
            speed_weight: Execution speed weight
            entropy_weight: Input entropy weight
            crash_weight: Crash potential weight
        """
        # Weight configuration
        self.coverage_weight = coverage_weight
        self.depth_weight = depth_weight
        self.speed_weight = speed_weight
        self.entropy_weight = entropy_weight
        self.crash_weight = crash_weight

        # Normalize weights
        total_weight = (
            coverage_weight + depth_weight + speed_weight +
            entropy_weight + crash_weight
        )
        self.coverage_weight /= total_weight
        self.depth_weight /= total_weight
        self.speed_weight /= total_weight
        self.entropy_weight /= total_weight
        self.crash_weight /= total_weight

        # Cache
        self._entropy_cache: Dict[str, float] = {}
        
        print(f"[EnergyScheduler] Initialized with weights:")
        print(f"  Coverage: {self.coverage_weight:.2f}")
        print(f"  Depth:    {self.depth_weight:.2f}")
        print(f"  Speed:    {self.speed_weight:.2f}")
        print(f"  Entropy:  {self.entropy_weight:.2f}")
        print(f"  Crash:    {self.crash_weight:.2f}")
    
    def calculate_energy(self, seed: Any, context: FuzzContext) -> float:
        """
        Calculate energy value for a seed

        Args:
            seed: Seed object
            context: Fuzzing context

        Returns:
            Energy value (0.0 - 10.0)
        """
        # Compute individual factor scores
        coverage_score = self._coverage_freshness(seed, context)
        depth_score = self._path_depth_score(seed)
        speed_score = self._execution_speed(seed)
        entropy_score = self._input_entropy(seed)
        crash_score = self._crash_potential(seed)

        # Weighted combination
        energy = (
            self.coverage_weight * coverage_score +
            self.depth_weight * depth_score +
            self.speed_weight * speed_score +
            self.entropy_weight * entropy_score +
            self.crash_weight * crash_score
        )

        # Dynamic adjustment: bonus during exploration phase
        if context.in_exploration_phase():
            energy *= 1.2

        # Normalize to reasonable range [0.5, 10.0]
        energy = max(0.5, min(10.0, energy * 10.0))

        return energy
    
    def _coverage_freshness(self, seed: Any, context: FuzzContext) -> float:
        """
        Coverage freshness score

        Scoring criteria:
        - Seeds that recently discovered new coverage receive a higher score
        - Uses an exponential decay function
        - Seeds with no new coverage receive a base score

        Returns:
            Score (0.0 - 1.0)
        """
        # Compute new coverage for the seed
        if hasattr(seed, 'coverage') and hasattr(context, 'global_coverage'):
            new_edges = seed.coverage - context.global_coverage
            if not new_edges:
                return 0.5  # No new coverage — base score

            # Ratio of new coverage
            new_ratio = len(new_edges) / max(1, len(seed.coverage))

            # Time decay
            if hasattr(seed, 'discovery_time') and seed.discovery_time > 0:
                age = max(0, context.current_time - seed.discovery_time)  # Ensure non-negative
                # Safe exponential decay (cap age to avoid overflow)
                age = min(age, 10000)  # Cap maximum age
                freshness = math.exp(-age / 1000)  # 1000-second half-life
            else:
                freshness = 1.0

            # Combined score
            score = 0.5 + 0.5 * freshness * new_ratio
            return min(1.0, score)

        return 0.5  # Default medium score
    
    def _path_depth_score(self, seed: Any) -> float:
        """
        Path depth score

        Deeper paths are more valuable (may trigger deep-seated bugs)

        Returns:
            Score (0.0 - 1.0)
        """
        if not hasattr(seed, 'path_depth'):
            return 0.5

        max_depth = 1000  # Assumed maximum depth
        normalized_depth = min(seed.path_depth, max_depth) / max_depth

        # Use a more aggressive power-law score so deep paths receive significantly higher energy
        score = normalized_depth ** 0.5

        return score
    
    def _execution_speed(self, seed: Any) -> float:
        """
        Execution speed score

        Faster seeds allow faster iteration

        Returns:
            Score (0.0 - 1.0)
        """
        if not hasattr(seed, 'exec_time') or seed.exec_time == 0:
            return 1.0  # Default: fast

        # Normalize to [0, 1] (assuming max 1 second)
        max_time = 1.0
        normalized_time = min(seed.exec_time, max_time) / max_time

        # Higher score for faster execution
        score = 1.0 - normalized_time

        return score
    
    def _input_entropy(self, seed: Any) -> float:
        """
        Input entropy score

        High-entropy inputs may explore more states

        Returns:
            Score (0.0 - 1.0)
        """
        # Check cache
        if hasattr(seed, 'seed_id'):
            if seed.seed_id in self._entropy_cache:
                return self._entropy_cache[seed.seed_id]

        # Obtain input data
        input_data = None
        if hasattr(seed, 'input_data'):
            input_data = seed.input_data
        elif hasattr(seed, 'trace_file'):
            # Simplified: read from trace file
            try:
                with open(seed.trace_file, 'rb') as f:
                    input_data = f.read()[:1024]  # Read only first 1024 bytes
            except:
                pass

        if not input_data or len(input_data) == 0:
            return 0.5  # Default medium entropy

        # Compute Shannon entropy
        byte_counts = Counter(input_data)
        entropy = 0.0
        total = len(input_data)

        for count in byte_counts.values():
            p = count / total
            entropy -= p * math.log2(p)

        # Normalize to [0, 1] (maximum entropy is 8 bits)
        max_entropy = 8.0
        score = entropy / max_entropy

        # Cache result
        if hasattr(seed, 'seed_id'):
            self._entropy_cache[seed.seed_id] = score

        return score
    
    def _crash_potential(self, seed: Any) -> float:
        """
        Crash potential score

        Estimate a seed's crash potential based on historical crash records

        Returns:
            Score (0.0 - 1.0)
        """
        # If the seed itself is a crash
        if hasattr(seed, 'crash') and seed.crash:
            return 1.0

        # Check crash records of parent and siblings
        parent_crashed = 0
        siblings_crashed = 0

        if hasattr(seed, 'parent_crashed_count'):
            parent_crashed = seed.parent_crashed_count

        if hasattr(seed, 'siblings_crashed_count'):
            siblings_crashed = seed.siblings_crashed_count

        # Compute potential score
        if parent_crashed > 0 or siblings_crashed > 0:
            # Has crash history — high potential
            crash_count = parent_crashed + siblings_crashed
            score = min(1.0, 0.5 + 0.1 * crash_count)
            return score

        # Generation can also be an indicator (early-generation seeds may be more valuable)
        if hasattr(seed, 'generation'):
            # Early-generation seeds receive a slightly higher score
            generation_score = math.exp(-seed.generation / 100)
            return 0.3 + 0.2 * generation_score

        return 0.3  # Default low potential


class ExplorationExploitationBalance:
    """
    Exploration-exploitation balance controller

    Dynamically adjusts the fuzzer's balance between exploration and exploitation:
    - Exploration: try new, diverse inputs
    - Exploitation: deeply mine known valuable inputs

    Strategy:
    1. Early stage: high exploration rate (80%)
    2. Middle stage: balanced (50%)
    3. Late stage: high exploitation rate (30%)
    4. Dynamic adjustment: increase exploration rate when no new coverage for a long time
    """

    def __init__(self, initial_rate: float = 0.7):
        """
        Initialize balance controller

        Args:
            initial_rate: Initial exploration rate (0.0 - 1.0)
        """
        self.exploration_rate = initial_rate
        self.last_adjustment_time = time.time()
        self.adjustment_interval = 100  # Adjust every 100 executions

        print(f"[ExploreExploit] Initialized with rate: {self.exploration_rate:.2f}")
    
    def update_phase(self, fuzzing_stats: Dict[str, Any]):
        """
        Update exploration/exploitation ratio based on fuzzing statistics

        Args:
            fuzzing_stats: Fuzzing statistics dictionary containing:
                - total_execs: Total execution count
                - new_coverage_count: Number of new coverage entries
                - no_new_coverage_count: Consecutive iterations without new coverage
        """
        total_execs = fuzzing_stats.get('total_execs', 0)
        no_new_cov = fuzzing_stats.get('no_new_coverage_count', 0)

        # Phase 1: Early stage (0-1000 execs) - high exploration
        if total_execs < 1000:
            self.exploration_rate = 0.8

        # Phase 2: Middle stage (1000-10000) - balanced
        elif total_execs < 10000:
            self.exploration_rate = 0.5

        # Phase 3: Late stage (>10000) - high exploitation
        else:
            self.exploration_rate = 0.3

        # Dynamic adjustment: increase exploration rate if no new coverage for a long time
        if no_new_cov > 500:
            self.exploration_rate = min(0.9, self.exploration_rate + 0.2)
            print(f"[ExploreExploit] No new coverage for {no_new_cov} iters, "
                  f"increasing exploration rate to {self.exploration_rate:.2f}")
        elif no_new_cov > 200:
            self.exploration_rate = min(0.8, self.exploration_rate + 0.1)

        # Clamp to valid range
        self.exploration_rate = max(0.1, min(0.9, self.exploration_rate))
    
    def should_explore(self) -> bool:
        """
        Decide whether to explore

        Returns:
            True means explore, False means exploit
        """
        return random.random() < self.exploration_rate

    def get_mutation_intensity(self, is_exploration: bool) -> float:
        """
        Get mutation intensity

        Exploration mode uses larger mutations; exploitation mode uses smaller mutations

        Args:
            is_exploration: Whether we are in exploration mode

        Returns:
            Mutation intensity (0.0 - 1.0)
        """
        if is_exploration:
            # Exploration: large-scale mutation
            return random.uniform(0.5, 1.0)
        else:
            # Exploitation: small-scale mutation
            return random.uniform(0.1, 0.4)


def test_energy_scheduler():
    """Test energy scheduler"""
    print("Testing AdvancedEnergyScheduler...")

    # Create scheduler
    scheduler = AdvancedEnergyScheduler()

    # Create test seed
    @dataclass
    class TestSeed:
        seed_id: str
        coverage: set
        discovery_time: float
        path_depth: int
        exec_time: float
        input_data: bytes
        crash: bool = False
        generation: int = 0

    # Test different types of seeds
    now = time.time()

    # Seed 1: Freshly discovered, deep path
    seed1 = TestSeed(
        seed_id="seed1",
        coverage={1, 2, 3, 4, 5},
        discovery_time=now,
        path_depth=500,
        exec_time=0.1,
        input_data=b"test_data_1",
        generation=0
    )

    # Seed 2: Old, shallow path
    seed2 = TestSeed(
        seed_id="seed2",
        coverage={1, 2, 3},
        discovery_time=now - 1000,
        path_depth=50,
        exec_time=0.5,
        input_data=b"test_data_2",
        generation=10
    )

    # Seed 3: Crash seed
    seed3 = TestSeed(
        seed_id="seed3",
        coverage={1, 2, 3, 4},
        discovery_time=now - 100,
        path_depth=200,
        exec_time=0.2,
        input_data=b"crash_data",
        crash=True,
        generation=5
    )

    # Create context
    context = FuzzContext(
        current_time=now,
        total_execs=1000,
        global_coverage={1, 2, 3},
        no_new_coverage_count=0
    )
    
    # 计算能量
    energy1 = scheduler.calculate_energy(seed1, context)
    energy2 = scheduler.calculate_energy(seed2, context)
    energy3 = scheduler.calculate_energy(seed3, context)
    
    print(f"Seed 1 energy: {energy1:.2f}")
    print(f"Seed 2 energy: {energy2:.2f}")
    print(f"Seed 3 energy: {energy3:.2f}")
    
    # 验证
    assert energy1 > energy2, "Fresh deep seed should have higher energy"
    assert energy3 > energy2, "Crash seed should have higher energy"
    
    print("✓ AdvancedEnergyScheduler test passed")


def test_exploration_exploitation():
    """Test exploration-exploitation balance"""
    print("\nTesting ExplorationExploitationBalance...")

    balance = ExplorationExploitationBalance()

    # Test different phases
    stats_early = {'total_execs': 100, 'no_new_coverage_count': 0}
    balance.update_phase(stats_early)
    print(f"Early phase rate: {balance.exploration_rate:.2f}")
    assert balance.exploration_rate == 0.8

    stats_mid = {'total_execs': 5000, 'no_new_coverage_count': 0}
    balance.update_phase(stats_mid)
    print(f"Mid phase rate: {balance.exploration_rate:.2f}")
    assert balance.exploration_rate == 0.5

    stats_late = {'total_execs': 15000, 'no_new_coverage_count': 0}
    balance.update_phase(stats_late)
    print(f"Late phase rate: {balance.exploration_rate:.2f}")
    assert balance.exploration_rate == 0.3

    # Test dynamic adjustment
    stats_stuck = {'total_execs': 15000, 'no_new_coverage_count': 600}
    balance.update_phase(stats_stuck)
    print(f"Stuck phase rate: {balance.exploration_rate:.2f}")
    assert balance.exploration_rate > 0.3

    print("✓ ExplorationExploitationBalance test passed")


if __name__ == '__main__':
    test_energy_scheduler()
    test_exploration_exploitation()

