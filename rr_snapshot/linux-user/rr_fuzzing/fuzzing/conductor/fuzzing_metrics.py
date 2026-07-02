#!/usr/bin/env python3
"""
FuzzingMetrics - Unified fuzzing metrics and failure tracking

Purpose: Eliminate silent failures, uniformly track all errors and failure reasons
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time


class FailureReason(Enum):
    """Failure reason classification"""
    # Execution failures
    EXEC_TIMEOUT = "execution_timeout"
    EXEC_CRASH = "execution_crash"
    EXEC_SIGNAL = "execution_signal"
    EXEC_INVALID_STATE = "invalid_state"

    # Mutation failures
    MUTATION_NO_CANDIDATES = "no_mutation_candidates"
    MUTATION_GENERATION_FAILED = "mutation_generation_failed"
    MUTATION_INVALID_INDEX = "invalid_syscall_index"

    # Replay failures
    REPLAY_MISMATCH = "replay_mismatch"
    REPLAY_DIVERGENCE = "replay_divergence"
    REPLAY_TIMEOUT = "replay_timeout"

    # Fork failures
    FORK_POINT_INVALID = "invalid_fork_point"
    FORK_SERVER_FAILED = "fork_server_failed"
    FORK_CHILD_DIED = "fork_child_died"

    # Resource issues
    RESOURCE_SHM_FULL = "shared_memory_full"
    RESOURCE_FD_EXHAUSTED = "fd_exhausted"
    RESOURCE_MEMORY_ERROR = "memory_error"

    # Configuration issues
    CONFIG_INVALID_TRACE = "invalid_trace_file"
    CONFIG_MISSING_BINARY = "missing_binary"
    CONFIG_PERMISSION_DENIED = "permission_denied"

    # Other
    UNKNOWN = "unknown"


@dataclass
class FailureEvent:
    """Record of a single failure event"""
    timestamp: float
    reason: FailureReason
    iteration: int
    component: str  # Name of the component where the failure occurred
    details: str
    context: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return (f"[{self.component}@iter{self.iteration}] {self.reason.value}: "
                f"{self.details}")


class FuzzingMetrics:
    """
    Unified fuzzing metrics tracker

    Responsibilities:
    1. Track all failure events (eliminate silent failures)
    2. Count the frequency of each failure type
    3. Provide failure trend analysis
    4. Generate diagnostic reports
    """

    def __init__(self):
        # Failure event history
        self.failure_events: List[FailureEvent] = []

        # Failure counts
        self.failure_counts: Dict[FailureReason, int] = {
            reason: 0 for reason in FailureReason
        }

        # Success counts
        self.success_counts = {
            'total_iterations': 0,
            'successful_iterations': 0,
            'successful_mutations': 0,
            'successful_forks': 0,
        }

        # Performance metrics
        self.performance = {
            'total_time': 0.0,
            'avg_iteration_time': 0.0,
            'last_iteration_time': 0.0,
        }

        # Per-component failure counts
        self.component_failures: Dict[str, int] = {}

        # Start time
        self.start_time = time.time()

    def record_failure(
        self,
        reason: FailureReason,
        component: str,
        details: str,
        iteration: int = -1,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Record a failure event

        Args:
            reason: Failure reason
            component: Component where the failure occurred (e.g. "QEMUExecutor", "SmartMutator")
            details: Detailed description
            iteration: Iteration count
            context: Additional context information
        """
        event = FailureEvent(
            timestamp=time.time(),
            reason=reason,
            iteration=iteration,
            component=component,
            details=details,
            context=context or {}
        )

        self.failure_events.append(event)
        self.failure_counts[reason] += 1

        # Per-component statistics
        if component not in self.component_failures:
            self.component_failures[component] = 0
        self.component_failures[component] += 1

    def record_success(self, metric_name: str):
        """
        Record a success event

        Args:
            metric_name: Metric name (e.g. "successful_mutations")
        """
        if metric_name in self.success_counts:
            self.success_counts[metric_name] += 1

    def update_performance(self, metric_name: str, value: float):
        """Update performance metrics"""
        if metric_name in self.performance:
            self.performance[metric_name] = value

    def get_failure_rate(self) -> float:
        """
        Calculate overall failure rate

        Returns:
            Failure rate (0.0-1.0)
        """
        total = self.success_counts['total_iterations']
        if total == 0:
            return 0.0

        failed = total - self.success_counts['successful_iterations']
        return failed / total

    def get_top_failures(self, n: int = 5) -> List[tuple]:
        """
        Get the top N failure reasons

        Returns:
            [(FailureReason, count), ...]
        """
        sorted_failures = sorted(
            self.failure_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return [(reason, count) for reason, count in sorted_failures[:n] if count > 0]

    def get_recent_failures(self, n: int = 10) -> List[FailureEvent]:
        """Get the most recent N failures"""
        return self.failure_events[-n:]

    def get_component_failure_rate(self, component: str) -> float:
        """Get the failure rate for a specific component"""
        total_failures = sum(self.failure_counts.values())
        if total_failures == 0:
            return 0.0

        component_failures = self.component_failures.get(component, 0)
        return component_failures / total_failures

    def generate_report(self) -> str:
        """
        Generate a diagnostic report

        Returns:
            Formatted report text
        """
        elapsed = time.time() - self.start_time

        report = []
        report.append("=" * 70)
        report.append("Fuzzing Metrics Report")
        report.append("=" * 70)

        # Basic statistics
        report.append("\n📊 Basic Statistics:")
        report.append(f"  Total iterations:      {self.success_counts['total_iterations']}")
        report.append(f"  Successful iterations: {self.success_counts['successful_iterations']}")
        report.append(f"  Failure rate:          {self.get_failure_rate()*100:.1f}%")
        report.append(f"  Total time:            {elapsed:.1f}s")

        # Top failure reasons
        report.append("\n❌ Top Failure Reasons:")
        top_failures = self.get_top_failures(5)
        if top_failures:
            for reason, count in top_failures:
                report.append(f"  {reason.value:30s} {count:5d} times")
        else:
            report.append("  No failures recorded ✅")

        # Per-component failure statistics
        report.append("\n🔧 Component Failures:")
        if self.component_failures:
            sorted_components = sorted(
                self.component_failures.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for component, count in sorted_components[:5]:
                rate = self.get_component_failure_rate(component)
                report.append(f"  {component:20s} {count:5d} times ({rate*100:.1f}%)")
        else:
            report.append("  No component failures ✅")

        # Recent failures
        report.append("\n🕒 Recent Failures (last 5):")
        recent = self.get_recent_failures(5)
        if recent:
            for event in recent:
                report.append(f"  {event}")
        else:
            report.append("  No recent failures ✅")

        # Performance metrics
        report.append("\n⚡ Performance:")
        if self.performance['avg_iteration_time'] > 0:
            report.append(f"  Avg iteration time: {self.performance['avg_iteration_time']:.3f}s")
        if self.performance['last_iteration_time'] > 0:
            report.append(f"  Last iteration time: {self.performance['last_iteration_time']:.3f}s")

        report.append("=" * 70)

        return "\n".join(report)

    def to_dict(self) -> Dict[str, Any]:
        """Export to dictionary (for JSON serialization)"""
        return {
            'failure_counts': {
                reason.value: count
                for reason, count in self.failure_counts.items()
            },
            'success_counts': self.success_counts,
            'performance': self.performance,
            'component_failures': self.component_failures,
            'total_failures': len(self.failure_events),
            'failure_rate': self.get_failure_rate(),
            'elapsed_time': time.time() - self.start_time,
        }

    def reset(self):
        """Reset all metrics"""
        self.failure_events.clear()
        self.failure_counts = {reason: 0 for reason in FailureReason}
        self.success_counts = {k: 0 for k in self.success_counts}
        self.component_failures.clear()
        self.start_time = time.time()


# Global singleton (optional)
_global_metrics: Optional[FuzzingMetrics] = None


def get_global_metrics() -> FuzzingMetrics:
    """Get the global metrics instance"""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = FuzzingMetrics()
    return _global_metrics


def reset_global_metrics():
    """Reset the global metrics"""
    global _global_metrics
    if _global_metrics:
        _global_metrics.reset()
    else:
        _global_metrics = FuzzingMetrics()
