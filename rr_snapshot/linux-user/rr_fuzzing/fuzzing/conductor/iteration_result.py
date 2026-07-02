#!/usr/bin/env python3
"""
IterationResult - Explicit iteration result return value

Purpose: Eliminate silent failures, provide clear success/failure status and error information
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum


class IterationStatus(Enum):
    """Iteration status enumeration"""
    SUCCESS = "success"                 # Successfully completed
    FAILURE = "failure"                 # Failed (generic)

    # Specific failure types
    NO_TRACE = "no_trace"              # No trace available
    NO_MUTATIONS = "no_mutations"       # Unable to generate mutations
    EXECUTION_FAILED = "exec_failed"    # Execution failed
    EXECUTION_TIMEOUT = "exec_timeout"  # Execution timed out
    EXECUTION_CRASH = "exec_crash"      # Execution crashed
    CFG_ANALYSIS_FAILED = "cfg_failed"  # CFG analysis failed
    FORK_FAILED = "fork_failed"         # Fork failed

    # Partial success
    PARTIAL_SUCCESS = "partial_success" # Partially executed successfully


@dataclass
class IterationResult:
    """
    Result of a single iteration

    Provides clear success/failure status, eliminating silent failure issues
    """

    # Basic status
    status: IterationStatus
    iteration_id: int

    # Success metrics
    new_coverage: bool = False
    new_paths: int = 0
    crashes_found: int = 0

    # Execution statistics
    execs_performed: int = 0
    mutations_applied: int = 0

    # Failure information
    error_message: Optional[str] = None
    error_component: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)

    # Additional context
    trace_id: Optional[str] = None
    fork_point: Optional[int] = None
    recipe_used: Optional[int] = None

    def is_success(self) -> bool:
        """Whether the iteration succeeded"""
        return self.status == IterationStatus.SUCCESS or self.status == IterationStatus.PARTIAL_SUCCESS

    def is_failure(self) -> bool:
        """Whether the iteration failed"""
        return not self.is_success()

    def has_new_coverage(self) -> bool:
        """Whether new coverage was found"""
        return self.new_coverage

    def has_crashes(self) -> bool:
        """Whether crashes were found"""
        return self.crashes_found > 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (for logging/serialization)"""
        return {
            'status': self.status.value,
            'iteration_id': self.iteration_id,
            'new_coverage': self.new_coverage,
            'new_paths': self.new_paths,
            'crashes_found': self.crashes_found,
            'execs_performed': self.execs_performed,
            'mutations_applied': self.mutations_applied,
            'error_message': self.error_message,
            'error_component': self.error_component,
            'trace_id': self.trace_id,
            'fork_point': self.fork_point,
            'recipe_used': self.recipe_used,
        }

    def __str__(self) -> str:
        """Friendly string representation"""
        if self.is_success():
            parts = [f"Iteration {self.iteration_id}: {self.status.value}"]
            if self.new_coverage:
                parts.append(f"(+{self.new_paths} paths)")
            if self.crashes_found > 0:
                parts.append(f"({self.crashes_found} crashes)")
            return " ".join(parts)
        else:
            return (f"Iteration {self.iteration_id}: {self.status.value} - "
                   f"{self.error_component}: {self.error_message}")


@dataclass
class BatchIterationResult:
    """
    Aggregated result of batch iterations

    Used for batch execution scenarios such as multi-fork
    """

    total_iterations: int
    successful: int
    failed: int

    # Aggregated metrics
    total_new_coverage: bool
    total_new_paths: int
    total_crashes: int
    total_execs: int

    # Detailed results
    results: List[IterationResult] = field(default_factory=list)

    # Failure breakdown
    failure_breakdown: Dict[IterationStatus, int] = field(default_factory=dict)

    def success_rate(self) -> float:
        """Success rate"""
        if self.total_iterations == 0:
            return 0.0
        return self.successful / self.total_iterations

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_iterations': self.total_iterations,
            'successful': self.successful,
            'failed': self.failed,
            'success_rate': self.success_rate(),
            'total_new_coverage': self.total_new_coverage,
            'total_new_paths': self.total_new_paths,
            'total_crashes': self.total_crashes,
            'total_execs': self.total_execs,
            'failure_breakdown': {
                status.value: count
                for status, count in self.failure_breakdown.items()
            },
        }

    def __str__(self) -> str:
        """Friendly string representation"""
        return (f"Batch: {self.successful}/{self.total_iterations} success "
               f"({self.success_rate()*100:.1f}%), "
               f"+{self.total_new_paths} paths, "
               f"{self.total_crashes} crashes")


def create_success_result(
    iteration_id: int,
    new_coverage: bool = False,
    new_paths: int = 0,
    crashes_found: int = 0,
    execs_performed: int = 1,
    mutations_applied: int = 1,
    trace_id: Optional[str] = None,
    fork_point: Optional[int] = None,
    recipe_used: Optional[int] = None,
    status: IterationStatus = IterationStatus.SUCCESS
) -> IterationResult:
    """Convenience function to create a success result"""
    return IterationResult(
        status=status,
        iteration_id=iteration_id,
        new_coverage=new_coverage,
        new_paths=new_paths,
        crashes_found=crashes_found,
        execs_performed=execs_performed,
        mutations_applied=mutations_applied,
        trace_id=trace_id,
        fork_point=fork_point,
        recipe_used=recipe_used,
    )


def create_failure_result(
    iteration_id: int,
    status: IterationStatus,
    error_message: str,
    error_component: str,
    error_details: Optional[Dict[str, Any]] = None,
    trace_id: Optional[str] = None
) -> IterationResult:
    """Convenience function to create a failure result"""
    return IterationResult(
        status=status,
        iteration_id=iteration_id,
        error_message=error_message,
        error_component=error_component,
        error_details=error_details or {},
        trace_id=trace_id,
    )


def aggregate_results(results: List[IterationResult]) -> BatchIterationResult:
    """
    Aggregate multiple iteration results

    Args:
        results: List of iteration results

    Returns:
        Batch aggregated result
    """
    total = len(results)
    successful = sum(1 for r in results if r.is_success())
    failed = total - successful

    # Aggregated metrics
    total_new_coverage = any(r.new_coverage for r in results)
    total_new_paths = sum(r.new_paths for r in results)
    total_crashes = sum(r.crashes_found for r in results)
    total_execs = sum(r.execs_performed for r in results)

    # Failure categorization
    failure_breakdown = {}
    for r in results:
        if r.is_failure():
            if r.status not in failure_breakdown:
                failure_breakdown[r.status] = 0
            failure_breakdown[r.status] += 1

    return BatchIterationResult(
        total_iterations=total,
        successful=successful,
        failed=failed,
        total_new_coverage=total_new_coverage,
        total_new_paths=total_new_paths,
        total_crashes=total_crashes,
        total_execs=total_execs,
        results=results,
        failure_breakdown=failure_breakdown,
    )
