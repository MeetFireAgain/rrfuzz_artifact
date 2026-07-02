#!/usr/bin/env python3
"""
MutationDependencyGraph - Track dependencies and effects between mutations

Purpose:
1. Track which mutation strategies are most effective
2. Identify mutation chains that lead to new coverage
3. Analyze mutation contributions to crashes
4. Guide future mutation selection
"""

from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import time
import json
from pathlib import Path


class MutationEffect(Enum):
    """Mutation effect classification"""
    NEW_COVERAGE = "new_coverage"      # Discovered new coverage
    CRASH = "crash"                    # Caused a crash
    TIMEOUT = "timeout"                # Caused a timeout
    NO_EFFECT = "no_effect"            # No notable effect
    INTERESTING = "interesting"        # Interesting but did not meet above criteria


class MutationType(Enum):
    """Mutation type (corresponding to mutator.py)"""
    BIT_FLIP = "bit_flip"
    ARITHMETIC = "arithmetic"
    INTERESTING_VALUE = "interesting_value"
    BLOCK_DELETION = "block_deletion"
    BLOCK_DUPLICATION = "block_duplication"
    HAVOC = "havoc"
    SPLICE = "splice"
    AFL_DETERMINISTIC = "afl_deterministic"
    AFL_HAVOC = "afl_havoc"
    AFL_SPLICE = "afl_splice"
    UNKNOWN = "unknown"


@dataclass
class MutationNode:
    """
    Node for a single mutation

    Records detailed information and effects of the mutation
    """

    # Unique identifier
    node_id: str  # Format: "iter_{iteration}_mut_{index}"

    # Basic mutation information
    iteration: int
    mutation_index: int  # Index within the current iteration
    mutation_type: MutationType

    # Parent node (based on which trace/mutation)
    parent_trace_id: Optional[str] = None
    parent_mutation_id: Optional[str] = None

    # Mutation details
    syscall_index: Optional[int] = None
    field_name: Optional[str] = None
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None

    # Execution results
    effect: MutationEffect = MutationEffect.NO_EFFECT
    new_edges: int = 0
    total_edges: int = 0
    crashed: bool = False
    timed_out: bool = False

    # Metadata
    timestamp: float = field(default_factory=time.time)
    exec_time: float = 0.0

    # Child nodes (derived mutations)
    children: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (for serialization)"""
        return {
            'node_id': self.node_id,
            'iteration': self.iteration,
            'mutation_index': self.mutation_index,
            'mutation_type': self.mutation_type.value,
            'parent_trace_id': self.parent_trace_id,
            'parent_mutation_id': self.parent_mutation_id,
            'syscall_index': self.syscall_index,
            'field_name': self.field_name,
            'effect': self.effect.value,
            'new_edges': self.new_edges,
            'total_edges': self.total_edges,
            'crashed': self.crashed,
            'timed_out': self.timed_out,
            'timestamp': self.timestamp,
            'exec_time': self.exec_time,
            'children_count': len(self.children),
        }


@dataclass
class DependencyEdge:
    """
    Dependency edge between two mutations

    Represents a parent -> child relationship
    """
    parent_id: str
    child_id: str
    edge_type: str  # "trace_based", "mutation_based", "coverage_based"
    strength: float = 1.0  # Dependency strength (0-1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'parent': self.parent_id,
            'child': self.child_id,
            'type': self.edge_type,
            'strength': self.strength,
        }


@dataclass
class MutationChain:
    """
    Effective mutation chain

    Represents a series of mutations that lead to a specific effect
    """
    chain_id: str
    nodes: List[str]  # List of node_ids
    final_effect: MutationEffect
    total_new_edges: int
    avg_exec_time: float

    def length(self) -> int:
        return len(self.nodes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chain_id': self.chain_id,
            'length': self.length(),
            'nodes': self.nodes,
            'final_effect': self.final_effect.value,
            'total_new_edges': self.total_new_edges,
            'avg_exec_time': self.avg_exec_time,
        }


class MutationDependencyGraph:
    """
    Mutation Dependency Graph

    Tracks relationships between all mutations and analyzes effective strategies
    """

    def __init__(self):
        # All nodes
        self.nodes: Dict[str, MutationNode] = {}

        # All edges
        self.edges: List[DependencyEdge] = []

        # Nodes categorized by effect
        self.nodes_by_effect: Dict[MutationEffect, List[str]] = {
            effect: [] for effect in MutationEffect
        }

        # Nodes categorized by type
        self.nodes_by_type: Dict[MutationType, List[str]] = {
            mut_type: [] for mut_type in MutationType
        }

        # Effective mutation chains
        self.effective_chains: List[MutationChain] = []

        # Statistics
        self.stats = {
            'total_mutations': 0,
            'new_coverage_count': 0,
            'crash_count': 0,
            'timeout_count': 0,
            'no_effect_count': 0,
        }

    def add_mutation(
        self,
        iteration: int,
        mutation_index: int,
        mutation_type: str,
        parent_trace_id: Optional[str] = None,
        syscall_index: Optional[int] = None,
        field_name: Optional[str] = None,
        old_value: Optional[Any] = None,
        new_value: Optional[Any] = None,
    ) -> str:
        """
        Add a new mutation node

        Returns:
            node_id: ID of the new node
        """
        node_id = f"iter_{iteration}_mut_{mutation_index}"

        # Convert mutation_type
        try:
            mut_type_enum = MutationType(mutation_type.lower())
        except ValueError:
            mut_type_enum = MutationType.UNKNOWN

        node = MutationNode(
            node_id=node_id,
            iteration=iteration,
            mutation_index=mutation_index,
            mutation_type=mut_type_enum,
            parent_trace_id=parent_trace_id,
            syscall_index=syscall_index,
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
        )

        self.nodes[node_id] = node
        self.nodes_by_type[mut_type_enum].append(node_id)
        self.stats['total_mutations'] += 1

        return node_id

    def update_mutation_result(
        self,
        node_id: str,
        has_new_coverage: bool = False,
        new_edges: int = 0,
        total_edges: int = 0,
        crashed: bool = False,
        timed_out: bool = False,
        exec_time: float = 0.0,
    ):
        """
        Update the execution result of a mutation
        """
        if node_id not in self.nodes:
            return

        node = self.nodes[node_id]
        node.new_edges = new_edges
        node.total_edges = total_edges
        node.crashed = crashed
        node.timed_out = timed_out
        node.exec_time = exec_time

        # Determine effect
        if crashed:
            node.effect = MutationEffect.CRASH
            self.stats['crash_count'] += 1
        elif timed_out:
            node.effect = MutationEffect.TIMEOUT
            self.stats['timeout_count'] += 1
        elif has_new_coverage:
            node.effect = MutationEffect.NEW_COVERAGE
            self.stats['new_coverage_count'] += 1
        elif new_edges > 0:
            node.effect = MutationEffect.INTERESTING
        else:
            node.effect = MutationEffect.NO_EFFECT
            self.stats['no_effect_count'] += 1

        # Categorize by effect
        self.nodes_by_effect[node.effect].append(node_id)

    def add_dependency(
        self,
        parent_id: str,
        child_id: str,
        edge_type: str = "trace_based",
        strength: float = 1.0
    ):
        """
        Add a dependency edge
        """
        if parent_id not in self.nodes or child_id not in self.nodes:
            return

        edge = DependencyEdge(
            parent_id=parent_id,
            child_id=child_id,
            edge_type=edge_type,
            strength=strength
        )
        self.edges.append(edge)

        # Update parent node's children list
        self.nodes[parent_id].children.append(child_id)

    def find_effective_chains(self, min_length: int = 2) -> List[MutationChain]:
        """
        Find effective mutation chains

        Backtrack from nodes that caused new coverage or crashes to the starting point
        """
        chains = []

        # Find all terminal nodes with effects
        effective_nodes = (
            self.nodes_by_effect[MutationEffect.NEW_COVERAGE] +
            self.nodes_by_effect[MutationEffect.CRASH]
        )

        for end_node_id in effective_nodes:
            chain = self._backtrack_chain(end_node_id)
            if len(chain) >= min_length:
                end_node = self.nodes[end_node_id]

                # Calculate statistics
                total_new_edges = sum(
                    self.nodes[nid].new_edges for nid in chain
                )
                avg_exec_time = sum(
                    self.nodes[nid].exec_time for nid in chain
                ) / len(chain)

                mutation_chain = MutationChain(
                    chain_id=f"chain_to_{end_node_id}",
                    nodes=chain,
                    final_effect=end_node.effect,
                    total_new_edges=total_new_edges,
                    avg_exec_time=avg_exec_time,
                )
                chains.append(mutation_chain)

        self.effective_chains = chains
        return chains

    def _backtrack_chain(self, node_id: str) -> List[str]:
        """
        Backtrack to find the complete mutation chain
        """
        chain = [node_id]
        current_id = node_id

        while True:
            node = self.nodes[current_id]
            if node.parent_mutation_id and node.parent_mutation_id in self.nodes:
                parent_id = node.parent_mutation_id
                chain.insert(0, parent_id)
                current_id = parent_id
            else:
                break

        return chain

    def get_type_effectiveness(self) -> Dict[MutationType, Dict[str, Any]]:
        """
        Analyze the effectiveness of each mutation type

        Returns statistics for each type
        """
        effectiveness = {}

        for mut_type in MutationType:
            node_ids = self.nodes_by_type[mut_type]
            if not node_ids:
                continue

            nodes = [self.nodes[nid] for nid in node_ids]

            total = len(nodes)
            new_coverage = sum(1 for n in nodes if n.effect == MutationEffect.NEW_COVERAGE)
            crashes = sum(1 for n in nodes if n.effect == MutationEffect.CRASH)
            timeouts = sum(1 for n in nodes if n.effect == MutationEffect.TIMEOUT)
            no_effect = sum(1 for n in nodes if n.effect == MutationEffect.NO_EFFECT)

            avg_new_edges = sum(n.new_edges for n in nodes) / total if total > 0 else 0
            avg_exec_time = sum(n.exec_time for n in nodes) / total if total > 0 else 0

            effectiveness[mut_type] = {
                'total': total,
                'new_coverage': new_coverage,
                'crashes': crashes,
                'timeouts': timeouts,
                'no_effect': no_effect,
                'new_coverage_rate': new_coverage / total if total > 0 else 0,
                'crash_rate': crashes / total if total > 0 else 0,
                'avg_new_edges': avg_new_edges,
                'avg_exec_time': avg_exec_time,
            }

        return effectiveness

    def get_top_chains(self, n: int = 10, by: str = "new_edges") -> List[MutationChain]:
        """
        Get the most effective mutation chains

        Args:
            n: Number of results to return
            by: Sort criterion ("new_edges", "length")
        """
        if not self.effective_chains:
            self.find_effective_chains()

        if by == "new_edges":
            sorted_chains = sorted(
                self.effective_chains,
                key=lambda c: c.total_new_edges,
                reverse=True
            )
        elif by == "length":
            sorted_chains = sorted(
                self.effective_chains,
                key=lambda c: c.length(),
                reverse=True
            )
        else:
            sorted_chains = self.effective_chains

        return sorted_chains[:n]

    def generate_report(self) -> str:
        """
        Generate analysis report
        """
        lines = []
        lines.append("=" * 70)
        lines.append("Mutation Dependency Graph Analysis Report")
        lines.append("=" * 70)
        lines.append("")

        # Basic statistics
        lines.append("📊 Basic Statistics:")
        lines.append(f"  Total mutations:     {self.stats['total_mutations']}")
        lines.append(f"  New coverage:        {self.stats['new_coverage_count']} "
                    f"({self.stats['new_coverage_count']/max(1, self.stats['total_mutations'])*100:.1f}%)")
        lines.append(f"  Crashes:             {self.stats['crash_count']}")
        lines.append(f"  Timeouts:            {self.stats['timeout_count']}")
        lines.append(f"  No effect:           {self.stats['no_effect_count']} "
                    f"({self.stats['no_effect_count']/max(1, self.stats['total_mutations'])*100:.1f}%)")
        lines.append("")

        # Type effectiveness analysis
        lines.append("🎯 Mutation Type Effectiveness:")
        effectiveness = self.get_type_effectiveness()

        # Sort by new_coverage_rate
        sorted_types = sorted(
            effectiveness.items(),
            key=lambda x: x[1]['new_coverage_rate'],
            reverse=True
        )

        for mut_type, stats in sorted_types:
            if stats['total'] == 0:
                continue
            lines.append(f"  {mut_type.value}:")
            lines.append(f"    Total:            {stats['total']}")
            lines.append(f"    New coverage:     {stats['new_coverage']} ({stats['new_coverage_rate']*100:.1f}%)")
            lines.append(f"    Crashes:          {stats['crashes']}")
            lines.append(f"    Avg new edges:    {stats['avg_new_edges']:.1f}")
            lines.append(f"    Avg exec time:    {stats['avg_exec_time']*1000:.2f}ms")

        lines.append("")

        # Effective chain analysis
        if self.effective_chains:
            lines.append(f"🔗 Effective Mutation Chains: {len(self.effective_chains)} found")
            top_chains = self.get_top_chains(n=5)

            for i, chain in enumerate(top_chains, 1):
                lines.append(f"  Chain #{i}:")
                lines.append(f"    Length:          {chain.length()}")
                lines.append(f"    Effect:          {chain.final_effect.value}")
                lines.append(f"    Total new edges: {chain.total_new_edges}")
                lines.append(f"    Avg exec time:   {chain.avg_exec_time*1000:.2f}ms")
        else:
            lines.append("🔗 Effective Mutation Chains: None found yet")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)

    def export_to_json(self, output_path: Path):
        """
        Export the complete graph structure to JSON
        """
        data = {
            'nodes': [node.to_dict() for node in self.nodes.values()],
            'edges': [edge.to_dict() for edge in self.edges],
            'chains': [chain.to_dict() for chain in self.effective_chains],
            'stats': self.stats,
            'type_effectiveness': {
                mut_type.value: stats
                for mut_type, stats in self.get_type_effectiveness().items()
            },
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=lambda o: list(o) if isinstance(o, set) else str(o))

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary (for integration into final_stats.json)
        """
        return {
            'total_mutations': self.stats['total_mutations'],
            'new_coverage_count': self.stats['new_coverage_count'],
            'crash_count': self.stats['crash_count'],
            'timeout_count': self.stats['timeout_count'],
            'no_effect_count': self.stats['no_effect_count'],
            'effective_chains_count': len(self.effective_chains),
            'type_effectiveness': {
                mut_type.value: stats
                for mut_type, stats in self.get_type_effectiveness().items()
            },
        }
