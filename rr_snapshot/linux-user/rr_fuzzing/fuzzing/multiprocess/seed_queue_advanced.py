#!/usr/bin/env python3
"""
Advanced Seed Queue with Energy Scheduling

This module provides an enhanced SeedQueue that integrates the AdvancedEnergyScheduler
for intelligent seed selection and energy management.
"""

import heapq
import hashlib
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field

# Import the energy scheduler
from .energy_scheduler import AdvancedEnergyScheduler, ExplorationExploitationBalance, FuzzContext


# Import SeedPriority from coverage_feedback if available, otherwise define it
try:
    from coverage_feedback import SeedPriority
except ImportError:
    from enum import IntEnum

    class SeedPriority(IntEnum):
        LOW = 0
        NORMAL = 1
        HIGH = 2
        CRITICAL = 3

# Always use our extended Seed class for advanced scheduling
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Set

@dataclass(order=True)
class Seed:
    """
    Extended Seed class with additional attributes for advanced energy scheduling.
    
    This extends the basic Seed concept with attributes needed for intelligent
    seed selection and prioritization.
    """
    priority: SeedPriority = field(compare=True, default=SeedPriority.NORMAL)
    energy: float = field(compare=True, default=1.0)
    seed_id: str = field(compare=False, default="")
    trace_file: Optional[str] = field(compare=False, default=None)
    coverage: Set[int] = field(compare=False, default_factory=set)
    parent_id: Optional[str] = field(compare=False, default=None)
    generation: int = field(compare=False, default=0)
    crash: bool = field(compare=False, default=False)
    execution_count: int = field(compare=False, default=0)
    new_coverage_count: int = field(compare=False, default=0)
    
    # Extended attributes for energy scheduling
    discovery_time: float = field(compare=False, default=0.0)
    path_depth: int = field(compare=False, default=0)
    exec_time: float = field(compare=False, default=0.0)
    input_data: Optional[bytes] = field(compare=False, default=None)
    parent_crashed_count: int = field(compare=False, default=0)
    siblings_crashed_count: int = field(compare=False, default=0)


class AdvancedSeedQueue:
    """
    高级Seed队列管理器
    
    集成AdvancedEnergyScheduler，实现智能seed选择：
    1. 基于多因子的能量计算
    2. 探索-利用平衡
    3. 动态能量更新
    4. 优先级堆管理
    """
    
    def __init__(
        self,
        max_size: int = 10000,
        dedup: bool = True,
        use_advanced_scheduling: bool = True,
    ):
        """
        初始化队列
        
        Args:
            max_size: 最大seed数量
            dedup: 是否去重
            use_advanced_scheduling: 是否使用高级能量调度
        """
        self.max_size = max_size
        self.dedup = dedup
        self.use_advanced_scheduling = use_advanced_scheduling
        
        self.seeds: List[Seed] = []  # 最小堆
        self.seed_map: Dict[str, Seed] = {}  # seed_id -> Seed
        self.coverage_hashes: Set[str] = set()  # coverage去重
        
        # 高级调度器
        if use_advanced_scheduling:
            self.energy_scheduler = AdvancedEnergyScheduler()
            self.explore_exploit_balance = ExplorationExploitationBalance()
        else:
            self.energy_scheduler = None
            self.explore_exploit_balance = None
        
        # 统计信息
        self.stats = {
            'total_added': 0,
            'duplicates_rejected': 0,
            'pruned': 0,
            'total_execs': 0,
            'no_new_coverage_count': 0,
        }
        
        # Fuzzing上下文（用于能量计算）
        self.context = FuzzContext(
            current_time=0.0,
            total_execs=0,
            global_coverage=set(),
            no_new_coverage_count=0,
        )
        
        print(f"[SeedQueue] Initialized (advanced_scheduling={use_advanced_scheduling})")
    
    def add(self, seed: Seed) -> bool:
        """
        添加seed到队列
        
        Returns:
            True if added, False if rejected (duplicate/full)
        """
        # ✅ 2025-11-18: 改进去重检查 - 只拒绝完全相同coverage且无新edges的seed
        if self.dedup:
            cov_hash = self._hash_coverage(seed.coverage)
            # 如果有新coverage（new_coverage_count > 0），总是接受
            if seed.new_coverage_count > 0:
                self.coverage_hashes.add(cov_hash)
            elif cov_hash in self.coverage_hashes:
                # 无新coverage且coverage hash重复，才拒绝
                self.stats['duplicates_rejected'] += 1
                return False
            else:
                self.coverage_hashes.add(cov_hash)
        
        # 如果使用高级调度，计算初始能量
        if self.use_advanced_scheduling and self.energy_scheduler:
            import time
            seed.discovery_time = time.time()
            initial_energy = self.energy_scheduler.calculate_energy(seed, self.context)
            seed.energy = initial_energy
        
        # 添加到队列
        heapq.heappush(self.seeds, seed)
        self.seed_map[seed.seed_id] = seed
        self.stats['total_added'] += 1
        
        # 队列大小控制
        if len(self.seeds) > self.max_size:
            self._prune()
        
        return True
    
    def pop(self, context: Optional[FuzzContext] = None) -> Optional[Seed]:
        """
        获取下一个seed（智能选择）
        
        Args:
            context: Fuzzing上下文（用于能量计算）
        
        Returns:
            选中的seed，如果队列为空则返回None
        """
        if not self.seeds:
            return None
        
        # 更新上下文
        if context:
            self.context = context
        
        # 高级调度模式
        if self.use_advanced_scheduling and self.energy_scheduler:
            return self._pop_advanced()
        # 简单模式（兼容旧版本）
        else:
            return self._pop_simple()
    
    def _pop_advanced(self) -> Optional[Seed]:
        """高级调度的pop"""
        # 1. 更新探索-利用平衡
        if self.explore_exploit_balance:
            self.explore_exploit_balance.update_phase({
                'total_execs': self.stats['total_execs'],
                'no_new_coverage_count': self.stats['no_new_coverage_count'],
            })
        
        # 2. 决定探索还是利用
        is_exploration = (
            self.explore_exploit_balance.should_explore()
            if self.explore_exploit_balance
            else False
        )
        
        # 3. 根据模式选择seed
        if is_exploration:
            # 探索模式：更倾向于选择多样化的seeds
            selected_seed = self._select_diverse_seed()
        else:
            # 利用模式：选择最高能量的seed
            selected_seed = self._select_best_seed()
        
        if not selected_seed:
            return None
        
        # 4. 更新执行计数
        selected_seed.execution_count += 1
        self.stats['total_execs'] += 1
        
        # 5. 重新计算能量
        new_energy = self.energy_scheduler.calculate_energy(selected_seed, self.context)
        
        # 6. 决定是否重新入队
        if new_energy > 0.1 and not selected_seed.crash:
            # 更新能量并重新入队
            selected_seed.energy = new_energy * 0.9  # 稍微降低
            heapq.heappush(self.seeds, selected_seed)
        else:
            # 能量耗尽，从map移除
            if selected_seed.seed_id in self.seed_map:
                del self.seed_map[selected_seed.seed_id]
        
        return selected_seed
    
    def _pop_simple(self) -> Optional[Seed]:
        """简单模式的pop（兼容旧版本）"""
        seed = heapq.heappop(self.seeds)
        seed.execution_count += 1
        self.stats['total_execs'] += 1
        
        # 简单能量递减
        if seed.energy > 0.1 and not seed.crash:
            seed.energy *= 0.9
            heapq.heappush(self.seeds, seed)
        else:
            if seed.seed_id in self.seed_map:
                del self.seed_map[seed.seed_id]
        
        return seed
    
    def _select_best_seed(self) -> Optional[Seed]:
        """选择最高能量的seed"""
        if not self.seeds:
            return None
        
        # 从堆顶弹出（最高优先级/能量）
        return heapq.heappop(self.seeds)
    
    def _select_diverse_seed(self) -> Optional[Seed]:
        """选择多样化的seed（探索模式）"""
        if not self.seeds:
            return None
        
        # 策略：从top N中随机选择（增加多样性）
        n = min(10, len(self.seeds))
        top_seeds = heapq.nsmallest(n, self.seeds)
        
        import random
        selected = random.choice(top_seeds)
        
        # 从堆中移除
        self.seeds.remove(selected)
        heapq.heapify(self.seeds)
        
        return selected
    
    def update_context(
        self,
        global_coverage: Optional[Set[int]] = None,
        new_coverage_found: bool = False,
    ):
        """
        更新fuzzing上下文
        
        Args:
            global_coverage: 全局coverage集合
            new_coverage_found: 是否发现了新coverage
        """
        import time
        self.context.current_time = time.time()
        
        if global_coverage is not None:
            self.context.global_coverage = global_coverage
        
        if new_coverage_found:
            self.stats['no_new_coverage_count'] = 0
        else:
            self.stats['no_new_coverage_count'] += 1
    
    def _hash_coverage(self, coverage: Set[int]) -> str:
        """计算coverage的hash（用于去重）"""
        sorted_cov = sorted(coverage)
        cov_str = ','.join(map(str, sorted_cov))
        return hashlib.md5(cov_str.encode()).hexdigest()
    
    def _prune(self):
        """修剪队列（移除低价值seeds）"""
        # 保留前 80% 的seeds
        target_size = int(self.max_size * 0.8)
        
        if len(self.seeds) <= target_size:
            return
        
        # 移除能量最低的seeds
        seeds_to_keep = heapq.nlargest(target_size, self.seeds)
        seeds_to_remove = set(self.seeds) - set(seeds_to_keep)
        
        for seed in seeds_to_remove:
            if seed.seed_id in self.seed_map:
                del self.seed_map[seed.seed_id]
            if self.dedup:
                cov_hash = self._hash_coverage(seed.coverage)
                if cov_hash in self.coverage_hashes:
                    self.coverage_hashes.remove(cov_hash)
        
        self.seeds = seeds_to_keep
        heapq.heapify(self.seeds)
        
        self.stats['pruned'] += len(seeds_to_remove)
    
    def is_empty(self) -> bool:
        """检查队列是否为空"""
        return len(self.seeds) == 0
    
    def size(self) -> int:
        """获取队列大小"""
        return len(self.seeds)
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            **self.stats,
            'queue_size': len(self.seeds),
            'exploration_rate': (
                self.explore_exploit_balance.exploration_rate
                if self.explore_exploit_balance
                else 0.0
            ),
        }


def test_advanced_seed_queue():
    """测试高级seed队列"""
    print("Testing AdvancedSeedQueue...")
    
    import time
    
    # 创建队列
    queue = AdvancedSeedQueue(max_size=100, use_advanced_scheduling=True)
    
    # 添加测试seeds
    for i in range(10):
        seed = Seed(
            seed_id=f"seed_{i}",
            priority=SeedPriority.NORMAL,
            coverage={i, i+1, i+2},
            path_depth=i * 10,
            exec_time=0.1 * i,
            input_data=f"test_data_{i}".encode(),
            discovery_time=time.time(),
        )
        queue.add(seed)
    
    print(f"Queue size: {queue.size()}")
    
    # 更新上下文
    queue.update_context(global_coverage={0, 1, 2}, new_coverage_found=True)
    
    # Pop几个seeds
    for i in range(5):
        seed = queue.pop()
        if seed:
            print(f"Popped: {seed.seed_id}, energy={seed.energy:.2f}, "
                  f"exec_count={seed.execution_count}")
    
    # 获取统计
    stats = queue.get_stats()
    print(f"Stats: {stats}")
    
    print("✓ AdvancedSeedQueue test passed")


if __name__ == '__main__':
    test_advanced_seed_queue()

