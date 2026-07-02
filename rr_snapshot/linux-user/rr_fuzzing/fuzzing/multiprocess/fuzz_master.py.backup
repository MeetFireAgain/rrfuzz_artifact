#!/usr/bin/env python3
"""
FuzzMaster: Multi-process fuzzing coordinator

This module implements the master process that coordinates multiple worker
fuzzing processes for parallel execution on multi-core systems.
"""

import os
import sys
import time
import json
import signal
import hashlib
import multiprocessing as mp
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class WorkerStats:
    """统计信息数据类"""
    worker_id: int
    execs: int = 0
    crashes: int = 0
    hangs: int = 0
    queue_size: int = 0
    coverage: int = 0
    last_update: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FuzzMaster:
    """
    Master进程：管理多个worker fuzzing进程
    
    职责：
    1. 初始化共享目录结构
    2. 启动和管理worker进程池
    3. 定期收集统计信息
    4. 显示实时状态
    5. 优雅关闭和保存状态
    """
    
    def __init__(
        self,
        num_workers: Optional[int] = None,
        sync_dir: str = "./sync_dir",
        program_path: str = None,
        qemu_path: str = None,
        trace_dir: str = None,
        initial_corpus: List[str] = None,
        timeout: int = 1000,
    ):
        """
        初始化FuzzMaster
        
        Args:
            num_workers: Worker进程数量（默认为CPU核心数）
            sync_dir: 共享目录路径
            program_path: 目标程序路径
            qemu_path: QEMU可执行文件路径
            trace_dir: Trace文件目录
            initial_corpus: 初始corpus文件列表
            timeout: 执行超时时间（毫秒）
        """
        self.num_workers = num_workers or os.cpu_count()
        self.sync_dir = Path(sync_dir).resolve()
        self.program_path = program_path
        self.qemu_path = qemu_path
        self.trace_dir = trace_dir
        self.initial_corpus = initial_corpus or []
        self.timeout = timeout
        
        # Worker进程管理
        self.worker_processes: List[mp.Process] = []
        self.shutdown_event = mp.Event()
        
        # 统计信息
        self.start_time = 0
        self.last_stats_time = 0
        
        print(f"🚀 Initializing FuzzMaster with {self.num_workers} workers")
        print(f"📁 Sync directory: {self.sync_dir}")
    
    def _init_sync_dir(self):
        """初始化共享目录结构"""
        print("📂 Initializing sync directory structure...")
        
        # 创建主目录
        self.sync_dir.mkdir(parents=True, exist_ok=True)
        
        # 创建子目录
        (self.sync_dir / "queue").mkdir(exist_ok=True)
        (self.sync_dir / "crashes").mkdir(exist_ok=True)
        (self.sync_dir / "hangs").mkdir(exist_ok=True)
        (self.sync_dir / "stats").mkdir(exist_ok=True)
        (self.sync_dir / "coverage").mkdir(exist_ok=True)
        
        # 为每个worker创建私有队列目录
        for i in range(self.num_workers):
            (self.sync_dir / "queue" / f"worker{i}").mkdir(exist_ok=True)
            (self.sync_dir / "crashes" / f"worker{i}").mkdir(exist_ok=True)
            (self.sync_dir / "hangs" / f"worker{i}").mkdir(exist_ok=True)
        
        # 初始化全局coverage bitmap
        bitmap_file = self.sync_dir / "coverage" / "global_bitmap.bin"
        if not bitmap_file.exists():
            with open(bitmap_file, 'wb') as f:
                f.write(b'\x00' * (1024 * 1024))  # 1MB bitmap
        
        # 初始化版本文件
        version_file = self.sync_dir / "coverage" / "version.txt"
        with open(version_file, 'w') as f:
            f.write("0\n")
        
        print("✓ Sync directory structure initialized")
    
    def _distribute_initial_corpus(self):
        """将初始corpus分配给各个worker"""
        if not self.initial_corpus:
            print("⚠ No initial corpus provided, workers will start with empty queue")
            return
        
        print(f"📦 Distributing {len(self.initial_corpus)} seeds to workers...")
        
        import pickle
        
        for i, seed_path in enumerate(self.initial_corpus):
            # 主要负责的worker（轮流分配）
            primary_worker = i % self.num_workers
            
            try:
                # 读取seed文件
                with open(seed_path, 'rb') as f:
                    seed_data = f.read()
                
                # 写入到worker的队列目录
                dest_path = (
                    self.sync_dir / "queue" / f"worker{primary_worker}" /
                    f"id_{i:06d}_cov_0_depth_0"
                )
                with open(dest_path, 'wb') as f:
                    f.write(seed_data)
                
                # 前10个seed也给前3个worker（冗余，加速启动）
                if i < 10:
                    for w in range(min(3, self.num_workers)):
                        if w != primary_worker:
                            dest_path = (
                                self.sync_dir / "queue" / f"worker{w}" /
                                f"id_{i:06d}_cov_0_depth_0"
                            )
                            with open(dest_path, 'wb') as f:
                                f.write(seed_data)
            
            except Exception as e:
                print(f"⚠ Failed to distribute seed {seed_path}: {e}")
        
        print("✓ Initial corpus distributed")
    
    def _worker_main(self, worker_id: int):
        """
        Worker进程的主函数
        
        Args:
            worker_id: Worker ID
        """
        # 设置进程名称
        try:
            import setproctitle
            setproctitle.setproctitle(f"rr-fuzz-worker-{worker_id}")
        except:
            pass
        
        # 设置CPU亲和性（Linux）
        try:
            os.sched_setaffinity(0, {worker_id % os.cpu_count()})
        except:
            pass
        
        # 导入FuzzConductor（在worker中导入避免主进程依赖）
        # fuzz_conductor.py 在 fuzzing/ 目录下，multiprocess/ 的上一级
        fuzzing_dir = Path(__file__).parent.parent.resolve()
        if str(fuzzing_dir) not in sys.path:
            sys.path.insert(0, str(fuzzing_dir))
        
        # 验证路径
        conductor_path = fuzzing_dir / "fuzz_conductor.py"
        if not conductor_path.exists():
            raise FileNotFoundError(f"Cannot find fuzz_conductor.py at {conductor_path}")
        
        from fuzz_conductor import FuzzConductor
        
        # 创建FuzzConductor实例
        try:
            # FuzzConductor 使用不同的参数名称
            conductor = FuzzConductor(
                qemu_path=self.qemu_path,
                target_binary=self.program_path,
                trace_file=str(Path(self.trace_dir).glob("*.dat").__next__()),  # 获取第一个 .dat 文件
                recipe_file=None,  # 暂不使用 recipe
                init_mode='adaptive'
            )
            
            print(f"✓ Worker {worker_id} initialized (PID: {os.getpid()})")
            
            # 启动 QEMU
            conductor.start_qemu()
            
            # 运行fuzzing循环（无限循环，直到 shutdown_event 触发）
            round_num = 0
            while not self.shutdown_event.is_set():
                try:
                    conductor.run(rounds=100)  # 每批运行 100 次
                    round_num += 1
                    
                    # 定期检查 shutdown
                    if round_num % 10 == 0:
                        if self.shutdown_event.is_set():
                            break
                except Exception as inner_e:
                    print(f"Worker {worker_id} iteration error: {inner_e}")
                    break
            
            # 清理
            conductor.cleanup()
        
        except KeyboardInterrupt:
            print(f"\n⚠ Worker {worker_id} interrupted")
        
        except Exception as e:
            print(f"\n❌ Worker {worker_id} crashed: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            print(f"✓ Worker {worker_id} exiting")
    
    def start(self):
        """启动所有worker进程并进入监控循环"""
        # 初始化环境
        self._init_sync_dir()
        self._distribute_initial_corpus()
        
        # 设置信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        print(f"\n{'='*70}")
        print(f"🚀 Starting {self.num_workers} fuzzing workers...")
        print(f"{'='*70}\n")
        
        # 启动worker进程
        for worker_id in range(self.num_workers):
            p = mp.Process(
                target=self._worker_main,
                args=(worker_id,),
                name=f"Worker-{worker_id}"
            )
            p.start()
            self.worker_processes.append(p)
            time.sleep(0.1)  # 错开启动时间
        
        print(f"✓ All {self.num_workers} workers started\n")
        
        # Master主循环：监控和统计
        self.start_time = time.time()
        self.last_stats_time = self.start_time
        
        try:
            self._master_loop()
        except KeyboardInterrupt:
            print("\n\n🛑 Received interrupt signal, stopping fuzzing...")
            self._stop_all_workers()
    
    def _signal_handler(self, signum, frame):
        """信号处理器"""
        print(f"\n\n🛑 Received signal {signum}, stopping fuzzing...")
        self.shutdown_event.set()
        self._stop_all_workers()
        sys.exit(0)
    
    def _master_loop(self):
        """Master监控循环"""
        update_interval = 10  # 每10秒更新一次
        save_interval = 300   # 每5分钟保存一次
        
        while True:
            time.sleep(update_interval)
            
            # 检查worker状态
            if not self._check_workers_alive():
                print("\n⚠ Some workers have died, stopping...")
                break
            
            # 收集统计信息
            stats = self._collect_stats()
            
            # 显示状态
            self._display_status(stats, time.time() - self.start_time)
            
            # 定期保存全局状态
            if time.time() - self.last_stats_time > save_interval:
                self._save_global_stats(stats)
                self.last_stats_time = time.time()
    
    def _check_workers_alive(self) -> bool:
        """检查worker进程是否存活"""
        for p in self.worker_processes:
            if not p.is_alive():
                return False
        return True
    
    def _collect_stats(self) -> Dict[str, Any]:
        """收集所有worker的统计信息"""
        global_stats = {
            'total_execs': 0,
            'total_crashes': 0,
            'unique_crashes': 0,
            'total_hangs': 0,
            'total_seeds': 0,
            'global_coverage': 0,
        }
        
        worker_stats = []
        
        # 收集每个worker的统计
        for i in range(self.num_workers):
            stats_file = self.sync_dir / "stats" / f"worker{i}_stats.json"
            if stats_file.exists():
                try:
                    with open(stats_file) as f:
                        ws = json.load(f)
                        worker_stats.append(ws)
                        global_stats['total_execs'] += ws.get('execs', 0)
                        global_stats['total_crashes'] += ws.get('crashes', 0)
                        global_stats['total_hangs'] += ws.get('hangs', 0)
                except:
                    worker_stats.append({
                        'worker_id': i,
                        'execs': 0,
                        'crashes': 0,
                        'hangs': 0,
                        'queue_size': 0,
                        'coverage': 0,
                    })
            else:
                worker_stats.append({
                    'worker_id': i,
                    'execs': 0,
                    'crashes': 0,
                    'hangs': 0,
                    'queue_size': 0,
                    'coverage': 0,
                })
        
        # 统计全局seeds数量
        for worker_dir in (self.sync_dir / "queue").iterdir():
            if worker_dir.is_dir():
                global_stats['total_seeds'] += len(list(worker_dir.iterdir()))
        
        # 统计unique crashes（基于文件hash）
        crash_hashes = set()
        for worker_dir in (self.sync_dir / "crashes").iterdir():
            if worker_dir.is_dir():
                for crash_file in worker_dir.glob("crash_*"):
                    try:
                        with open(crash_file, 'rb') as f:
                            crash_hashes.add(hashlib.sha256(f.read()).hexdigest())
                    except:
                        pass
        global_stats['unique_crashes'] = len(crash_hashes)
        
        # 计算全局coverage（从bitmap）
        bitmap_file = self.sync_dir / "coverage" / "global_bitmap.bin"
        try:
            with open(bitmap_file, 'rb') as f:
                bitmap = f.read()
                global_stats['global_coverage'] = sum(1 for b in bitmap if b > 0)
        except:
            pass
        
        return {'global': global_stats, 'workers': worker_stats}
    
    def _display_status(self, stats: Dict[str, Any], elapsed: float):
        """显示fuzzing状态"""
        gs = stats['global']
        
        # 计算执行速度
        execs_per_sec = gs['total_execs'] / elapsed if elapsed > 0 else 0
        
        # 清屏（可选）
        # print("\033[2J\033[H", end='')
        
        print("\n" + "="*70)
        print(f"  RR-Fuzz Multi-Core Status  [{self.num_workers} workers]")
        print("="*70)
        print(f"  Runtime:         {elapsed:.0f}s ({elapsed/60:.1f}m)")
        print(f"  Total Execs:     {gs['total_execs']:,}  "
              f"({execs_per_sec:.1f} exec/s)")
        print(f"  Total Seeds:     {gs['total_seeds']:,}")
        print(f"  Global Coverage: {gs['global_coverage']:,} edges")
        print(f"  Total Crashes:   {gs['total_crashes']}  "
              f"(Unique: {gs['unique_crashes']})")
        print(f"  Total Hangs:     {gs['total_hangs']}")
        print("-"*70)
        
        # 显示每个worker的状态
        for ws in stats['workers']:
            worker_id = ws.get('worker_id', 0)
            execs = ws.get('execs', 0)
            crashes = ws.get('crashes', 0)
            hangs = ws.get('hangs', 0)
            queue_size = ws.get('queue_size', 0)
            coverage = ws.get('coverage', 0)
            
            print(f"  Worker {worker_id}:  "
                  f"{execs:>8,} execs  "
                  f"{crashes:>4} crashes  "
                  f"{hangs:>3} hangs  "
                  f"{queue_size:>5} seeds  "
                  f"{coverage:>5} cov")
        
        print("="*70)
    
    def _save_global_stats(self, stats: Dict[str, Any]):
        """保存全局统计信息"""
        global_stats_file = self.sync_dir / "stats" / "global_stats.json"
        try:
            with open(global_stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            print(f"⚠ Failed to save global stats: {e}")
    
    def _stop_all_workers(self):
        """停止所有worker进程"""
        print("\n🛑 Stopping all workers...")
        
        # 设置shutdown事件
        self.shutdown_event.set()
        
        # 等待进程优雅退出
        for p in self.worker_processes:
            p.join(timeout=5)
        
        # 强制终止未退出的进程
        for p in self.worker_processes:
            if p.is_alive():
                print(f"⚠ Force terminating worker {p.name}")
                p.terminate()
                p.join(timeout=2)
        
        # 最后的统计
        stats = self._collect_stats()
        self._display_status(stats, time.time() - self.start_time)
        self._save_global_stats(stats)
        
        print("\n✓ All workers stopped.")
        print(f"✓ Results saved to: {self.sync_dir}")


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='RR-Fuzz Multi-Core Fuzzing Master'
    )
    parser.add_argument(
        '-n', '--num-workers',
        type=int,
        default=None,
        help='Number of worker processes (default: CPU count)'
    )
    parser.add_argument(
        '-s', '--sync-dir',
        type=str,
        default='./sync_dir',
        help='Synchronization directory path'
    )
    parser.add_argument(
        '-p', '--program',
        type=str,
        required=True,
        help='Target program path'
    )
    parser.add_argument(
        '-q', '--qemu',
        type=str,
        required=True,
        help='QEMU executable path'
    )
    parser.add_argument(
        '-t', '--trace-dir',
        type=str,
        required=True,
        help='Trace directory path'
    )
    parser.add_argument(
        '-i', '--input',
        type=str,
        nargs='+',
        help='Initial corpus files'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=1000,
        help='Execution timeout in milliseconds'
    )
    
    args = parser.parse_args()
    
    # 创建并启动FuzzMaster
    master = FuzzMaster(
        num_workers=args.num_workers,
        sync_dir=args.sync_dir,
        program_path=args.program,
        qemu_path=args.qemu,
        trace_dir=args.trace_dir,
        initial_corpus=args.input,
        timeout=args.timeout,
    )
    
    master.start()


if __name__ == '__main__':
    main()

