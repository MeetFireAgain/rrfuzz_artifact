#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Crash Analysis and Triaging Module

Responsible for:
1. Collecting crash information
2. Computing crash hashes for deduplication
3. Classifying crash priorities
4. Managing the crash database
"""

import hashlib
import json
import struct
import fcntl
import os
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
from datetime import datetime


# Signal name mapping
SIGNAL_NAMES = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
}


@dataclass
class CrashInfo:
    """Crash Information"""
    crash_id: str                    # Unique ID
    signal: int                      # Signal number
    signal_name: str                 # Signal name
    pc: int                          # Program Counter
    fault_address: Optional[int]     # Fault address (SIGSEGV, etc.)
    backtrace: List[str]             # Call stack
    syscall_index: int               # Index of syscall that triggered the crash
    mutation_recipe: Dict            # Mutation recipe used
    timestamp: str                   # Time of occurrence
    crash_hash: str                  # Hash used for deduplication
    priority: str                    # Priority: HIGH/MEDIUM/LOW
    exploitability: str              # Exploitability assessment
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: Dict) -> 'CrashInfo':
        """Create from dictionary"""
        return CrashInfo(**data)


class CrashAnalyzer:
    """Crash Analyzer"""
    
    def __init__(self, output_dir: Path, worker_id: int = 0, target_name: str = ""):
        """
        Initialize Crash Analyzer

        Args:
            output_dir: Output directory
            worker_id: Unique worker ID for naming
            target_name: Target binary name (included in hash to prevent cross-target collisions)
        """
        self.output_dir = Path(output_dir)
        self.worker_id = worker_id
        self.target_name = target_name
        self.crashes_dir = self.output_dir / "crashes"
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        
        self.crash_db_file = self.crashes_dir / "crash_db.json"
        self.crashes: Dict[str, Dict] = self._load_crash_db()
        
        self.unique_hashes: Set[str] = set(self.crashes.keys())
    
    def _load_crash_db(self) -> Dict:
        """Load known crash database (with locking for multi-process support)"""
        if not self.crash_db_file.exists():
            return {}
            
        try:
            with open(self.crash_db_file, 'r') as f:
                # Acquire shared lock for reading
                fcntl.flock(f, fcntl.LOCK_SH)
                try:
                    data = json.load(f)
                    return data
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as e:
            print(f"[CrashAnalyzer] Warning: Failed to load crash DB: {e}")
            return {}
    
    def _save_crash_db(self):
        """Save crash database (atomic write + lock for multi-process safety)"""
        lock_file = self.crash_db_file.with_suffix(self.crash_db_file.suffix + '.lock')
        tmp_file = self.crash_db_file.with_suffix(self.crash_db_file.suffix + '.tmp')

        try:
            lock_file.parent.mkdir(parents=True, exist_ok=True)
            with open(lock_file, 'a+') as lockf:
                # Acquire exclusive process lock for full read-merge-write cycle
                fcntl.flock(lockf, fcntl.LOCK_EX)
                try:
                    # Reload latest on-disk DB before writing to avoid lost updates
                    if self.crash_db_file.exists():
                        try:
                            with open(self.crash_db_file, 'r') as rf:
                                on_disk = json.load(rf)
                            for h, data in on_disk.items():
                                if h in self.crashes:
                                    self.crashes[h]['count'] = max(self.crashes[h]['count'], data.get('count', 0))
                                    existing_ids = set(self.crashes[h].get('crash_ids', []))
                                    for cid in data.get('crash_ids', []):
                                        if cid not in existing_ids:
                                            self.crashes[h]['crash_ids'].append(cid)
                                else:
                                    self.crashes[h] = data
                                    self.unique_hashes.add(h)
                        except Exception:
                            pass

                    # Atomic write: write to temp, fsync, then replace
                    with open(tmp_file, 'w') as wf:
                        json.dump(self.crashes, wf, indent=2)
                        wf.flush()
                        os.fsync(wf.fileno())
                    os.replace(tmp_file, self.crash_db_file)
                finally:
                    fcntl.flock(lockf, fcntl.LOCK_UN)
        except Exception as e:
            print(f"[CrashAnalyzer] Error: Failed to save crash DB: {e}")
            try:
                if tmp_file.exists():
                    tmp_file.unlink()
            except Exception:
                pass
    
    def analyze_crash(self, qemu_status: Dict, mutation_recipe: Dict, 
                     iteration: int = 0) -> CrashInfo:
        """
        Analyze a crash
        
        Args:
            qemu_status: Status information returned by QEMU
            mutation_recipe: Mutation recipe used
            iteration: Fuzzing iteration count
        
        Returns:
            CrashInfo object
        """
        # Extract signal information
        signal = qemu_status.get('signal', 0)
        signal_name = self._get_signal_name(signal)
        
        # Extract PC
        pc = qemu_status.get('pc', 0)
        
        # Extract fault address (for SIGSEGV/SIGBUS)
        fault_address = qemu_status.get('fault_address', None)
        
        # Extract call stack
        backtrace = qemu_status.get('backtrace', [])
        if isinstance(backtrace, str):
            backtrace = [backtrace]
        
        # Extract syscall index
        syscall_index = qemu_status.get('syscall_index', 
                                       mutation_recipe.get('syscall_index', -1))
        
        # Generate crash hash (for deduplication)
        crash_hash = self._compute_crash_hash(signal, pc, backtrace)
        
        # Determine priority
        priority = self._classify_priority(signal, pc, fault_address)
        
        # Assess exploitability
        exploitability = self._assess_exploitability(signal, pc, fault_address, backtrace)
        
        # Generate unique ID (include worker_id to avoid collisions)
        crash_id = f"crash_w{self.worker_id}_{iteration:06d}_{crash_hash[:8]}"
        
        # Create crash info
        crash_info = CrashInfo(
            crash_id=crash_id,
            signal=signal,
            signal_name=signal_name,
            pc=pc,
            fault_address=fault_address,
            backtrace=backtrace[:10],  # Only keep the first 10 frames
            syscall_index=syscall_index,
            mutation_recipe=mutation_recipe,
            timestamp=datetime.now().isoformat(),
            crash_hash=crash_hash,
            priority=priority,
            exploitability=exploitability
        )
        
        return crash_info
    
    def _compute_crash_hash(self, signal: int, pc: int, backtrace: List[str]) -> str:
        """
        Compute crash hash for deduplication

        Uses signal + PC + first 3 frames of the call stack.
        When backtrace is empty and PC is in ASLR-variable range
        (x86-64 stack/heap: 0x7f0000000000+, or corrupted retaddr
        pattern ending in a common suffix), normalise PC to 1MB
        granularity to avoid every heap-overflow crash being unique.
        """
        # Normalise ASLR-variable PCs for 64-bit targets (x86-64, aarch64).
        # Any PC above 4GB (0x100000000) without a backtrace is treated as
        # ASLR-variable — corrupted stack return addresses on 64-bit vary by
        # 40+ bits per run. Without a stable backtrace anchor, collapse to
        # signal-only to avoid every heap-overflow crash being unique.
        # Examples caught: 0x6fff7ed22ec1, 0x7f3a1b2c3d4e, 0x7fffffffe8c0.
        effective_pc = pc
        if not backtrace and pc > 0x100000000:
            effective_pc = 0  # signal-only grouping for ASLR heap overflows

        hash_components = [
            f"target:{self.target_name}" if self.target_name else "target:unknown",
            f"sig:{signal}",
            f"pc:{effective_pc:#x}" if effective_pc else "pc:unknown",
        ]

        # Add the first 3 frames of the call stack
        for i, frame in enumerate(backtrace[:3]):
            if isinstance(frame, str):
                hash_components.append(f"frame{i}:{frame}")
            elif isinstance(frame, int):
                hash_components.append(f"frame{i}:{frame:#x}")

        hash_input = ":".join(hash_components)
        return hashlib.sha256(hash_input.encode()).hexdigest()
    
    def _classify_priority(self, signal: int, pc: int, fault_address: Optional[int]) -> str:
        """
        Classify crash priority
        
        HIGH:   Potentially exploitable crash
        MEDIUM: Normal crash
        LOW:    Unlikely to be exploitable
        """
        # HIGH priority conditions
        if signal == 11 and fault_address is not None:  # SIGSEGV
            # Near NULL pointer (potentially controllable)
            if fault_address < 0x10000:
                return "HIGH"
            # Near stack/heap boundary
            if 0x7fff00000000 <= fault_address <= 0x7fffffffffff:
                return "HIGH"
        
        if signal == 6:  # SIGABRT
            # Usually indicates heap corruption or assertion failure
            return "HIGH"
        
        if signal == 4:  # SIGILL
            # Illegal instruction, potentially code overwrite
            return "HIGH"
        
        if pc == 0 or (pc is not None and pc < 0x1000):
            # PC jump near NULL
            return "HIGH"
        
        # MEDIUM priority
        if signal == 11:  # SIGSEGV
            return "MEDIUM"

        if signal == 7:  # SIGBUS
            return "MEDIUM"

        if signal == 8:  # SIGFPE
            return "MEDIUM"

        # LOW priority
        return "LOW"
    
    def _assess_exploitability(self, signal: int, pc: int, 
                               fault_address: Optional[int], 
                               backtrace: List[str]) -> str:
        """
        Assess exploitability
        
        Returns:
            "EXPLOITABLE", "PROBABLY_EXPLOITABLE", "PROBABLY_NOT_EXPLOITABLE", "UNKNOWN"
        """
        # EXPLOITABLE: Obviously exploitable
        if signal == 11 and fault_address is not None:
            # Controllable small address (potentially pointer overwrite)
            if 0 < fault_address < 0x10000:
                return "EXPLOITABLE"
        
        if pc == 0 or (pc is not None and pc < 0x1000):
            # PC overwritten by NULL
            return "EXPLOITABLE"
        
        if signal == 6:  # SIGABRT from heap corruption
            # Heap corruption is usually exploitable
            if any('heap' in str(frame).lower() or 'malloc' in str(frame).lower() 
                   for frame in backtrace):
                return "PROBABLY_EXPLOITABLE"
        
        # PROBABLY_EXPLOITABLE
        if signal in [4, 11]:  # SIGILL, SIGSEGV
            return "PROBABLY_EXPLOITABLE"
        
        # PROBABLY_NOT_EXPLOITABLE
        if signal in [8, 13]:  # SIGFPE, SIGPIPE
            return "PROBABLY_NOT_EXPLOITABLE"
        
        # UNKNOWN
        return "UNKNOWN"
    
    def _get_signal_name(self, signal: int) -> str:
        """Convert signal number to name"""
        return SIGNAL_NAMES.get(signal, f"SIG{signal}")
    
    def is_duplicate(self, crash_info: CrashInfo) -> bool:
        """Check if it's a duplicate crash"""
        return crash_info.crash_hash in self.unique_hashes
    
    def save_crash(self, crash_info: CrashInfo, save_details: bool = True):
        """
        Save crash
        
        Args:
            crash_info: Crash information
            save_details: Whether to save detailed information to a separate file
        """
        if self.is_duplicate(crash_info):
            # Update count
            self.crashes[crash_info.crash_hash]['count'] += 1
            self.crashes[crash_info.crash_hash]['last_seen'] = crash_info.timestamp
            self.crashes[crash_info.crash_hash]['crash_ids'].append(crash_info.crash_id)
        else:
            # New crash
            self.crashes[crash_info.crash_hash] = {
                'count': 1,
                'first_seen': crash_info.timestamp,
                'last_seen': crash_info.timestamp,
                'crash_ids': [crash_info.crash_id],
                'info': crash_info.to_dict()
            }
            self.unique_hashes.add(crash_info.crash_hash)
            
            # Save detailed information to a separate file
            if save_details:
                crash_file = self.crashes_dir / f"{crash_info.crash_id}.json"
                try:
                    with open(crash_file, 'w') as f:
                        json.dump(crash_info.to_dict(), f, indent=2)
                except Exception as e:
                    print(f"[CrashAnalyzer] Warning: Failed to save crash details: {e}")
        
        # Save database
        self._save_crash_db()
    
    def get_unique_crashes(self, sort_by: str = 'priority') -> List[Dict]:
        """
        Get deduplicated crash list
        
        Args:
            sort_by: Sorting method: 'priority', 'count', 'time', 'exploitability'
        
        Returns:
            Sorted crash list
        """
        crashes = list(self.crashes.values())
        
        if sort_by == 'priority':
            priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
            crashes.sort(key=lambda c: (
                priority_order.get(c['info']['priority'], 99),
                -c['count']  # Same priority sorted by count descending
            ))
        elif sort_by == 'exploitability':
            exploit_order = {
                'EXPLOITABLE': 0,
                'PROBABLY_EXPLOITABLE': 1,
                'PROBABLY_NOT_EXPLOITABLE': 2,
                'UNKNOWN': 3
            }
            crashes.sort(key=lambda c: (
                exploit_order.get(c['info']['exploitability'], 99),
                -c['count']
            ))
        elif sort_by == 'count':
            crashes.sort(key=lambda c: -c['count'])
        elif sort_by == 'time':
            crashes.sort(key=lambda c: c['first_seen'], reverse=True)
        
        return crashes
    
    def get_crash_by_hash(self, crash_hash: str) -> Optional[Dict]:
        """Get crash information by hash"""
        return self.crashes.get(crash_hash)
    
    def get_statistics(self) -> Dict:
        """Get statistics"""
        unique_count = len(self.crashes)
        total_count = sum(c['count'] for c in self.crashes.values())
        
        # Statistics by priority
        priority_stats = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for crash_data in self.crashes.values():
            priority = crash_data['info']['priority']
            priority_stats[priority] = priority_stats.get(priority, 0) + 1
        
        # Statistics by exploitability
        exploit_stats = {
            'EXPLOITABLE': 0,
            'PROBABLY_EXPLOITABLE': 0,
            'PROBABLY_NOT_EXPLOITABLE': 0,
            'UNKNOWN': 0
        }
        for crash_data in self.crashes.values():
            exploit = crash_data['info']['exploitability']
            exploit_stats[exploit] = exploit_stats.get(exploit, 0) + 1
        
        # Statistics by signal
        signal_stats = {}
        for crash_data in self.crashes.values():
            signal_name = crash_data['info']['signal_name']
            signal_stats[signal_name] = signal_stats.get(signal_name, 0) + 1
        
        return {
            'unique_crashes': unique_count,
            'total_crashes': total_count,
            'dedup_rate': (total_count - unique_count) / total_count * 100 if total_count > 0 else 0,
            'priority_distribution': priority_stats,
            'exploitability_distribution': exploit_stats,
            'signal_distribution': signal_stats
        }
    
    def print_summary(self, top_n: int = 10, verbose: bool = False):
        """
        Print crash summary
        
        Args:
            top_n: Show top N crashes
            verbose: Whether to show detailed information
        """

        # Force reload from disk to ensure we have the latest data
        self.crashes = self._load_crash_db()
        stats = self.get_statistics()
        
        # print(f"\n{'='*80}")
        # print(f"Crash Analysis Summary")
        # print(f"{'='*80}")
        
        print("-" * 70)
        print(f"{'📊 Crash Analysis Report':^70}")
        print("-" * 70)
        
        # Row 1: General & Signal
        print(f" │ {'📉 Statistic Overview':<32} │ {'🔍 Top Signals':<32} │")
        print(f" │ {'─'*32} │ {'─'*32} │")
        
        # General Stats
        dedup_rate = f"{stats['dedup_rate']:.1f}%"
        print(f" │ Unique Crashes: {stats['unique_crashes']:<16} │ {self._fmt_signal(stats, 0):<30} │")
        print(f" │ Total Crashes : {stats['total_crashes']:<16} │ {self._fmt_signal(stats, 1):<30} │")
        print(f" │ Dedup Rate    : {dedup_rate:<16} │ {self._fmt_signal(stats, 2):<30} │")
        print(" " + "─"*70)
        
        # Row 2: Distributions
        print(f" │ {'🎯 Priority Distribution':<32} │ {'💥 Exploitability':<32} │")
        print(f" │ {'─'*32} │ {'─'*32} │")
        
        # Format Priority (Top 3)
        p_keys = list(stats['priority_distribution'].keys())
        e_keys = list(stats['exploitability_distribution'].keys())
        
        for i in range(max(len(p_keys), len(e_keys), 3)):
            if i >= 3: break # Limit to 3 rows
            
            p_str = ""
            if i < len(p_keys):
                k = p_keys[i]
                v = stats['priority_distribution'][k]
                pct = v / stats['unique_crashes'] * 100 if stats['unique_crashes'] > 0 else 0
                p_str = f"{k:<6}: {v} ({pct:.0f}%)"
            
            e_str = ""
            if i < len(e_keys):
                k = e_keys[i]
                v = stats['exploitability_distribution'][k]
                pct = v / stats['unique_crashes'] * 100 if stats['unique_crashes'] > 0 else 0
                # Abbreviate long names
                short_k = k.replace('PROBABLY_', 'P.').replace('EXPLOITABLE', 'EXP')
                e_str = f"{short_k:<12}: {v} ({pct:.0f}%)"
                
            print(f" │ {p_str:<32} │ {e_str:<32} │")
            
        print("-" * 70)

    def _fmt_signal(self, stats, idx):
        sorted_sigs = sorted(stats['signal_distribution'].items(), key=lambda x: x[1], reverse=True)
        if idx < len(sorted_sigs):
            sig, count = sorted_sigs[idx]
            return f"{sig}: {count}"
        return ""
        
        if stats['unique_crashes'] > 0:
            print(f"\n🏆 Top {min(top_n, stats['unique_crashes'])} Unique Crashes:")
            print(f"{'#':<4} {'Priority':<8} {'Exploit':<28} {'Signal':<10} {'PC':>18} {'Count':>6}")
            print("-" * 60)
            
            for i, crash_data in enumerate(self.get_unique_crashes()[:top_n], 1):
                info = crash_data['info']
                count = crash_data['count']
                
                pc_str = f"0x{info['pc']:x}" if info['pc'] else "unknown"
                
                print(f"{i:<4} {info['priority']:<8} {info['exploitability']:<28} "
                      f"{info['signal_name']:<10} {pc_str:>18} {count:>6}")
                
                if verbose:
                    print(f"     Hash: {info['crash_hash'][:16]}...")
                    print(f"     Syscall: #{info['syscall_index']}")
                    if info['fault_address'] is not None:
                        print(f"     Fault addr: 0x{info['fault_address']:x}")
                    if info['backtrace']:
                        print(f"     Backtrace: {info['backtrace'][:2]}")
                    print()
        
        # print(f"{'='*80}\n")
    
    def export_to_file(self, output_file: Path, format: str = 'json'):
        """
        Export crash data to file
        
        Args:
            output_file: Output file path
            format: Output format ('json' or 'csv')
        """
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump({
                    'statistics': self.get_statistics(),
                    'crashes': self.get_unique_crashes()
                }, f, indent=2, default=lambda o: list(o) if isinstance(o, set) else str(o))
        elif format == 'csv':
            import csv
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Hash', 'Priority', 'Exploitability', 'Signal', 'PC', 
                                'Fault Addr', 'Count', 'First Seen', 'Last Seen'])
                
                for crash_data in self.get_unique_crashes():
                    info = crash_data['info']
                    writer.writerow([
                        info['crash_hash'][:16],
                        info['priority'],
                        info['exploitability'],
                        info['signal_name'],
                        f"0x{info['pc']:x}" if info['pc'] else "",
                        f"0x{info['fault_address']:x}" if info['fault_address'] else "",
                        crash_data['count'],
                        crash_data['first_seen'],
                        crash_data['last_seen']
                    ])
        
        print(f"[CrashAnalyzer] Exported crash data to {output_file}")


def main():
    """Test Entry Point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Crash Analyzer Tool')
    parser.add_argument('crash_dir', help='Crashes directory')
    parser.add_argument('--top', type=int, default=10, help='Show top N crashes')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--export', help='Export to file (JSON or CSV)')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format')
    
    args = parser.parse_args()
    
    # Load crash analyzer
    analyzer = CrashAnalyzer(Path(args.crash_dir))
    
    # Print summary
    analyzer.print_summary(top_n=args.top, verbose=args.verbose)
    
    # Export (if specified)
    if args.export:
        analyzer.export_to_file(Path(args.export), format=args.format)


if __name__ == "__main__":
    main()

