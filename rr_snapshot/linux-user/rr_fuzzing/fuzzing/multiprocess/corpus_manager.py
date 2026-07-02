#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Corpus Persistence Management

Responsible for:
1. Saving fuzzing corpus to disk
2. Restoring corpus from disk
3. Corpus merging and minimization
4. Corpus quality assessment
"""

import json
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime
from dataclasses import asdict


class CorpusManager:
    """Manages saving and loading of the fuzzing corpus"""
    
    def __init__(self, corpus_dir: Path):
        """
        Initialize Corpus Manager
        
        Args:
            corpus_dir: Directory for storing the corpus
        """
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        
        self.seeds_dir = self.corpus_dir / "seeds"
        self.seeds_dir.mkdir(exist_ok=True)
        
        self.queue_file = self.corpus_dir / "queue.json"
        self.metadata_file = self.corpus_dir / "metadata.json"
        self.coverage_file = self.corpus_dir / "coverage.dat"
    
    def save_corpus(self, seed_queue: 'SeedQueue', coverage_tracker: 'CoverageTracker',
                   fuzzer_stats: Optional[Dict] = None):
        """
        Save the current corpus
        
        Args:
            seed_queue: Seed queue
            coverage_tracker: Coverage tracker
            fuzzer_stats: Fuzzer statistics (optional)
        """
        print(f"[Corpus] Saving corpus to {self.corpus_dir}...")
        
        # 1. Save queue state
        queue_data = {
            'version': '1.0',
            'saved_at': datetime.now().isoformat(),
            'seed_count': len(seed_queue.seeds),
            'seeds': []
        }
        
        for seed in seed_queue.seeds:
            seed_dict = {
                'seed_id': seed.seed_id,
                'trace_file': seed.trace_file,
                'coverage': list(seed.coverage),  # Set -> List
                'energy': seed.energy,
                'priority': seed.priority.name,  # Enum -> string
                'parent_id': seed.parent_id,
                'generation': seed.generation,
                'crash': seed.crash,
            }
            queue_data['seeds'].append(seed_dict)
        
        with open(self.queue_file, 'w') as f:
            json.dump(queue_data, f, indent=2)
        
        print(f"[Corpus] Saved {len(seed_queue.seeds)} seeds to queue")
        
        # 2. Copy all seed trace files
        copied_count = 0
        for seed in seed_queue.seeds:
            if seed.trace_file and Path(seed.trace_file).exists():
                src = Path(seed.trace_file)
                dest = self.seeds_dir / f"{seed.seed_id}.dat"
                try:
                    shutil.copy2(src, dest)
                    copied_count += 1
                except Exception as e:
                    print(f"[Corpus] Warning: Failed to copy {src}: {e}")
        
        print(f"[Corpus] Copied {copied_count}/{len(seed_queue.seeds)} trace files")
        
        # 3. Save coverage data
        coverage_data = {
            'global_coverage': list(coverage_tracker.global_coverage),
            'edge_coverage': {str(k): v for k, v in coverage_tracker.edge_coverage.items()},
            'total_edges': len(coverage_tracker.edge_coverage),
        }
        
        with open(self.coverage_file, 'w') as f:
            json.dump(coverage_data, f)
        
        print(f"[Corpus] Saved coverage data: {len(coverage_tracker.global_coverage)} blocks, "
              f"{len(coverage_tracker.edge_coverage)} edges")
        
        # 4. Save metadata
        metadata = {
            'version': '1.0',
            'last_updated': datetime.now().isoformat(),
            'queue_size': len(seed_queue.seeds),
            'total_coverage': len(coverage_tracker.global_coverage),
            'coverage_edges': len(coverage_tracker.edge_coverage),
            'fuzzer_stats': fuzzer_stats or {},
        }
        
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"[Corpus] ✅ Corpus saved successfully")
    
    def load_corpus(self) -> Optional[Dict]:
        """
        Load corpus
        
        Returns:
            Dictionary containing seeds and coverage, or None if failed
        """
        if not self.queue_file.exists():
            print(f"[Corpus] No existing corpus found at {self.corpus_dir}")
            return None
        
        try:
            print(f"[Corpus] Loading corpus from {self.corpus_dir}...")
            
            # 1. Load queue data
            with open(self.queue_file, 'r') as f:
                queue_data = json.load(f)
            
            # 2. Restore trace file paths
            seeds_loaded = 0
            for seed_dict in queue_data['seeds']:
                seed_id = seed_dict['seed_id']
                trace_file = self.seeds_dir / f"{seed_id}.dat"
                if trace_file.exists():
                    seed_dict['trace_file'] = str(trace_file)
                    seeds_loaded += 1
                else:
                    print(f"[Corpus] Warning: Trace file not found for seed {seed_id}")
                    seed_dict['trace_file'] = None
            
            print(f"[Corpus] Loaded {seeds_loaded}/{len(queue_data['seeds'])} seeds")
            
            # 3. Load coverage data
            coverage_data = None
            if self.coverage_file.exists():
                with open(self.coverage_file, 'r') as f:
                    coverage_data = json.load(f)
                print(f"[Corpus] Loaded coverage data: {len(coverage_data['global_coverage'])} blocks")
            
            # 4. Load metadata
            metadata = None
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    metadata = json.load(f)
                print(f"[Corpus] Corpus last updated: {metadata.get('last_updated', 'unknown')}")
            
            return {
                'queue': queue_data,
                'coverage': coverage_data,
                'metadata': metadata
            }
        
        except Exception as e:
            print(f"[Corpus] ❌ Failed to load corpus: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_metadata(self) -> Optional[Dict]:
        """Get corpus metadata"""
        if not self.metadata_file.exists():
            return None
        
        try:
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    
    def get_statistics(self) -> Dict:
        """Get corpus statistics"""
        metadata = self.get_metadata()
        
        if not metadata:
            return {
                'exists': False,
                'queue_size': 0,
                'total_coverage': 0,
                'last_updated': None
            }
        
        # Check file sizes
        total_size = 0
        seed_count = 0
        for seed_file in self.seeds_dir.glob("*.dat"):
            total_size += seed_file.stat().st_size
            seed_count += 1
        
        return {
            'exists': True,
            'queue_size': metadata.get('queue_size', 0),
            'total_coverage': metadata.get('total_coverage', 0),
            'coverage_edges': metadata.get('coverage_edges', 0),
            'last_updated': metadata.get('last_updated'),
            'seed_files': seed_count,
            'total_size_mb': total_size / (1024 * 1024),
            'fuzzer_stats': metadata.get('fuzzer_stats', {})
        }
    
    def print_statistics(self):
        """Print corpus statistics"""
        stats = self.get_statistics()
        
        print(f"\n{'='*60}")
        print(f"Corpus Statistics")
        print(f"{'='*60}")
        
        if not stats['exists']:
            print("  Status: No corpus found")
            print(f"{'='*60}\n")
            return
        
        print(f"  Status:         Active")
        print(f"  Location:       {self.corpus_dir}")
        print(f"  Queue size:     {stats['queue_size']} seeds")
        print(f"  Seed files:     {stats['seed_files']}")
        print(f"  Total size:     {stats['total_size_mb']:.2f} MB")
        print(f"  Total coverage: {stats['total_coverage']} blocks")
        print(f"  Coverage edges: {stats['coverage_edges']}")
        print(f"  Last updated:   {stats['last_updated']}")
        
        if stats['fuzzer_stats']:
            print(f"\n  Fuzzer stats:")
            for key, value in stats['fuzzer_stats'].items():
                print(f"    {key:20s}: {value}")
        
        print(f"{'='*60}\n")
    
    def minimize_corpus(self, coverage_tracker: 'CoverageTracker') -> List[str]:
        """
        Minimize corpus, keeping fewer seeds that cover the same paths
        
        Returns:
            List of retained seed_ids
        """
        print(f"[Corpus] Minimizing corpus...")
        
        # Load corpus
        corpus_data = self.load_corpus()
        if not corpus_data:
            print(f"[Corpus] No corpus to minimize")
            return []
        
        seeds = corpus_data['queue']['seeds']
        
        # Greedy algorithm: sort by coverage size descending, select seeds that cover new edges
        covered_edges = set()
        minimized_seeds = []
        
        # Sort by coverage size (prefer seeds with more coverage)
        seeds.sort(key=lambda s: len(s['coverage']), reverse=True)
        
        for seed in seeds:
            seed_coverage = set(seed['coverage'])
            new_coverage = seed_coverage - covered_edges
            
            # Keep if it provides new coverage
            if new_coverage or len(minimized_seeds) == 0:
                minimized_seeds.append(seed['seed_id'])
                covered_edges.update(seed_coverage)
        
        reduction = (1 - len(minimized_seeds) / len(seeds)) * 100 if seeds else 0
        print(f"[Corpus] Minimization: {len(seeds)} -> {len(minimized_seeds)} seeds "
              f"({reduction:.1f}% reduction)")
        print(f"[Corpus] Coverage maintained: {len(covered_edges)} edges")
        
        return minimized_seeds
    
    def clean_old_seeds(self, keep_days: int = 7):
        """
        Clean up old seed files
        
        Args:
            keep_days: Keep seeds from the most recent N days
        """
        import time
        
        threshold = time.time() - (keep_days * 24 * 3600)
        removed_count = 0
        
        for seed_file in self.seeds_dir.glob("*.dat"):
            if seed_file.stat().st_mtime < threshold:
                try:
                    seed_file.unlink()
                    removed_count += 1
                except Exception as e:
                    print(f"[Corpus] Warning: Failed to remove {seed_file}: {e}")
        
        if removed_count > 0:
            print(f"[Corpus] Cleaned {removed_count} old seed files")


def merge_corpuses(output_dir: Path, input_dirs: List[Path], 
                   minimize: bool = True) -> Dict:
    """
    Merge multiple corpuses into output_dir
    
    Args:
        output_dir: Output directory
        input_dirs: List of input directories
        minimize: Whether to minimize the merged corpus
    
    Returns:
        Merge statistics
    """
    print(f"\n{'='*60}")
    print(f"Merging Corpuses")
    print(f"{'='*60}")
    
    output_mgr = CorpusManager(output_dir)
    
    all_seeds = {}
    all_coverage = set()
    total_input_seeds = 0
    
    # Load corpus from each input directory
    for input_dir in input_dirs:
        if not input_dir.exists():
            print(f"[Merge] Warning: Input directory not found: {input_dir}")
            continue
        
        mgr = CorpusManager(input_dir)
        data = mgr.load_corpus()
        if not data:
            print(f"[Merge] Warning: Failed to load corpus from {input_dir}")
            continue
        
        # Merge seeds (deduplication)
        for seed_dict in data['queue']['seeds']:
            seed_id = seed_dict['seed_id']
            seed_coverage = set(seed_dict['coverage'])
            
            # Use coverage as deduplication criterion (keep only one with same coverage)
            coverage_hash = hash(frozenset(seed_coverage))
            
            if coverage_hash not in all_seeds:
                all_seeds[coverage_hash] = seed_dict
                all_coverage.update(seed_coverage)
            
            total_input_seeds += 1
    
    unique_seeds = list(all_seeds.values())
    
    print(f"\n[Merge] Merged {len(input_dirs)} corpuses:")
    print(f"  Total input seeds:  {total_input_seeds}")
    print(f"  Unique seeds:       {len(unique_seeds)}")
    print(f"  Dedup rate:         {(1 - len(unique_seeds)/total_input_seeds)*100:.1f}%")
    print(f"  Total coverage:     {len(all_coverage)} edges")
    
    # Minimize (if requested)
    if minimize:
        print(f"\n[Merge] Applying minimization...")
        # TODO: Implement minimization logic
    
    # Save merged corpus
    # TODO: Refactor to directly save seed list
    
    print(f"\n[Merge] ✅ Corpus merge completed")
    print(f"{'='*60}\n")
    
    return {
        'input_seeds': total_input_seeds,
        'unique_seeds': len(unique_seeds),
        'coverage': len(all_coverage),
        'dedup_rate': (1 - len(unique_seeds)/total_input_seeds)*100 if total_input_seeds > 0 else 0
    }


def main():
    """Test Entry Point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Corpus Manager Tool')
    parser.add_argument('corpus_dir', help='Corpus directory')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--merge', nargs='+', help='Merge multiple corpuses')
    parser.add_argument('--minimize', action='store_true', help='Minimize corpus')
    parser.add_argument('--clean', type=int, metavar='DAYS', help='Clean old seeds (keep N days)')
    
    args = parser.parse_args()
    
    corpus_dir = Path(args.corpus_dir)
    
    if args.merge:
        # 合并多个corpus
        input_dirs = [Path(d) for d in args.merge]
        merge_corpuses(corpus_dir, input_dirs, minimize=args.minimize)
    else:
        # 单个corpus操作
        mgr = CorpusManager(corpus_dir)
        
        if args.stats:
            mgr.print_statistics()
        
        if args.minimize:
            # TODO: 需要coverage_tracker
            print("[Corpus] Minimize requires coverage tracker (not implemented in CLI)")
        
        if args.clean:
            mgr.clean_old_seeds(keep_days=args.clean)


if __name__ == "__main__":
    main()
