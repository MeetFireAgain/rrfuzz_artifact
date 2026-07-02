
import os
import sys
import json
import logging
from typing import Dict, List, Set, Tuple, Any, Optional

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

class StaticAnalyzer:
    """
    Whole-program static analysis using angr to complement dynamic traces.
    """
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.project = None
        self.cfg = None
        self.branches: List[Dict[str, Any]] = []
        self.bb_to_func: Dict[int, str] = {}
        
        if not ANGR_AVAILABLE:
            print("[StaticAnalyzer] WARNING: angr not installed. Static analysis will be disabled.")
            return

        if not os.path.exists(binary_path):
            print(f"[StaticAnalyzer] ERROR: Binary not found: {binary_path}")
            return

    def analyze(self) -> bool:
        """Perform CFG analysis"""
        if not ANGR_AVAILABLE or not os.path.exists(self.binary_path):
            return False

        try:
            import fcntl
            lock_file = "/tmp/static_analyzer.lock"
            print(f"[StaticAnalyzer] 🔍 Analyzing {self.binary_path} (Whole-Program)...")
            
            with open(lock_file, 'w') as lf:
                print(f"[StaticAnalyzer] 🔒 Waiting for global analyzer lock...")
                fcntl.flock(lf, fcntl.LOCK_EX)
                
                # Load project with minimal overhead
                self.project = angr.Project(self.binary_path, auto_load_libs=False)
                
                # Build CFG (Fast mode is usually sufficient for our needs)
                self.cfg = self.project.analyses.CFGFast()
                
                # Extract basic info
                self._extract_branches()
                self._map_bbs_to_functions()
                
                fcntl.flock(lf, fcntl.LOCK_UN)
            
            # 🔥 Performance: Clear large angr objects after data extraction
            self.project = None
            self.cfg = None
            import gc
            gc.collect()
            
            print(f"[StaticAnalyzer] ✅ Analysis complete. Found {len(self.branches)} potential branches.")
            return True
        except Exception as e:
            print(f"[StaticAnalyzer] ❌ Analysis failed: {e}")
            self.project = None
            self.cfg = None
            return False

    def _extract_branches(self):
        """Identify conditional jumps and their targets"""
        self.branches = []
        if not self.cfg:
            return

        for node in self.cfg.graph.nodes:
            if node.block is None:
                continue
                
            # Check for conditional jumps (two exits)
            successors = list(self.cfg.graph.successors(node))
            if len(successors) == 2:
                branch_info = {
                    'src_addr': node.addr,
                    'targets': [s.addr for s in successors],
                    'func_addr': node.function_address
                }
                self.branches.append(branch_info)

    def _map_bbs_to_functions(self):
        """Map basic block addresses to function names"""
        self.bb_to_func = {}
        for func_addr, func in self.cfg.kb.functions.items():
            for block_addr in func.block_addrs:
                self.bb_to_func[block_addr] = func.name

    def get_static_cfg_data(self) -> Dict[str, Any]:
        """Export analysis results for PathFinder"""
        return {
            'binary': self.binary_path,
            'branches': self.branches,
            'bb_to_func': self.bb_to_func,
            'stats': {
                'num_branches': len(self.branches),
                'num_functions': len(self.cfg.kb.functions) if self.cfg else 0
            }
        }

    def save_results(self, output_path: str):
        """Save analysis results to JSON"""
        data = self.get_static_cfg_data()
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[StaticAnalyzer] Results saved to {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 static_analyzer.py <binary>")
        sys.exit(1)
        
    analyzer = StaticAnalyzer(sys.argv[1])
    if analyzer.analyze():
        analyzer.save_results("/tmp/static_cfg.json")
