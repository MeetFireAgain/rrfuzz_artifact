import logging
from typing import Dict, List, Set, Optional, Any
from pathlib import Path

class SecurityWatchdog:
    """
    Security-aware monitoring for bug discovery.
    Identifies dangerous sinks from static analysis and monitors execution hits.
    """
    def __init__(self, static_cfg: Optional[Dict[str, Any]] = None):
        self.logger = logging.getLogger("SecurityWatchdog")
        self.dangerous_funcs = {
            'system', 'execve', 'popen', 'execl', 'execvp',
            'strcpy', 'strcat', 'sprintf', 'gets',
            'memcpy', 'memmove' # Generic sinks, use with caution
        }
        self.sink_bbs: Set[int] = set()
        self.bb_to_func: Dict[int, str] = {}
        
        if static_cfg:
            self._load_cfg(static_cfg)

    def _load_cfg(self, cfg: Dict[str, Any]):
        """Maps basic blocks from static analysis to security-critical functions"""
        # Handle both integer and hex-string keys
        self.bb_to_func = {}
        for k, v in cfg.get('bb_to_func', {}).items():
            try:
                addr = int(str(k), 0) # 0 handles 0x prefix automatically
                self.bb_to_func[addr] = v
            except ValueError:
                continue
        
        for bb, func in self.bb_to_func.items():
            # Check if function name contains any dangerous patterns
            for dangerous in self.dangerous_funcs:
                if dangerous in func.lower():
                    self.sink_bbs.add(bb)
                    
        self.logger.info(f"SecurityWatchdog: Identified {len(self.sink_bbs)} dangerous sink basic blocks.")

    def check_execution(self, hit_bbs: List[int]) -> List[str]:
        """
        Checks if any hit basic blocks belong to dangerous sinks.
        Returns a list of function names hit.
        """
        found_sinks = []
        for bb in hit_bbs:
            if bb in self.sink_bbs:
                func_name = self.bb_to_func.get(bb, "unknown")
                if func_name not in found_sinks:
                    found_sinks.append(func_name)
                    self.logger.warning(f"🔥 SECURITY ALERT: dangerous sink '{func_name}' hit at block {hex(bb)}!")
        
        return found_sinks

    def get_discovery_score_bonus(self, hit_bbs: List[int]) -> float:
        """Calculates an 'interest' bonus based on security hits"""
        sinks = self.check_execution(hit_bbs)
        if sinks:
            # 1.0 bonus per unique dangerous function hit
            return len(sinks) * 1.5
        return 0.0
