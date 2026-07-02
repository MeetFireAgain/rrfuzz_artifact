import os
import json
import logging
import subprocess
import signal
import time
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Any
from .target_profile import TargetProfile
from .lifecycle_manager import TargetLifecycleManager
from .protocol_adapters import HTTPAdapter

class EvolutionCandidate:
    """Represents a potential trace candidate for promotion/evolution"""
    def __init__(self, trace_id: str, new_coverage: int, instructions: List[Any], score: float = 0.0):
        self.trace_id = trace_id
        self.new_coverage = new_coverage
        self.instructions = instructions
        self.score = score
        self.promotion_attempted = False

class EvolutionEngine:
    """
    Core engine for identifying and promoting high-potential mutated traces.
    Implements Phase 1: Evolutionary Discovery & Promotion.
    """
    def __init__(self, output_dir: str, promotion_threshold: int = 5):
        self.output_dir = Path(output_dir)
        self.candidates: List[EvolutionCandidate] = []
        self.promotion_threshold = promotion_threshold
        self.logger = logging.getLogger("EvolutionEngine")
        
        # Paths for candidates
        self.candidates_dir = self.output_dir / "evolution_candidates"
        self.candidates_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_iteration(self, result: Any, instructions: List[Any]) -> Optional[EvolutionCandidate]:
        """
        Evaluates an individual fuzzing iteration for evolution potential.
        """
        if not result or result.new_coverage <= 0:
            return None

        # Calculate evolution score
        # 1. Coverage weight (primary)
        coverage_score = result.new_coverage * 10.0
        
        # 2. Complexity weight (prefer simpler mutations that found more)
        mutation_count = len(instructions) if instructions else 1
        complexity_penalty = mutation_count * 0.5
        
        score = coverage_score - complexity_penalty
        
        if score >= self.promotion_threshold:
            candidate = EvolutionCandidate(
                trace_id=result.trace_id,
                new_coverage=result.new_coverage,
                instructions=instructions,
                score=score
            )
            self.candidates.append(candidate)
            self._save_candidate(candidate)
            return candidate
            
        return None

    def _save_candidate(self, candidate: EvolutionCandidate):
        """Persists candidate info for later promotion processing"""
        candidate_file = self.candidates_dir / f"candidate_{len(self.candidates):03d}.json"
        
        recipe_data = []
        if candidate.instructions:
            for inst in candidate.instructions:
                # Helper to convert bytes for JSON
                raw_data = getattr(inst, 'data', None)
                if isinstance(raw_data, bytes):
                    try:
                        data_repr = raw_data.decode('utf-8', errors='replace')
                    except:
                        data_repr = raw_data.hex()
                else:
                    data_repr = str(raw_data)

                recipe_data.append({
                    'syscall_idx': getattr(inst, 'syscall_idx', -1),
                    'cmd': getattr(inst, 'cmd', -1),
                    'arg_idx': getattr(inst, 'arg_idx', -1),
                    'data_hex': raw_data.hex() if isinstance(raw_data, bytes) else None,
                    'data_str': data_repr
                })

        data = {
            'trace_id': candidate.trace_id,
            'new_coverage': candidate.new_coverage,
            'score': candidate.score,
            'recipe': recipe_data
        }
        
        with open(candidate_file, 'w') as f:
            json.dump(data, f, indent=2)

    def get_best_candidate(self) -> Optional[EvolutionCandidate]:
        """Returns the highest scoring pending candidate"""
        pending = [c for c in self.candidates if not c.promotion_attempted]
        if not pending:
            return None
        return max(pending, key=lambda c: c.score)

    def mark_promoted(self, candidate: EvolutionCandidate):
        candidate.promotion_attempted = True

class ReRecordingExecutor:
    """
    Handles the actual 'Re-recording' process to promote a mutated candidate to a full RR trace.
    """
    def __init__(self, profile: TargetProfile, qemu_path: str, output_dir: str):
        self.profile = profile
        self.lifecycle_mgr = TargetLifecycleManager(profile, qemu_path)
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger("ReRecordingExecutor")
        
        # Stimulus helper script
        self.stimulus_script = Path(__file__).parent.parent.parent / "tests" / "scripts" / "stimuli" / "generic_payload.py"

    def promote_candidate(self, candidate: EvolutionCandidate, output_name: str) -> Optional[str]:
        """
        Attempts to generate a new RR trace based on the successful mutation.
        Returns the path to the new trace file if successful.
        """
        if self.logger: self.logger.info(f"🚀 Promoting candidate {candidate.trace_id} (Score: {candidate.score:.2f})")
        
        # 1. Synthesize stimulus
        stimulus_data = self._synthesize_stimulus(candidate)
        if not stimulus_data:
            if self.logger: self.logger.warning("❌ Could not synthesize stimulus from mutation")
            return None
            
        # 2. Write stimulus to temporary file
        stim_file = self.output_dir / f"stimulus_{output_name}.bin"
        with open(stim_file, "wb") as f:
            f.write(stimulus_data)
            
        # 3. Run QEMU RECORD session
        trace_path = self._run_record_session(stim_file, output_name, stimulus_data)
        
        if trace_path and os.path.exists(trace_path):
            return str(trace_path)
            
        return None

    def _synthesize_stimulus(self, candidate: EvolutionCandidate) -> Optional[bytes]:
        """
        Extracts the input payload from the mutation recipe.
        Currently looks for the largest buffer mutation at high syscall indices.
        """
        best_data = None
        max_idx = -1
        
        if not candidate.instructions:
            return None
            
        for inst in candidate.instructions:
            # We prioritize mutations on 'read' or 'recv' (captured as kind=1/2 aux or arg data)
            data = getattr(inst, 'data', None)
            syscall_idx = getattr(inst, 'syscall_idx', -1)
            cmd = getattr(inst, 'cmd', -1)
            
            if cmd in [1, 2, 4] and isinstance(data, bytes):
                if syscall_idx > max_idx or (syscall_idx == max_idx and len(data) > len(best_data if best_data else b'')):
                    max_idx = syscall_idx
                    best_data = data
        
        return best_data

    def _run_record_session(self, stimulus_file: Path, output_name: str, stimulus_data: bytes) -> Optional[Path]:
        """
        Executes a recording session using a generic stimulus script.
        """
        trace_file = self.output_dir / "seeds" / f"{output_name}.bin"
        trace_file.parent.mkdir(parents=True, exist_ok=True)
        temp_trace = Path(f"/tmp/{output_name}_record.bin")
        log_path = self.output_dir / f"record_{output_name}.log"
        
        # 1. Start target in record mode
        proc = self.lifecycle_mgr.start_service(mode='record', trace_file=str(temp_trace), log_file=str(log_path))
        
        try:
            # 2. Wait for initialization
            time.sleep(5) 
            
            # 3. Dynamic Protocol Selection
            # ✅ Handle protocol decoupling (HTTP vs TCP Raw)
            protocol = self.profile.get('protocol', 'http').lower()
            if protocol == 'http':
                from .protocol_adapters import HTTPAdapter
                adapter = HTTPAdapter("127.0.0.1", self.profile.target_port)
            else:
                from .protocol_adapters import TCPRawAdapter
                adapter = TCPRawAdapter("127.0.0.1", self.profile.target_port)
                
            if self.logger: self.logger.info(f"[*] Sending stim via {adapter.__class__.__name__} to port {self.profile.target_port}")
            adapter.send_payload(payload=stimulus_data)
            time.sleep(2)
        except Exception as e:
            if self.logger: self.logger.error(f"❌ Recording failed: {e}")
        finally:
            self.lifecycle_mgr.stop_service()
                    
        if temp_trace.exists():
            shutil.move(str(temp_trace), str(trace_file))
            temp_bbl = temp_trace.with_suffix(temp_trace.suffix + ".bbl")
            if temp_bbl.exists():
                shutil.move(str(temp_bbl), str(trace_file.with_suffix(trace_file.suffix + ".bbl")))
            return trace_file
            
        return None
