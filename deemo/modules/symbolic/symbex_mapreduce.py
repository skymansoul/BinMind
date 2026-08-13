"""MapReduce-style distributed symbolic execution.

Partitions a binary by function, executes each function's symbolic analysis
as an independent sub-problem (map), then deduplicates and merges the
resulting path sets (reduce). Falls back to r2 disassembly when angr is
unavailable.
"""

import logging
import os
import json
import time
import pickle
import hashlib
import threading
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    from concurrent.futures import ProcessPoolExecutor, as_completed
    MP_AVAILABLE = True
except ImportError:
    MP_AVAILABLE = False


@dataclass
class SubProblem:
    """A single function's symbolic analysis task dispatched to a worker."""
    sub_id: str
    func_name: str
    binary_path: str
    start_state: Any = None
    inputs: Dict = field(default_factory=dict)
    constraints: List = field(default_factory=list)
    target: Any = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class SubResult:
    """Result from one worker after processing a SubProblem."""
    sub_id: str
    success: bool
    paths: List = field(default_factory=list)
    elapsed: float = 0.0
    error: Optional[str] = None
    state_size: int = 0


@dataclass
class MapReduceResult:
    """Aggregate output of a full MapReduce run."""
    sub_problems: List
    sub_results: List
    merged_paths: List
    statistics: Dict = field(default_factory=dict)


class FunctionBoundaryDetector:
    """Uses r2 to enumerate function boundaries (name, offset, size) from a binary."""

    def detect(self, binary_path: str) -> List[Dict[str, Any]]:
        """Run r2 'aflj' and parse the JSON function list."""
        import subprocess
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aflj;q', binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            data = json.loads(r.stdout)
            return [{
                'name': f.get('name'),
                'offset': f.get('offset'),
                'size': f.get('size', 0),
                'num_instr': f.get('ninstr', 0),
                'num_edges': f.get('numargs', 0)
            } for f in data]
        except Exception as e:
            logger.warning(f"Function boundary detection failed: {e}")
            return []


def _subproblem_worker(sub: SubProblem) -> SubResult:
    """Per-subproblem worker. Prefers angr; degrades to r2 disassembly on failure."""
    start = time.time()
    try:
        try:
            import angr
        except ImportError:
            return _fallback_r2_worker(sub, start)

        proj = angr.Project(sub.binary_path, auto_load_libs=False)
        func_addr = None
        if sub.metadata:
            offset = sub.metadata.get('offset')
            if offset:
                func_addr = offset
        if func_addr is None:
            try:
                func_addr = proj.loader.find_symbol(sub.func_name)
                if func_addr:
                    func_addr = func_addr.rebased_addr
            except Exception:
                logger.debug("suppressed", exc_info=True)
        if func_addr is None:
            try:
                import subprocess as _sp
                r = _sp.run(
                    ['r2', '-q', '-c', f'afl~{sub.func_name};q', sub.binary_path],
                    capture_output=True, text=True, timeout=30,
                    encoding='utf-8', errors='replace'
                )
                for line in r.stdout.strip().split('\n'):
                    parts = line.split()
                    if parts:
                        try:
                            func_addr = int(parts[0], 16)
                            break
                        except ValueError:
                            continue
            except Exception:
                logger.debug("suppressed", exc_info=True)

        if func_addr is None:
            return SubResult(
                sub_id=sub.sub_id, success=False,
                elapsed=time.time() - start,
                error=f"Cannot locate function: {sub.func_name}"
            )

        state = proj.factory.blank_state(addr=func_addr)
        simgr = proj.factory.simulation_manager(state)

        paths: List[Dict[str, Any]] = []
        simgr.run(n=200)
        for i, s in enumerate(simgr.deadended + simgr.active[:5]):
            constraints = [str(c) for c in s.solver.constraints]
            output = {}
            for reg in ['rax', 'eax', 'rbx', 'rcx', 'rdx']:
                try:
                    val = s.solver.eval(s.registers.load(reg))
                    output[reg] = val
                except Exception:
                    logger.debug("suppressed", exc_info=True)
            paths.append({
                'path_id': f"{sub.sub_id}_p{i}",
                'constraints': sub.constraints + constraints,
                'output_values': output
            })

        return SubResult(
            sub_id=sub.sub_id,
            success=len(paths) > 0,
            paths=paths,
            elapsed=time.time() - start,
            state_size=len(simgr.active) + len(simgr.deadended)
        )
    except Exception as e:
        return SubResult(
            sub_id=sub.sub_id, success=False,
            elapsed=time.time() - start, error=str(e)
        )


def _fallback_r2_worker(sub: SubProblem, start: float) -> SubResult:
    """Fallback: disassemble the function with r2 and return instruction trace."""
    try:
        import subprocess as _sp
        r = _sp.run(
            ['r2', '-q', '-c', f'pdf @ {sub.func_name};q', sub.binary_path],
            capture_output=True, text=True, timeout=60,
            encoding='utf-8', errors='replace'
        )
        paths: List[Dict[str, Any]] = []
        lines = r.stdout.strip().split('\n')
        instructions = []
        for line in lines:
            m = __import__('re').match(r'^\s*0x([0-9a-f]+)\s+', line)
            if m:
                instructions.append({'addr': int(m.group(1), 16), 'raw': line.strip()[:100]})
        if instructions:
            paths.append({
                'path_id': f"{sub.sub_id}_r2_0",
                'constraints': sub.constraints,
                'output_values': {},
                'instruction_count': len(instructions),
                'instructions': instructions[:20]
            })
        return SubResult(
            sub_id=sub.sub_id,
            success=len(paths) > 0,
            paths=paths,
            elapsed=time.time() - start
        )
    except Exception as e:
        return SubResult(
            sub_id=sub.sub_id, success=False,
            elapsed=time.time() - start, error=str(e)
        )


class PathMerger:
    """Reduce phase: deduplicate paths by (path_id, constraint_tuple) key."""

    @staticmethod
    def merge(results: List[SubResult]) -> List[Dict[str, Any]]:
        """Collect all paths from sub-results, drop exact duplicates."""
        all_paths: List[Dict[str, Any]] = []
        for r in results:
            for p in r.paths:
                p['source_sub'] = r.sub_id
                all_paths.append(p)
        seen = set()
        unique: List[Dict[str, Any]] = []
        for p in all_paths:
            key = (p.get('path_id'),
                   tuple(sorted(p.get('constraints', []))))
            if key in seen:
                continue
            seen.add(key)
            unique.append(p)
        return unique


class SymbExMapReduce:
    """Orchestrator: partition → map (parallel) → reduce (merge)."""

    def __init__(self, num_workers: int = 4):
        self.num_workers = num_workers
        self.boundary = FunctionBoundaryDetector()

    def partition(self, binary_path: str,
                  target_funcs: Optional[List[str]] = None,
                  max_problems: int = 50) -> List[SubProblem]:
        """Split binary into per-function SubProblems. Optionally filter by name."""
        funcs = self.boundary.detect(binary_path)
        if target_funcs:
            funcs = [f for f in funcs if f['name'] in target_funcs]
        funcs = funcs[:max_problems]
        subs: List[SubProblem] = []
        for f in funcs:
            sub = SubProblem(
                sub_id=hashlib.sha256(
                    f"{binary_path}:{f['name']}".encode()
                ).hexdigest()[:16],
                func_name=f['name'],
                binary_path=binary_path,
                metadata={
                    'offset': f.get('offset'),
                    'size': f.get('size'),
                    'ninstr': f.get('num_instr')
                }
            )
            subs.append(sub)
        return subs

    def map_phase(self, subs: List[SubProblem],
                  use_processes: bool = True) -> List[SubResult]:
        """Execute all sub-problems, optionally via ProcessPoolExecutor."""
        results: List[SubResult] = []
        if use_processes and MP_AVAILABLE:
            with ProcessPoolExecutor(max_workers=self.num_workers) as pool:
                futures = {pool.submit(_subproblem_worker, s): s for s in subs}
                for fut in as_completed(futures):
                    try:
                        r = fut.result(timeout=300)
                    except Exception as e:
                        r = SubResult(
                            sub_id=futures[fut].sub_id,
                            success=False, error=str(e)
                        )
                    results.append(r)
        else:
            for s in subs:
                results.append(_subproblem_worker(s))
        return results

    def reduce_phase(self, results: List[SubResult]) -> List[Dict[str, Any]]:
        """Merge and deduplicate results from all workers."""
        return PathMerger.merge(results)

    def run(self, binary_path: str,
            target_funcs: Optional[List[str]] = None,
            max_problems: int = 50) -> MapReduceResult:
        """Full pipeline: partition → map → reduce."""
        subs = self.partition(binary_path, target_funcs, max_problems)
        results = self.map_phase(subs)
        merged = self.reduce_phase(results)
        stats = {
            'sub_problems': len(subs),
            'successful': sum(1 for r in results if r.success),
            'failed': sum(1 for r in results if not r.success),
            'merged_paths': len(merged),
            'total_paths': sum(len(r.paths) for r in results)
        }
        return MapReduceResult(
            sub_problems=subs, sub_results=results,
            merged_paths=merged, statistics=stats
        )


def run_distributed_symbex(binary_path: str,
                           target_funcs: Optional[List[str]] = None,
                           num_workers: int = 4,
                           max_problems: int = 50) -> Dict[str, Any]:
    """One-shot: instantiate MapReduce engine, partition binary, execute, merge."""
    mr = SymbExMapReduce(num_workers=num_workers)
    result = mr.run(binary_path, target_funcs, max_problems)
    return {
        'success': True,
        'statistics': result.statistics,
        'sub_results': [
            {
                'sub_id': r.sub_id,
                'success': r.success,
                'path_count': len(r.paths),
                'elapsed': r.elapsed,
                'error': r.error
            }
            for r in result.sub_results
        ],
        'merged_path_count': len(result.merged_paths),
        'sample_paths': result.merged_paths[:5]
    }
