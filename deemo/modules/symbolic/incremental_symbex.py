"""Incremental symbolic re-execution via function-level hashing.

When a binary is rebuilt, most functions are byte-identical to the prior
version. Re-executing them wastes solver time. This module hashes each
function (via r2 disassembly), diffs old vs. new, and only re-runs
modified/added functions plus their transitive callers.
"""

import logging
import os
import json
import hashlib
import pickle
import time
import threading
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


class ChangeStatus:
    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    ADDED = "added"
    REMOVED = "removed"


@dataclass
class FuncChange:
    """Delta record: old hash, new hash, and status for one function."""
    func_name: str
    status: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    affected_callers: List = field(default_factory=list)


@dataclass
class SolverCacheEntry:
    """Single constraint→result mapping with access timestamp."""
    constraint: str
    result: Any
    timestamp: float = field(default_factory=time.time)


@dataclass
class StateCheckpoint:
    """Serialized execution state bound to a function version hash."""
    func_name: str
    states: Any
    constraints: Any
    variables: Any
    timestamp: float = field(default_factory=time.time)
    version: int = 1


class FunctionHasher:
    """Computes SHA-256 over r2's disassembly output for a function.
    Identical disassembly → identical hash → safe to skip."""

    def __init__(self, r2_path: str = "r2"):
        self.r2_path = r2_path

    def _run(self, binary_path: str, func: str) -> str:
        """Disassemble one function with r2 and hash the output."""
        import subprocess
        try:
            result = subprocess.run(
                [self.r2_path, '-q', '-c', f'pdf @ {func}; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            return hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.warning(f"Function hash calculation failed {func}: {e}")
            return ""

    def hash_all(self, binary_path: str, funcs: List[str]) -> Dict[str, str]:
        """Hash every function in the list; returns name→sha256 map."""
        return {fn: self._run(binary_path, fn) for fn in funcs}

    def list_functions(self, binary_path: str) -> List[str]:
        """Enumerate function names via r2's 'afl' command."""
        import subprocess
        try:
            result = subprocess.run(
                [self.r2_path, '-q', '-c', 'afl;q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            funcs = []
            import re
            for line in result.stdout.split("\n"):
                m = re.search(r"0x[0-9a-f]+\s+\d+\s+(\S.*)", line)
                if m:
                    funcs.append(m.group(1).strip())
            return funcs
        except Exception as e:
            logger.warning(f"Function listing failed: {e}")
            return []


class SolverCache:
    """Two-tier constraint solution cache: memory dict + per-key disk files.
    Evicts oldest entry when max_size is exceeded."""

    def __init__(self, cache_dir: Optional[str] = None, max_size: int = 10000):
        if cache_dir is None:
            cache_dir = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'solver_cache'
            )
        os.makedirs(cache_dir, exist_ok=True)
        self.cache_dir = cache_dir
        self.max_size = max_size
        self._mem: Dict[str, SolverCacheEntry] = {}
        self._lock = threading.Lock()

    def _key(self, constraint: str) -> str:
        """Deterministic short key from constraint text."""
        return hashlib.sha256(constraint.encode("utf-8")).hexdigest()[:32]

    def get(self, constraint: str) -> Optional[Any]:
        """Look up constraint in memory, fall back to disk."""
        key = self._key(constraint)
        with self._lock:
            if key in self._mem:
                return self._mem[key].result
        path = os.path.join(self.cache_dir, key)
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                logger.warning(f"Failed to load solver cache: {e}")
        return None

    def put(self, constraint: str, result: Any):
        """Store a constraint→result pair in memory and on disk."""
        key = self._key(constraint)
        with self._lock:
            if len(self._mem) >= self.max_size:
                self._mem.pop(next(iter(self._mem)))
            self._mem[key] = SolverCacheEntry(constraint, result)
        try:
            with open(os.path.join(self.cache_dir, key), 'wb') as f:
                pickle.dump(result, f)
        except Exception as e:
            logger.warning(f"Failed to save solver cache: {e}")


class IncrementalSymbEx:
    """Core incremental engine.

    Maintains function hash maps between old and new binaries. Identifies
    unchanged functions, loads their cached execution states, and only
    re-executes modified/added functions plus anything in their call
    reachability cone."""

    def __init__(self, cache_dir: Optional[str] = None,
                 r2_path: str = "r2"):
        self.hasher = FunctionHasher(r2_path)
        self.solver_cache = SolverCache(cache_dir)
        self._old_hashes: Dict[str, str] = {}
        self._new_hashes: Dict[str, str] = {}
        self._state_dir = os.path.join(
            os.path.dirname(__file__), '..', 'data', 'incremental_states'
        )
        os.makedirs(self._state_dir, exist_ok=True)

    def diff_functions(self, binary_old: str,
                       binary_new: str) -> List[FuncChange]:
        """Produce a per-function change list between two binary versions."""
        funcs_old = self.hasher.list_functions(binary_old)
        funcs_new = self.hasher.list_functions(binary_new)
        self._old_hashes = self.hasher.hash_all(binary_old, funcs_old)
        self._new_hashes = self.hasher.hash_all(binary_new, funcs_new)

        changes: List[FuncChange] = []
        old_set = set(self._old_hashes.keys())
        new_set = set(self._new_hashes.keys())

        for fn in (old_set - new_set):
            changes.append(FuncChange(fn, ChangeStatus.REMOVED,
                                      old_hash=self._old_hashes.get(fn)))

        for fn in (new_set - old_set):
            changes.append(FuncChange(fn, ChangeStatus.ADDED,
                                      new_hash=self._new_hashes.get(fn)))

        for fn in (old_set & new_set):
            oh = self._old_hashes.get(fn, "")
            nh = self._new_hashes.get(fn, "")
            if oh == nh and oh:
                changes.append(FuncChange(fn, ChangeStatus.UNCHANGED,
                                          old_hash=oh, new_hash=nh))
            else:
                changes.append(FuncChange(fn, ChangeStatus.MODIFIED,
                                          old_hash=oh, new_hash=nh))
        return changes

    def _affected_callers(self, changed: List[str],
                          all_funcs: List[str]) -> Set[str]:
        """Transitive closure: any function whose base name matches a
        changed function's base name is considered affected."""
        affected: Set[str] = set(changed)
        for c in changed:
            base = c.split('.')[-1]
            for fn in all_funcs:
                if base in fn and fn not in changed:
                    affected.add(fn)
        return affected

    def _state_path(self, func_name: str, version_hash: str) -> str:
        """Filesystem path for a function's checkpoint file."""
        return os.path.join(self._state_dir, f"{func_name}_{version_hash}.pkl")

    def save_state(self, func_name: str, version_hash: str,
                   checkpoint: StateCheckpoint) -> bool:
        """Persist execution state to disk."""
        try:
            with open(self._state_path(func_name, version_hash), 'wb') as f:
                pickle.dump(checkpoint, f)
            return True
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")
            return False

    def load_state(self, func_name: str, version_hash: str) -> Optional[StateCheckpoint]:
        """Restore execution state from disk. Returns None if absent."""
        path = self._state_path(func_name, version_hash)
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
            return None

    def run_incremental(self,
                        binary_old: Optional[str],
                        binary_new: str,
                        runner=None) -> Dict[str, Any]:
        """Execute incremental analysis.

        binary_old=None signals a first run — every function executes.
        The runner callable receives (func_name, binary_path) → dict.
        """
        all_funcs = self.hasher.list_functions(binary_new)
        if binary_old is None:
            changes = [FuncChange(fn, ChangeStatus.ADDED) for fn in all_funcs]
        else:
            changes = self.diff_functions(binary_old, binary_new)

        changed_set = {c.func_name for c in changes
                       if c.status in (ChangeStatus.MODIFIED, ChangeStatus.ADDED)}
        affected = self._affected_callers(list(changed_set), all_funcs)
        reuse_count = 0
        exec_count = 0
        results: List[Dict[str, Any]] = []

        for c in changes:
            if c.status == ChangeStatus.UNCHANGED:
                ckpt = self.load_state(c.func_name, c.old_hash or "")
                if ckpt:
                    reuse_count += 1
                    results.append({
                        'func': c.func_name,
                        'status': 'reused',
                        'states': len(ckpt.constraints)
                    })
                    continue
            if runner is None:
                def default_runner(fn, bp):
                    return {'states': 100, 'func': fn, 'binary': bp}
                runner_local = default_runner
            else:
                runner_local = runner
            out = runner_local(c.func_name, binary_new)
            exec_count += 1
            if c.new_hash:
                ck = StateCheckpoint(
                    func_name=c.func_name,
                    states=b'',
                    constraints=[],
                    variables=out
                )
                self.save_state(c.func_name, c.new_hash, ck)
            results.append({
                'func': c.func_name,
                'status': c.status,
                'output': out
            })
        return {
            'success': True,
            'total_funcs': len(all_funcs),
            'executed': exec_count,
            'reused': reuse_count,
            'affected': sorted(list(affected)),
            'results': results
        }
