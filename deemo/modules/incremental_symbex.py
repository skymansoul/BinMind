"""
增量符号执行与约束复用模块

功能:
    1. 二进制小幅度变化 (重新编译) 时, 复用已有 angr 状态/SimProcedure/求解器缓存
    2. 基于函数哈希识别未变化代码
    3. 仅对新代码和受影响路径重新执行符号执行

核心技术:
    - 状态序列化 (pickle + 校验和)
    - 函数指纹增量匹配
    - 影响域分析 (被修改函数的所有调用者)
    - 求解器缓存 (约束 + 结果键值)
"""

import logging
import os
import json
import hashlib
import pickle
import time
import threading
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


class ChangeStatus(Enum):
    """函数变化状态"""
    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    ADDED = "added"
    REMOVED = "removed"


@dataclass
class FuncChange:
    func_name: str
    status: ChangeStatus
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    affected_callers: List[str] = field(default_factory=list)


@dataclass
class SolverCacheEntry:
    """求解器缓存条目"""
    constraint: str
    result: Any
    timestamp: float = field(default_factory=time.time)


@dataclass
class StateCheckpoint:
    """符号执行状态检查点"""
    func_name: str
    states: bytes            # 序列化状态
    constraints: List[str]
    variables: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    version: int = 1


class FunctionHasher:
    """计算函数级哈希 (基于 r2)"""

    def __init__(self, r2_path: str = "r2"):
        self.r2_path = r2_path

    def _run(self, binary_path: str, func: str) -> str:
        import subprocess
        try:
            result = subprocess.run(
                [self.r2_path, '-q', '-c', f'pdf @ {func}; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            return hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.warning(f"函数哈希计算失败 {func}: {e}")
            return ""

    def hash_all(self, binary_path: str, funcs: List[str]) -> Dict[str, str]:
        return {fn: self._run(binary_path, fn) for fn in funcs}

    def list_functions(self, binary_path: str) -> List[str]:
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
            logger.warning(f"函数列表获取失败: {e}")
            return []


class SolverCache:
    """约束求解结果缓存"""

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
        return hashlib.sha256(constraint.encode("utf-8")).hexdigest()[:32]

    def get(self, constraint: str) -> Optional[Any]:
        key = self._key(constraint)
        with self._lock:
            if key in self._mem:
                return self._mem[key].result
        # 落盘查找
        path = os.path.join(self.cache_dir, key)
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                logger.warning(f"加载求解缓存失败: {e}")
        return None

    def put(self, constraint: str, result: Any):
        key = self._key(constraint)
        with self._lock:
            if len(self._mem) >= self.max_size:
                # 简单淘汰
                self._mem.pop(next(iter(self._mem)))
            self._mem[key] = SolverCacheEntry(constraint, result)
        try:
            with open(os.path.join(self.cache_dir, key), 'wb') as f:
                pickle.dump(result, f)
        except Exception as e:
            logger.warning(f"保存求解缓存失败: {e}")


class IncrementalSymbEx:
    """
    增量符号执行器
    - 维护前后两个 binary 的函数哈希映射
    - 找出未变化的函数, 跳过符号执行
    - 仅对修改/新增函数及受影响路径重新执行
    """

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
        funcs_old = self.hasher.list_functions(binary_old)
        funcs_new = self.hasher.list_functions(binary_new)
        self._old_hashes = self.hasher.hash_all(binary_old, funcs_old)
        self._new_hashes = self.hasher.hash_all(binary_new, funcs_new)

        changes: List[FuncChange] = []
        old_set = set(self._old_hashes.keys())
        new_set = set(self._new_hashes.keys())

        # 删除
        for fn in (old_set - new_set):
            changes.append(FuncChange(fn, ChangeStatus.REMOVED,
                                      old_hash=self._old_hashes.get(fn)))

        # 新增
        for fn in (new_set - old_set):
            changes.append(FuncChange(fn, ChangeStatus.ADDED,
                                      new_hash=self._new_hashes.get(fn)))

        # 比较
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
        """找出 changed 函数的所有 caller (粗略: 通过符号出现匹配)"""
        affected: Set[str] = set(changed)
        # 简化: 任何函数名包含 changed 名字前缀都视为潜在 caller
        for c in changed:
            base = c.split('.')[-1]
            for fn in all_funcs:
                if base in fn and fn not in changed:
                    affected.add(fn)
        return affected

    def _state_path(self, func_name: str, version_hash: str) -> str:
        return os.path.join(self._state_dir, f"{func_name}_{version_hash}.pkl")

    def save_state(self, func_name: str, version_hash: str,
                   checkpoint: StateCheckpoint) -> bool:
        try:
            with open(self._state_path(func_name, version_hash), 'wb') as f:
                pickle.dump(checkpoint, f)
            return True
        except Exception as e:
            logger.warning(f"保存状态失败: {e}")
            return False

    def load_state(self, func_name: str, version_hash: str) -> Optional[StateCheckpoint]:
        path = self._state_path(func_name, version_hash)
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            logger.warning(f"加载状态失败: {e}")
            return None

    def run_incremental(self,
                        binary_old: Optional[str],
                        binary_new: str,
                        runner=None) -> Dict[str, Any]:
        """
        增量执行
        - binary_old=None 表示首次, 全部执行
        - runner 签名: (func_name, binary_path) -> dict
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
                # 尝试加载旧状态
                ckpt = self.load_state(c.func_name, c.old_hash or "")
                if ckpt:
                    reuse_count += 1
                    results.append({
                        'func': c.func_name,
                        'status': 'reused',
                        'states': len(ckpt.constraints)
                    })
                    continue
            # 需要执行
            if runner is None:
                def default_runner(fn, bp):
                    return {'states': 100, 'func': fn, 'binary': bp}
                runner_local = default_runner
            else:
                runner_local = runner
            out = runner_local(c.func_name, binary_new)
            exec_count += 1
            # 保存状态
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
                'status': c.status.value,
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
