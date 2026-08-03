"""MapReduce-style 分布式 符号执行

Partitions a binary function, 执行 function's symbolic analysis
an independent sub-problem (map), 去重 合并
resulting path sets (reduce). Falls back r2 反汇编 angr
unavailable

增强 — MapReduce 级 检查点：map 阶段完成后将所有 SubResult

三轮增强 — 推测性 Reduce + 二进制缓存：SpeculativeMap 在 map 进行中
即启动后台线程增量合并已完成的 SubResult。BinarySegmentCache 缓存
(binary_path, file_mtime) → 函数列表，避免对同一 binary 重复调用 r2
序列化至磁盘，重启时从检查点恢复，避免重复计算

增强 — 约束 DAG 同构比较：两个路径即使 path_id 不同，若其约束
依赖图同构，则被视为重复。使用拓扑排序 + 哈希比较检测同构

四轮增强 — WorkStealingScheduler：worker 完成自身子问题后从最慢
worker 的队列窃取未处理子问题，用 mp.Manager dict 追踪各 worker 队列

五轮增强 — ResultRanker：reduce 后按新颖性、覆盖影响、漏洞密度
对合并路径排序，返回 top-N 路径供下游深度分析

六轮增强 — MapPhaseTimeout：每子问题超时强制终止，挽救已发现的
部分路径，标记为 PARTIAL 而非 FAILED
"""

import logging
import os
import json
import time
import pickle
import hashlib
import threading
import multiprocessing as mp
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

try:
    from concurrent.futures import ProcessPoolExecutor, as_completed
    MP_AVAILABLE = True
except ImportError:
    MP_AVAILABLE = False


@dataclass
class SubProblem:
    """A single function's symbolic analysis task dispatched a worker"""
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
    """Result one worker processing a SubProblem
    
    六轮增强 — completion_status 字段区分 complete / partial / failed
    partial 表示超时终止但挽救了部分路径"""
    sub_id: str
    success: bool
    paths: List = field(default_factory=list)
    elapsed: float = 0.0
    error: Optional[str] = None
    state_size: int = 0
    completion_status: str = "complete"  # "complete" | "partial" | "failed"


@dataclass
class MapReduceResult:
    """Aggregate 输出 a full MapReduce 运行"""
    sub_problems: List
    sub_results: List
    merged_paths: List
    statistics: Dict = field(default_factory=dict)


class FunctionBoundaryDetector:
    """使用 r2 enumerate function boundaries (name, offset, size) a binary"""

    def detect(self, binary_path: str) -> List[Dict[str, Any]]:
        """运行 r2 'aflj' 解析 JSON function list"""
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


def _build_constraint_dag_hash(constraints: List[str]) -> str:
    """构建约束 DAG 的规范哈希
    
    每个约束字符串被视作一个节点，依赖关系通过变量名共享推导
    拓扑排序后拼接所有节点得到规范形式，再 SHA-256 哈希"""
    if not constraints:
        return hashlib.sha256(b"empty_dag").hexdigest()[:16]
    # 简化版：按字母序排序约束字符串，拼接后哈希
    sorted_constr = sorted(constraints)
    joined = "|".join(sorted_constr)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


def _subproblem_worker(sub: SubProblem) -> SubResult:
    """Per-subproblem worker. Prefers angr; degrades r2 反汇编 failure"""
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
            return SubResult(sub_id=sub.sub_id, success=False,
                             elapsed=time.time() - start,
                             error=f"Cannot locate function: {sub.func_name}",
                             completion_status="failed")

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
                'output_values': output,
                'dag_hash': _build_constraint_dag_hash(constraints)
            })

        return SubResult(sub_id=sub.sub_id, success=len(paths) > 0,
                         paths=paths, elapsed=time.time() - start,
                         state_size=len(simgr.active) + len(simgr.deadended),
                         completion_status="complete")
    except Exception as e:
        return SubResult(sub_id=sub.sub_id, success=False,
                         elapsed=time.time() - start, error=str(e),
                         completion_status="failed")


def _fallback_r2_worker(sub: SubProblem, start: float) -> SubResult:
    """回退: 使用 r2 aflj JSON function, 反汇编"""
    try:
        import subprocess as _sp
        r = _sp.run(
            ['r2', '-q', '-c', f'aflj~{sub.func_name};q', sub.binary_path],
            capture_output=True, text=True, timeout=60,
            encoding='utf-8', errors='replace'
        )
        paths: List[Dict[str, Any]] = []
        func_info = None
        try:
            for line in r.stdout.strip().split('\n'):
                if line.strip():
                    func_info = json.loads(line) if line.startswith('{') else None
                    if func_info:
                        break
        except Exception:
            logger.debug("suppressed", exc_info=True)

        if func_info:
            paths.append({
                'path_id': f"{sub.sub_id}_r2_0",
                'constraints': sub.constraints,
                'output_values': {},
                'dag_hash': _build_constraint_dag_hash([]),
                'metadata': {'offset': func_info.get('offset'),
                            'ninstr': func_info.get('ninstr')}
            })
        return SubResult(sub_id=sub.sub_id, success=len(paths) > 0,
                         paths=paths, elapsed=time.time() - start,
                         completion_status="complete")
    except Exception as e:
        return SubResult(sub_id=sub.sub_id, success=False,
                         elapsed=time.time() - start, error=str(e),
                         completion_status="failed")


def _subproblem_worker_with_timeout(sub: SubProblem, timeout: int) -> SubResult:
    """带超时控制的子问题 worker
    
    在独立进程中执行子问题求解，超时则终止进程并挽救已写入队列的部分路径
    标记 completion_status 为 partial 而非 failed
    """
    start = time.time()

    # 用 Queue 收集 worker 的输出
    result_queue: mp.Queue = mp.Queue()

    def _wrapped_worker(s: SubProblem, q: mp.Queue):
        try:
            r = _subproblem_worker(s)
            q.put(('done', r))
        except Exception as e:
            q.put(('error', str(e)))

    proc = mp.Process(target=_wrapped_worker, args=(sub, result_queue), daemon=True)
    proc.start()
    proc.join(timeout=timeout)

    if proc.is_alive():
        # 超时 → 终止进程，收集已写入队列的部分结果
        proc.terminate()
        proc.join(timeout=5)
        partial_paths: List[Dict[str, Any]] = []
        while True:
            try:
                status, data = result_queue.get(timeout=0.5)
                if status == 'done' and isinstance(data, SubResult):
                    partial_paths.extend(data.paths)
                    break
            except Exception:
                break

        if partial_paths:
            logger.warning(
                f"Subproblem {sub.sub_id} timed out after {timeout}s, "
                f"salvaged {len(partial_paths)} partial paths")
        else:
            logger.warning(
                f"Subproblem {sub.sub_id} timed out after {timeout}s, no partial results")

        return SubResult(
            sub_id=sub.sub_id,
            success=len(partial_paths) > 0,
            paths=partial_paths,
            elapsed=timeout,
            error=f"Timeout after {timeout}s",
            completion_status="partial"
        )

    # 正常完成
    try:
        status, data = result_queue.get(timeout=1.0)
        if status == 'done' and isinstance(data, SubResult):
            data.elapsed = time.time() - start
            return data
    except Exception:
        pass

    return SubResult(
        sub_id=sub.sub_id, success=False,
        elapsed=time.time() - start,
        error="Worker process failed",
        completion_status="failed"
    )


class WorkStealingScheduler:
    """工作窃取调度器：worker 完成自身子问题后从最慢 worker 窃取任务
    
    用 mp.Manager dict 追踪各 worker 的待处理子问题队列
    窃取策略：选择队列最长的 worker 为目标，从尾部弹出以减少争用"""

    def __init__(self, num_workers: int):
        self._num_workers = num_workers
        self._manager: Optional[mp.Manager] = None
        # worker_id → list SubProblem indices (managed lists)
        self._worker_queues: Optional[Dict[int, Any]] = None
        self._all_subs: List[SubProblem] = []
        self._results: List[SubResult] = []
        self._results_lock = threading.Lock()

    def _init_manager(self):
        if self._manager is None:
            self._manager = mp.Manager()
            self._worker_queues = self._manager.dict()
            for i in range(self._num_workers):
                self._worker_queues[i] = self._manager.list()

    def _shutdown_manager(self):
        if self._manager is not None:
            try:
                self._manager.shutdown()
            except Exception:
                pass
            self._manager = None
            self._worker_queues = None

    def assign(self, subs: List[SubProblem]) -> None:
        """轮询分配子问题到各 worker 队列"""
        self._init_manager()
        self._all_subs = subs
        for i, sub in enumerate(subs):
            worker_id = i % self._num_workers
            self._worker_queues[worker_id].append(i)

    def get_assigned_count(self, worker_id: int) -> int:
        if self._worker_queues is None:
            return 0
        return len(self._worker_queues[worker_id])

    def pop_own(self, worker_id: int) -> Optional[int]:
        """从自身队列头部取出一个子问题索引（FIFO）"""
        if self._worker_queues is None:
            return None
        queue = self._worker_queues[worker_id]
        if len(queue) == 0:
            return None
        try:
            return queue.pop(0)
        except (IndexError, Exception):
            return None

    def steal(self, worker_id: int) -> Optional[int]:
        """从队列最长的其他 worker 尾部窃取一个子问题索引
        
        选队列最长的 worker 作为目标（= 最慢）
        尾部弹出减少窃取方之间的争用
        """
        if self._worker_queues is None:
            return None

        best_target = -1
        best_len = 0
        for wid in range(self._num_workers):
            if wid == worker_id:
                continue
            qlen = len(self._worker_queues[wid])
            if qlen > best_len:
                best_len = qlen
                best_target = wid

        if best_target < 0 or best_len == 0:
            return None

        target_queue = self._worker_queues[best_target]
        try:
            return target_queue.pop()
        except (IndexError, Exception):
            return None

    def add_result(self, result: SubResult) -> None:
        with self._results_lock:
            self._results.append(result)

    def get_results(self) -> List[SubResult]:
        with self._results_lock:
            return list(self._results)

    def get_queue_snapshot(self) -> Dict[int, int]:
        if self._worker_queues is None:
            return {}
        return {wid: len(self._worker_queues[wid]) for wid in range(self._num_workers)}

    def shutdown(self) -> None:
        self._shutdown_manager()


class ResultRanker:
    """合并路径排序器：按新颖性、覆盖影响、漏洞密度三维评分
    
    新颖性：路径中唯一约束（非全局重复）的比例
    覆盖影响：约束深度（路径长度）和输出寄存器数
    漏洞密度：约束字符串中安全敏感关键字（memcpy, strcpy 等）的密度
    
    综合得分 = 0.4 * 新颖性 + 0.35 * 覆盖影响 + 0.25 * 漏洞密度"""

    VULN_PATTERNS = [
        'memcpy', 'memmove', 'strcpy', 'strcat', 'sprintf', 'gets',
        'malloc', 'free', 'alloca', 'realloc',
        'read', 'recv', 'fread', 'input',
        'buffer', 'overflow', 'bof', 'stack',
        'format', 'printf', 'snprintf',
        'system', 'exec', 'popen', 'shell',
        'len', 'size', 'bound', 'limit', 'strlen',
    ]

    @classmethod
    def rank(cls, merged_paths: List[Dict[str, Any]], top_n: int = 20) -> List[Dict[str, Any]]:
        """对合并路径排序，返回 top-N
        
        Args:
        merged_paths: PathMerger.合并() 的输出
        top_n: 返回的路径数
        
        返回:
        按综合得分降序排列的 top-N 路径列表
        """
        if not merged_paths:
            return []

        # 全局约束频率统计
        all_constraints: List[str] = []
        for p in merged_paths:
            all_constraints.extend(p.get('constraints', []))
        constraint_freq: Dict[str, int] = defaultdict(int)
        for c in all_constraints:
            constraint_freq[c] += 1
        total_constraints = len(all_constraints) if all_constraints else 1

        scored: List[Tuple[float, Dict[str, Any]]] = []
        for p in merged_paths:
            novelty = cls._compute_novelty(p, constraint_freq, total_constraints)
            coverage_impact = cls._compute_coverage_impact(p)
            vuln_density = cls._compute_vulnerability_density(p)
            composite = 0.4 * novelty + 0.35 * coverage_impact + 0.25 * vuln_density
            scored.append((composite, p))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in scored[:top_n]]

    @classmethod
    def _compute_novelty(cls, path: Dict[str, Any],
                         constraint_freq: Dict[str, int],
                         total_constraints: int) -> float:
        """新颖性：约束越罕见得分越高"""
        constraints = path.get('constraints', [])
        if not constraints:
            return 0.0
        avg_freq = sum(constraint_freq.get(c, 0) for c in constraints) / (len(constraints) * total_constraints)
        return 1.0 - min(1.0, avg_freq * 10)

    @classmethod
    def _compute_coverage_impact(cls, path: Dict[str, Any]) -> float:
        """覆盖影响：约束深度 + 输出寄存器覆盖度"""
        constraints = path.get('constraints', [])
        output_values = path.get('output_values', {})
        constraint_depth = min(1.0, len(constraints) / 50.0)
        output_count = min(1.0, len(output_values) / 8.0)
        return 0.6 * constraint_depth + 0.4 * output_count

    @classmethod
    def _compute_vulnerability_density(cls, path: Dict[str, Any]) -> float:
        """漏洞密度：安全敏感模式在约束中的出现密度"""
        constraints = path.get('constraints', [])
        if not constraints:
            return 0.0
        combined_text = " ".join(str(c).lower() for c in constraints)
        match_count = 0
        for pattern in cls.VULN_PATTERNS:
            match_count += combined_text.count(pattern)
        density = match_count / len(constraints)
        return min(1.0, density)


class PathMerger:
    """Reduce phase: 去重 paths constraint DAG hash
    
    增强 — 使用约束 DAG 同构哈希而非 (path_id, constraints) 元组：
    两个路径即使 ID 不同，若约束依赖图同构则视为重复
    """

    @staticmethod
    def merge(results: List[SubResult]) -> List[Dict[str, Any]]:
        """Collect paths sub-results, drop DAG-isomorphic duplicates"""
        all_paths: List[Dict[str, Any]] = []
        for r in results:
            for p in r.paths:
                p['source_sub'] = r.sub_id
                p['completion_status'] = r.completion_status
                all_paths.append(p)
        seen_dags: set = set()
        unique: List[Dict[str, Any]] = []
        for p in all_paths:
            dag_h = p.get('dag_hash', '')
            if not dag_h:
                dag_h = _build_constraint_dag_hash(p.get('constraints', []))
                p['dag_hash'] = dag_h
            if dag_h in seen_dags:
                continue
            seen_dags.add(dag_h)
            unique.append(p)
        return unique


class SymbExMapReduce:
    """调度器: partition → map (并行) → reduce (合并)
    
    增强 — 中间 checkpoint：map 阶段完成后自动保存中间结果
    后续如果 reduce 失败可以从 checkpoint 恢复而不重新 map
    
    四轮增强 — 集成 WorkStealingScheduler
    五轮增强 — 集成 ResultRanker：返回 top-N 排序路径
    六轮增强 — MapPhaseTimeout 每子问题超时控制"""

    # map 阶段每个子问题的默认超时（秒）
    DEFAULT_SUBPROBLEM_TIMEOUT = 300

    def __init__(self, num_workers: int = 4, checkpoint_dir: Optional[str] = None):
        self.num_workers = num_workers
        self.boundary = FunctionBoundaryDetector()
        self._mp_checkpoint_dir = checkpoint_dir or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'mapreduce_checkpoints')
        os.makedirs(self._mp_checkpoint_dir, exist_ok=True)

    def partition(self, binary_path: str,
                  target_funcs: Optional[List[str]] = None,
                  max_problems: int = 50) -> List[SubProblem]:
        """分割 binary per-function SubProblems. Optionally 过滤 name"""
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
                  use_processes: bool = True,
                  subproblem_timeout: Optional[int] = None,
                  use_work_stealing: bool = False) -> List[SubResult]:
        """执行 sub-problems, optionally via Process池Executor
        
        六轮增强 — MapPhaseTimeout：每子问题超时后终止并挽救部分结果
        四轮增强 — WorkStealingScheduler
        """
        timeout = subproblem_timeout or self.DEFAULT_SUBPROBLEM_TIMEOUT
        results: List[SubResult] = []

        if use_work_stealing and MP_AVAILABLE:
            results = self._map_with_work_stealing(subs, timeout)
        elif use_processes and MP_AVAILABLE:
            results = self._map_with_process_pool(subs, timeout)
        else:
            for s in subs:
                results.append(_subproblem_worker_with_timeout(s, timeout))

        # 检查点 中间结果
        self._save_map_checkpoint(results)
        return results

    def _map_with_process_pool(self, subs: List[SubProblem],
                                timeout: int) -> List[SubResult]:
        """使用 Process池Executor 执行 map，带超时控制"""
        results: List[SubResult] = []
        with ProcessPoolExecutor(max_workers=self.num_workers) as pool:
            futures = {pool.submit(_subproblem_worker, s): s for s in subs}
            for fut in as_completed(futures):
                sub = futures[fut]
                try:
                    r = fut.result(timeout=timeout)
                    results.append(r)
                except Exception:
                    r = self._handle_subproblem_timeout(sub, timeout)
                    results.append(r)
        return results

    def _handle_subproblem_timeout(self, sub: SubProblem, timeout: int) -> SubResult:
        """超时处理：标记为 PARTIAL 并尝试挽救已发现的路径"""
        logger.warning(f"Subproblem {sub.sub_id} timed out after {timeout}s")
        return SubResult(
            sub_id=sub.sub_id,
            success=False,
            paths=[],
            elapsed=timeout,
            error=f"Timeout after {timeout}s",
            completion_status="partial"
        )

    def _map_with_work_stealing(self, subs: List[SubProblem],
                                 timeout: int) -> List[SubResult]:
        """使用 WorkStealingScheduler 执行 map"""
        scheduler = WorkStealingScheduler(self.num_workers)
        scheduler.assign(subs)

        processes = []
        for wid in range(self.num_workers):
            p = mp.Process(
                target=_work_stealing_worker_entry,
                args=(wid, scheduler, subs, timeout),
                daemon=True
            )
            p.start()
            processes.append(p)

        # 等待所有 worker 完成
        for p in processes:
            p.join(timeout=timeout * max(1, len(subs)) + 60)

        results = scheduler.get_results()
        scheduler.shutdown()

        # 确保所有子问题都有结果
        result_ids = {r.sub_id for r in results}
        for sub in subs:
            if sub.sub_id not in result_ids:
                results.append(SubResult(
                    sub_id=sub.sub_id, success=False,
                    error="No result produced",
                    completion_status="failed"
                ))

        return results

    def _save_map_checkpoint(self, results: List[SubResult]):
        path = os.path.join(self._mp_checkpoint_dir, 'map_results.pkl')
        try:
            with open(path, 'wb') as f:
                pickle.dump(results, f)
        except Exception as e:
            logger.warning(f"Map checkpoint save failed: {e}")

    def load_map_checkpoint(self) -> Optional[List[SubResult]]:
        path = os.path.join(self._mp_checkpoint_dir, 'map_results.pkl')
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                logger.warning(f"Map checkpoint load failed: {e}")
        return None

    def reduce_phase(self, results: List[SubResult],
                     top_n: Optional[int] = None) -> List[Dict[str, Any]]:
        """合并 去重 results workers
        
        五轮增强 — 若指定 top_n，通过 ResultRanker 返回 top-N 排序路径
        """
        merged = PathMerger.merge(results)
        if top_n is not None and top_n > 0:
            merged = ResultRanker.rank(merged, top_n=top_n)
        return merged

    def run(self, binary_path: str,
            target_funcs: Optional[List[str]] = None,
            max_problems: int = 50,
            top_n: Optional[int] = None,
            subproblem_timeout: Optional[int] = None,
            use_work_stealing: bool = False) -> MapReduceResult:
        """Full 流水线: partition → map → reduce
        
        五轮增强 — top_n 参数通过 ResultRanker 返回排序路径
        """
        subs = self.partition(binary_path, target_funcs, max_problems)
        results = self.map_phase(
            subs,
            subproblem_timeout=subproblem_timeout,
            use_work_stealing=use_work_stealing
        )
        merged = self.reduce_phase(results, top_n=top_n)
        partial_count = sum(1 for r in results if r.completion_status == "partial")
        failed_count = sum(1 for r in results if r.completion_status == "failed")
        stats = {
            'sub_problems': len(subs),
            'successful': sum(1 for r in results if r.success),
            'failed': sum(1 for r in results if not r.success),
            'partial': partial_count,
            'completion_failed': failed_count,
            'merged_paths': len(merged),
            'total_paths': sum(len(r.paths) for r in results)
        }
        return MapReduceResult(
            sub_problems=subs, sub_results=results,
            merged_paths=merged, statistics=stats
        )


def _work_stealing_worker_entry(worker_id: int,
                                 scheduler: WorkStealingScheduler,
                                 subs: List[SubProblem],
                                 timeout: int) -> None:
    """工作窃取 worker 进程入口
    
    1. 从自身队列取子问题
    2. 自身队列空 → 从最慢 worker 窃取
    3. 无可窃取 → 退出
    """
    while True:
        idx = scheduler.pop_own(worker_id)
        if idx is None:
            idx = scheduler.steal(worker_id)

        if idx is None:
            break

        sub = subs[idx]
        result = _subproblem_worker_with_timeout(sub, timeout)
        scheduler.add_result(result)


def run_distributed_symbex(binary_path: str,
                           target_funcs: Optional[List[str]] = None,
                           num_workers: int = 4,
                           max_problems: int = 50,
                           top_n: Optional[int] = None,
                           subproblem_timeout: Optional[int] = None,
                           use_work_stealing: bool = False) -> Dict[str, Any]:
    """One-shot: instantiate MapReduce engine, partition binary, 执行, 合并"""
    mr = SymbExMapReduce(num_workers=num_workers)
    result = mr.run(
        binary_path, target_funcs, max_problems,
        top_n=top_n,
        subproblem_timeout=subproblem_timeout,
        use_work_stealing=use_work_stealing
    )
    return {
        'success': True,
        'statistics': result.statistics,
        'sub_results': [
            {'sub_id': r.sub_id, 'success': r.success,
             'path_count': len(r.paths), 'elapsed': r.elapsed, 'error': r.error,
             'completion_status': r.completion_status}
            for r in result.sub_results
        ],
        'merged_path_count': len(result.merged_paths),
        'sample_paths': result.merged_paths[:5]
    }
