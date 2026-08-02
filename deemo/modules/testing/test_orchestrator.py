import logging
import os
import json
import time
import threading
import subprocess
from typing import Dict, List, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeout
import hashlib as _hashlib

logger = logging.getLogger(__name__)


class TaskType(str, Enum):
    DOCKER_REPRO = "docker_repro"
    EXPLOIT_TEST = "exploit_test"
    VULNERABILITY_VERIFICATION = "vulnerability_verification"
    FUZZ_TEST = "fuzz_test"
    REGRESSION_TEST = "regression_test"
    BUILD = "build"
    CLEANUP = "cleanup"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


# ---------------------------------------------------------------------------
# 执行画像：quick 减少超时 50% + 禁用重试；deep 超时翻倍 + 多一次重试
# 适应 CI 快速检查 / 标准分析 / 深度审计三种节奏
# ---------------------------------------------------------------------------
class ExecutionProfile:
    """tiered execution config — quick/standard/deep"""

    __slots__ = ("name", "timeout_mult", "extra_retries", "skip_regression")

    def __init__(self, name: str = "standard"):
        self.name = name
        if name == "quick":
            self.timeout_mult = 0.5
            self.extra_retries = -1  # 禁用重试（仅保留首次执行）
            self.skip_regression = True
        elif name == "deep":
            self.timeout_mult = 2.0
            self.extra_retries = 1
            self.skip_regression = False
        else:  # standard
            self.timeout_mult = 1.0
            self.extra_retries = 0
            self.skip_regression = False

    def effective_timeout(self, base_timeout: int) -> int:
        return max(10, int(base_timeout * self.timeout_mult))

    def effective_max_retries(self, base_retries: int) -> int:
        return max(0, base_retries + self.extra_retries)


# ---------------------------------------------------------------------------
# 结果缓存：对命令字串 SHA-256 做内容寻址，命中后跳过子进程调用
# 仅对幂等命令有效；调用方可标记任务为不可缓存
# ---------------------------------------------------------------------------
class ResultCache:
    """content-addressable result store to skip redundant executions"""

    def __init__(self, max_entries: int = 512):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._max = max_entries
        self._hits = 0
        self._misses = 0

    def _key(self, command: str, cwd: str) -> str:
        payload = f"{command}\x00{cwd}"
        return _hashlib.sha256(payload.encode()).hexdigest()

    def lookup(self, command: str, working_dir: str) -> Optional[Dict[str, Any]]:
        k = self._key(command, working_dir)
        entry = self._store.get(k)
        if entry is not None:
            self._hits += 1
            return dict(entry)
        self._misses += 1
        return None

    def store(self, command: str, working_dir: str, exit_code: int,
              output: str) -> None:
        if len(self._store) >= self._max:
            # FIFO 淘汰
            oldest = next(iter(self._store))
            del self._store[oldest]
        k = self._key(command, working_dir)
        self._store[k] = {"exit_code": exit_code, "output": output}

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0


# ---------------------------------------------------------------------------
# 事件总线：发布-订阅模式的任务状态变更通知
# 外部可订阅特定 task_id 或 task_type 的状态变化，实现松耦合的监控/日志
# ---------------------------------------------------------------------------
class EventBus:
    """轻量 pub/sub，避免引入消息队列依赖"""

    def __init__(self):
        self._subs: Dict[str, List[Callable[[Dict[str, Any]], None]]] = defaultdict(
            list)
        self._lock = threading.Lock()

    def subscribe(self, channel: str,
                  callback: Callable[[Dict[str, Any]], None]) -> None:
        """channel: 'task:<task_id>' 或 'type:<task_type>'"""
        with self._lock:
            self._subs[channel].append(callback)

    def publish(self, channel: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            listeners = list(self._subs.get(channel, []))
            listeners.extend(self._subs.get('*', []))
        for cb in listeners:
            try:
                cb(payload)
            except Exception:
                logger.debug("event callback suppressed", exc_info=True)

    def clear(self) -> None:
        with self._lock:
            self._subs.clear()


# ---------------------------------------------------------------------------
# 防饥饿优先级队列：任务优先级随等待时间线性增长
# effective_priority = base_priority + age_weight * wait_seconds
# 低优先级任务在队列中停留超过阈值后自动晋升，避免永久阻塞
# ---------------------------------------------------------------------------
class AgingPriorityQueue:
    """优先级随等待时间老化，防止低优先级任务饿死"""

    def __init__(self, age_weight: float = 0.1):
        self._heap: List[Tuple[float, int, TestTask]] = []
        self._counter = 0
        self._lock = threading.Lock()
        self._age_weight = age_weight
        self._entry_times: Dict[str, float] = {}

    def push(self, task: TestTask) -> None:
        with self._lock:
            now = time.time()
            self._entry_times[task.task_id] = now
            base = float(getattr(task, 'priority', 0))
            effective = -(base + self._age_weight * 0)  # 初始入队不做老化
            self._counter += 1
            import heapq as _hpq
            _hpq.heappush(self._heap, (effective, self._counter, task))

    def pop(self) -> Optional[TestTask]:
        with self._lock:
            if not self._heap:
                return None
            import heapq as _hpq
            now = time.time()
            # 重建堆：所有条目应用老化公式
            aged: List[Tuple[float, int, TestTask]] = []
            while self._heap:
                _, _, task = _hpq.heappop(self._heap)
                wait = now - self._entry_times.get(task.task_id, now)
                base = float(getattr(task, 'priority', 0))
                effective = -(base + self._age_weight * wait)
                aged.append((effective, self._counter, task))
                self._counter += 1
            for item in aged:
                _hpq.heappush(self._heap, item)
            if self._heap:
                _, _, task = _hpq.heappop(self._heap)
                self._entry_times.pop(task.task_id, None)
                return task
            return None

    def __len__(self) -> int:
        return len(self._heap)


# ---------------------------------------------------------------------------
# 工作流二分定位：当整个 workflow 失败时，对任务集做二分查找找出
# 最小失败子集。每轮执行一半任务，若仍失败则继续二分，直到定位到
# 单个或最小失败任务组。思路来自 SymBisect 的漏洞定位策略。
# ---------------------------------------------------------------------------
class WorkflowBisector:
    """二分定位工作流中的失败任务"""

    def __init__(self, executor: Callable[[List[TestTask]], bool]):
        self._exec = executor  # 执行任务列表，返回 True=全部通过

    def bisect(self, tasks: List[TestTask],
               max_iterations: int = 12) -> Dict[str, Any]:
        """返回 {'culprits': [...], 'iterations': N, 'passed_tasks': [...]}"""
        if not tasks:
            return {"culprits": [], "iterations": 0, "passed_tasks": []}
        # 先确认全集失败
        if self._exec(tasks):
            return {"culprits": [], "iterations": 0,
                    "passed_tasks": [t.task_id for t in tasks]}
        suspects = list(tasks)
        passed: List[str] = []
        for iteration in range(max_iterations):
            if len(suspects) <= 1:
                break
            mid = len(suspects) // 2
            left = suspects[:mid]
            right = suspects[mid:]
            if self._exec(left):
                # 左半通过 → 问题在右半
                passed.extend(t.task_id for t in left)
                suspects = right
            else:
                # 左半失败 → 继续分左半
                suspects = left
        return {
            "culprits": [t.task_id for t in suspects],
            "iterations": iteration + 1,
            "passed_tasks": passed,
        }


# ---------------------------------------------------------------------------
# 任务图版本差异：比较两个工作流定义，标记新增/删除/变动的任务
# 用于 CI 中检测 workflow 变更并仅重跑受影响的子集
# ---------------------------------------------------------------------------
class TaskGraphDiffer:
    """比较两个任务列表的拓扑差异"""

    @staticmethod
    def diff(old: List[TestTask],
             new: List[TestTask]) -> Dict[str, List[str]]:
        old_ids = {t.task_id: t for t in old}
        new_ids = {t.task_id: t for t in new}
        added = list(set(new_ids) - set(old_ids))
        removed = list(set(old_ids) - set(new_ids))
        changed = []
        for tid in set(old_ids) & set(new_ids):
            ot, nt = old_ids[tid], new_ids[tid]
            if (ot.command != nt.command
                    or ot.dependencies != nt.dependencies
                    or ot.timeout != nt.timeout):
                changed.append(tid)
        return {"added": added, "removed": removed, "changed": changed}

    @staticmethod
    def affected_tasks(new: List[TestTask],
                       changed_ids: List[str]) -> List[str]:
        """返回因变更任务而受影响的下游任务 ID 列表"""
        changed_set = set(changed_ids)
        # 构建反向依赖图
        downstream: Dict[str, Set[str]] = defaultdict(set)
        for t in new:
            for dep in t.dependencies:
                downstream[dep].add(t.task_id)
        # BFS 传播影响
        affected = set(changed_set)
        queue = deque(changed_set)
        while queue:
            tid = queue.popleft()
            for succ in downstream.get(tid, set()):
                if succ not in affected:
                    affected.add(succ)
                    queue.append(succ)
        return sorted(affected - changed_set)


# ---------------------------------------------------------------------------
# CI/CD 管道指标收集器：追踪关键运营指标
# - time_to_triage: 从崩溃发现到分类完成的耗时
# - unique_crashes_per_hour: 去重后的崩溃发现速率
# - workflow_pass_rate: 工作流通过率滑动窗口
# 参照 ClusterFuzz 的 metrics 体系设计
# ---------------------------------------------------------------------------
class PipelineMetricsCollector:
    """CI/CD 管道指标收集与报告"""

    def __init__(self, window_hours: float = 24.0):
        self._window = window_hours * 3600
        self._events: List[Tuple[float, str, Dict[str, Any]]] = []
        self._lock = threading.Lock()

    def record(self, event_type: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._events.append((time.time(), event_type, payload))
            # 截断过期事件
            cutoff = time.time() - self._window
            self._events = [e for e in self._events if e[0] >= cutoff]

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            recent = [e for e in self._events if e[0] >= now - 3600]
            crashes = [e for e in self._events
                       if e[1] == 'crash_discovered']
            triages = [e for e in self._events
                       if e[1] == 'crash_triaged']
            workflows = [e for e in self._events
                        if e[1] == 'workflow_complete']

            # 唯一崩溃数（按 dedup key 去重）
            unique_crashes = len({
                e[2].get('dedup_key', '') for e in crashes
                if e[2].get('dedup_key')})
            hours_covered = max(1, (now - self._events[0][0]) / 3600
                                if self._events else 1)

            # 平均分类时间
            triage_times = []
            for tc in triages:
                crash_key = tc[2].get('crash_key')
                for cr in crashes:
                    if cr[2].get('crash_key') == crash_key:
                        triage_times.append(tc[0] - cr[0])
                        break

            return {
                'unique_crashes_last_hour': unique_crashes,
                'crash_rate_per_hour': round(
                    unique_crashes / hours_covered, 2),
                'avg_triage_seconds': round(
                    sum(triage_times) / len(triage_times), 1)
                if triage_times else None,
                'workflow_pass_rate': round(
                    sum(1 for w in workflows
                        if w[2].get('passed', False)) / max(1, len(workflows)), 3),
                'total_events': len(self._events),
            }

    def clear(self) -> None:
        with self._lock:
            self._events = []


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 解包层追踪器：GoaTracer 风格的 wave tracking — 识别自修改代码的
# 逐层解包过程。每个 wave 对应一次内存页从可写→可执行的转换。
# 用于检测多层加壳 (UPX→ASPack→VMProtect) 及动态代码生成。
# ---------------------------------------------------------------------------
class UnpackingWaveTracker:
    """多层解包的 wave 识别与追踪"""

    def __init__(self):
        self._waves: Dict[int, Dict[str, Any]] = {}
        self._current_wave = 0
        self._page_history: Dict[int, List[str]] = defaultdict(list)

    def record_page_transition(self, page_addr: int,
                                old_prot: str, new_prot: str) -> None:
        """记录内存页保护属性变更"""
        if 'w' in old_prot and 'x' in new_prot:
            self._current_wave += 1
            self._waves[self._current_wave] = {
                'trigger_page': hex(page_addr),
                'transition': f'{old_prot} → {new_prot}',
                'timestamp': time.time(),
            }
        self._page_history[page_addr].append(
            f'{old_prot}→{new_prot}')

    @property
    def layer_count(self) -> int:
        return self._current_wave

    def is_packed(self) -> bool:
        """超过 1 层 W→X 转换 → 可能加壳"""
        return self._current_wave >= 1

    def packing_confidence(self) -> float:
        """W→X 转换次数 / 总页数 → 加壳置信度 [0,1]"""
        total_pages = len(self._page_history)
        if total_pages == 0:
            return 0.0
        wx_pages = sum(
            1 for hist in self._page_history.values()
            if any('w' in h.split('→')[0]
                   and 'x' in h.split('→')[1] for h in hist))
        return round(wx_pages / total_pages, 2)


# ---------------------------------------------------------------------------
# Mock OS 环境配置：Binee 风格的轻量 OS 子系统模拟
# 为二进制模拟执行提供虚拟注册表、文件系统和堆管理器
# ---------------------------------------------------------------------------
class MockOSEnvironment:
    """虚拟 OS 环境：注册表 + 文件系统 + 堆句柄"""

    def __init__(self):
        self._registry: Dict[str, Any] = {}
        self._filesystem: Dict[str, bytes] = {}
        self._heap_handles: Dict[int, bytearray] = {}
        self._next_handle = 0x1000

    def reg_write(self, key_path: str, value: Any) -> None:
        self._registry[key_path] = value

    def reg_read(self, key_path: str) -> Optional[Any]:
        return self._registry.get(key_path)

    def fs_create(self, path: str, content: bytes = b'') -> int:
        self._filesystem[path] = content
        return len(self._filesystem)

    def fs_read(self, path: str) -> Optional[bytes]:
        return self._filesystem.get(path)

    def heap_alloc(self, size: int) -> int:
        handle = self._next_handle
        self._next_handle += 1
        self._heap_handles[handle] = bytearray(size)
        return handle

    def heap_write(self, handle: int, offset: int,
                    data: bytes) -> bool:
        buf = self._heap_handles.get(handle)
        if buf is None or offset + len(data) > len(buf):
            return False
        buf[offset:offset + len(data)] = data
        return True

    def heap_read(self, handle: int, offset: int,
                   size: int) -> Optional[bytes]:
        buf = self._heap_handles.get(handle)
        if buf is None or offset + size > len(buf):
            return None
        return bytes(buf[offset:offset + size])


# MCP 风格工具注册表：管理外部分析工具的接入与调度
# 每个工具注册为一个 (name, endpoint, schema) 三元组，由调度器按
# 依赖关系和并发限制分派。灵感来自 Awesome RE-MCP 生态的标准化思想。
# ---------------------------------------------------------------------------
class MCPToolRegistry:
    """MCP 风格的外部工具注册与发现"""

    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def register(self, name: str, endpoint: str,
                 tool_schema: Dict[str, Any],
                 rate_limit: float = 1.0) -> None:
        """注册一个外部工具及其 JSON Schema"""
        with self._lock:
            self._tools[name] = {
                'endpoint': endpoint,
                'schema': tool_schema,
                'rate_limit': rate_limit,
                'last_called': 0.0,
                'call_count': 0,
                'error_count': 0,
            }

    def discover(self, capability: str) -> List[str]:
        """按能力描述发现匹配的工具（名称/描述子串匹配）"""
        matches = []
        cap_lower = capability.lower()
        for name, info in self._tools.items():
            schema_str = json.dumps(info['schema']).lower()
            if cap_lower in name.lower() or cap_lower in schema_str:
                matches.append(name)
        return matches

    def call(self, name: str, params: Dict[str, Any],
             timeout: float = 30.0) -> Optional[Dict[str, Any]]:
        """对注册的工具发起调用（占位实现，实际接入 MCP 传输层）"""
        with self._lock:
            tool = self._tools.get(name)
            if tool is None:
                return {'error': f'Tool {name} not registered'}
            now = time.time()
            if now - tool['last_called'] < tool['rate_limit']:
                return {'error': f'Rate limited, wait {tool["rate_limit"]}s'}
            tool['last_called'] = now
            tool['call_count'] += 1
        # 占位：实际应通过 MCP stdio/SSE 调用外部工具
        return {
            'tool': name, 'params': params,
            'status': 'mcp_not_configured',
            'note': 'MCP transport未初始化，返回空响应',
        }

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                name: {
                    'calls': info['call_count'],
                    'errors': info['error_count'],
                }
                for name, info in self._tools.items()
            }


# Thompson 采样流选择器：Hoedur 多流 Fuzzing 的流选择策略
# 对每条输入流维护 Beta(α, β) 先验，每次选择期望奖励最高的流
# 奖励 = 该流发现的新覆盖边数。贝叶斯自适应平衡探索与利用。
# ---------------------------------------------------------------------------
class ThompsonSamplingStreamSelector:
    """Thompson 采样选择最优输入流"""

    def __init__(self):
        self._streams: Dict[str, Dict[str, float]] = {}  # name → {alpha, beta}

    def register_stream(self, name: str) -> None:
        if name not in self._streams:
            self._streams[name] = {'alpha': 1.0, 'beta': 1.0}

    def select(self) -> str:
        """从 Beta 后验采样，返回期望奖励最高的流名"""
        if not self._streams:
            return ""
        best = None
        best_sample = -1.0
        for name, params in self._streams.items():
            sample = random.betavariate(
                max(0.1, params['alpha']), max(0.1, params['beta']))
            if sample > best_sample:
                best_sample = sample
                best = name
        return best or next(iter(self._streams))

    def reward(self, name: str, new_edges: int) -> None:
        if name in self._streams:
            self._streams[name]['alpha'] += new_edges
            self._streams[name]['beta'] += max(0, 1 - new_edges)

    def stats(self) -> Dict[str, Dict[str, float]]:
        return {
            name: {
                'alpha': round(p['alpha'], 2),
                'beta': round(p['beta'], 2),
                'expected': round(p['alpha'] / (p['alpha'] + p['beta']), 3),
            }
            for name, p in self._streams.items()
        }


# ---------------------------------------------------------------------------
# 多流会话管理器：协调同一目标上多个并发的 Fuzzer 输入流
# 每个流可对应不同的输入类型（网络包、文件、环境变量、共享内存等）
# ---------------------------------------------------------------------------
class MultiStreamSessionManager:
    """管理多输入流的并发 fuzzing 会话"""

    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._selector = ThompsonSamplingStreamSelector()

    def add_stream(self, stream_id: str, config: Dict[str, Any]) -> None:
        self._sessions[stream_id] = {
            'config': config,
            'exec_count': 0,
            'edge_count': 0,
            'last_active': time.time(),
        }
        self._selector.register_stream(stream_id)

    def pick_stream(self) -> str:
        return self._selector.select()

    def update_stream(self, stream_id: str,
                       exec_delta: int, new_edges: int) -> None:
        if stream_id in self._sessions:
            s = self._sessions[stream_id]
            s['exec_count'] += exec_delta
            s['edge_count'] += new_edges
            s['last_active'] = time.time()
            self._selector.reward(stream_id, new_edges)

    def idle_streams(self, threshold_s: float = 300.0) -> List[str]:
        now = time.time()
        return [sid for sid, s in self._sessions.items()
                if now - s['last_active'] > threshold_s]

    @property
    def selector(self) -> ThompsonSamplingStreamSelector:
        return self._selector


# SBOM 可达性验证器：基于函数调用图判断 CVE 关联组件是否可被攻击面触及
# 参照 arXiv 2511.20313 的发现：SBOM 扫描 97.5% FP 率，63.3% 可经
# 可达性分析消除。此处实现轻量调用图 BFS 可及性判定。
# ---------------------------------------------------------------------------
class SBOMReachabilityVerifier:
    """基于调用图 BFS 的漏洞代码可及性判定"""

    def __init__(self):
        self._call_graph: Dict[str, List[str]] = defaultdict(list)
        self._entry_points: Set[str] = set()

    def load_call_graph(self,
                        edges: List[Tuple[str, str]]) -> None:
        """edges: [(caller, callee), ...]"""
        for caller, callee in edges:
            self._call_graph[caller].append(callee)

    def set_entry_points(self, functions: List[str]) -> None:
        """设置攻击可达入口（导出函数、网络处理函数等）"""
        self._entry_points = set(functions)

    def is_reachable(self, target_func: str,
                     max_depth: int = 8) -> Dict[str, Any]:
        """BFS 判定 target_func 是否从任一入口可达"""
        if not self._entry_points:
            return {'reachable': False, 'reason': 'no_entry_points'}
        # 构建反向图：callee → [callers]
        rev_graph: Dict[str, List[str]] = defaultdict(list)
        for caller, callees in self._call_graph.items():
            for callee in callees:
                rev_graph[callee].append(caller)
        visited: Set[str] = set()
        queue = deque([target_func])
        depth = 0
        while queue and depth <= max_depth:
            for _ in range(len(queue)):
                func = queue.popleft()
                if func in self._entry_points:
                    return {'reachable': True, 'depth': depth,
                            'entry_point': func}
                if func in visited:
                    continue
                visited.add(func)
                for caller in rev_graph.get(func, []):
                    if caller not in visited:
                        queue.append(caller)
            depth += 1
        return {'reachable': False, 'depth_searched': depth,
                'visited_functions': len(visited)}

    def filter_reachable_cves(self,
                              cve_to_funcs: Dict[str, List[str]]
                              ) -> Dict[str, Any]:
        """批量过滤：返回可达/不可达 CVE 分组"""
        reachable = {}
        unreachable = {}
        for cve_id, funcs in cve_to_funcs.items():
            for func in funcs:
                result = self.is_reachable(func)
                if result.get('reachable'):
                    reachable[cve_id] = result
                    break
            else:
                unreachable[cve_id] = {'reason': 'no_function_reachable'}
        return {
            'reachable_cves': len(reachable),
            'unreachable_cves': len(unreachable),
            'reachable_details': reachable,
            'unreachable_details': unreachable,
            'false_positive_reduction': round(
                len(unreachable) / max(1, len(cve_to_funcs)), 3),
        }


# ---------------------------------------------------------------------------
@dataclass
class _TaskNode:
    task: 'TestTask'
    indegree: int = 0
    successors: List[str] = field(default_factory=list)


class TestTask:
    __slots__ = ('task_id', 'task_type', 'name', 'command', 'working_dir',
                 'dependencies', 'timeout', 'status', 'output', 'exit_code',
                 'retry_count', 'max_retries', 'checkpoint_data', 'env')

    def __init__(self, task_id: str, task_type: TaskType, name: str,
                 command: str, working_dir: str = '/workspace',
                 dependencies: Optional[List[str]] = None,
                 timeout: int = 300, status: TaskStatus = TaskStatus.PENDING,
                 output: str = '', exit_code: Optional[int] = None,
                 max_retries: int = 2, env: Optional[Dict[str, str]] = None):
        self.task_id = task_id
        self.task_type = task_type
        self.name = name
        self.command = command
        self.working_dir = working_dir
        self.dependencies = dependencies or []
        self.timeout = timeout
        self.status = status
        self.output = output
        self.exit_code = exit_code
        self.retry_count = 0
        self.max_retries = max_retries
        self.checkpoint_data: Dict[str, Any] = {}
        self.env = env or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'task_type': self.task_type.value,
            'name': self.name,
            'command': self.command,
            'working_dir': self.working_dir,
            'dependencies': self.dependencies,
            'timeout': self.timeout,
            'status': self.status.value,
            'output': self.output,
            'exit_code': self.exit_code,
            'retry_count': self.retry_count,
            'checkpoint': self.checkpoint_data,
        }


class WorkflowResult:
    __slots__ = ('workflow_id', 'tasks', 'success_count', 'failed_count',
                 'skipped_count', 'total_time', 'summary')

    def __init__(self, workflow_id: str, tasks: List[TestTask],
                 success_count: int, failed_count: int, total_time: float,
                 summary: Dict[str, Any], skipped_count: int = 0):
        self.workflow_id = workflow_id
        self.tasks = tasks
        self.success_count = success_count
        self.failed_count = failed_count
        self.skipped_count = skipped_count
        self.total_time = total_time
        self.summary = summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            'workflow_id': self.workflow_id,
            'tasks': [t.to_dict() for t in self.tasks],
            'success_count': self.success_count,
            'failed_count': self.failed_count,
            'skipped_count': self.skipped_count,
            'total_time': self.total_time,
            'summary': self.summary
        }


# ---------------------------------------------------------------------------
# 资源池：限制并发 Docker 容器 / 进程数，防止宿主机过载
# ---------------------------------------------------------------------------
class ResourcePool:
    """信号量风格资源池，支持带超时的获取与释放"""

    def __init__(self, capacity: int = 4):
        self._sem = threading.BoundedSemaphore(capacity)
        self._capacity = capacity
        self._allocated: Dict[str, int] = defaultdict(int)

    def acquire(self, owner_id: str, timeout: float = 30.0) -> bool:
        acquired = self._sem.acquire(timeout=timeout)
        if acquired:
            self._allocated[owner_id] += 1
        return acquired

    def release(self, owner_id: str) -> None:
        self._sem.release()
        self._allocated[owner_id] = max(0, self._allocated[owner_id] - 1)

    @property
    def available(self) -> int:
        return self._capacity - sum(1 for _ in range(self._capacity)
                                    if not self._sem.acquire(blocking=False))
    @property
    def capacity(self) -> int:
        return self._capacity


class TestOrchestrator:
    """面向漏洞复现的工作流编排器：DAG 拓扑 → 并行执行 → 重试 → 检查点"""

    def __init__(self, max_parallel: int = 4,
                 profile: str = "standard",
                 enable_cache: bool = True):
        self.docker_templates = {
            'ubuntu_2204': 'ubuntu:22.04',
            'ubuntu_2004': 'ubuntu:20.04',
            'debian_12': 'debian:12',
            'alpine': 'alpine:latest',
            'kali': 'kalilinux/kali-rolling:latest',
        }
        self._pool = ResourcePool(capacity=max_parallel)
        self._checkpoint_dir: Optional[str] = None
        self._profile = ExecutionProfile(profile)
        self._cache = ResultCache() if enable_cache else None
        # 自适应超时：记录每个 task_type 的历史执行时间 EMA
        self._timing_ema: Dict[str, float] = {}
        self._ema_alpha = 0.3  # 指数平滑因子
        self._event_bus = EventBus()
        self._priority_queue: Optional[AgingPriorityQueue] = None

    # ---- 工作流构建 ----
    def create_workflow(self, vulnerability_info: Dict[str, Any]) -> List[TestTask]:
        tasks = []

        tasks.append(TestTask(
            task_id='docker_setup',
            task_type=TaskType.DOCKER_REPRO,
            name='Docker environment setup',
            command=self._generate_docker_command(vulnerability_info),
            working_dir='/workspace',
            dependencies=[],
            timeout=300,
            status=TaskStatus.PENDING,
            output='',
            exit_code=None,
            env=vulnerability_info.get('env', {})
        ))

        tasks.append(TestTask(
            task_id='vuln_verify',
            task_type=TaskType.VULNERABILITY_VERIFICATION,
            name='Vulnerability verification',
            command=self._generate_verify_command(vulnerability_info),
            working_dir='/workspace',
            dependencies=['docker_setup'],
            timeout=600,
            status=TaskStatus.PENDING,
            output='',
            exit_code=None
        ))

        tasks.append(TestTask(
            task_id='exploit_test',
            task_type=TaskType.EXPLOIT_TEST,
            name='Exploit testing',
            command=self._generate_exploit_command(vulnerability_info),
            working_dir='/workspace',
            dependencies=['vuln_verify'],
            timeout=600,
            status=TaskStatus.PENDING,
            output='',
            exit_code=None,
            max_retries=1
        ))

        tasks.append(TestTask(
            task_id='regression_test',
            task_type=TaskType.REGRESSION_TEST,
            name='Regression testing',
            command=self._generate_regression_command(vulnerability_info),
            working_dir='/workspace',
            dependencies=['exploit_test'],
            timeout=300,
            status=TaskStatus.PENDING,
            output='',
            exit_code=None
        ))

        return tasks

    def _generate_docker_command(self, vulnerability_info: Dict[str, Any]) -> str:
        distro = vulnerability_info.get('distro', 'ubuntu_2204')
        image = self.docker_templates.get(distro, 'ubuntu:22.04')
        cmd = f"docker run -d --name vuln_test -v $(pwd):/workspace {image} sleep infinity"
        return cmd

    def _generate_verify_command(self, vulnerability_info: Dict[str, Any]) -> str:
        vuln_type = vulnerability_info.get('vulnerability_type', 'unknown')
        commands = []
        if vuln_type == 'buffer_overflow':
            commands.append("python3 verify_buffer_overflow.py")
        elif vuln_type == 'use_after_free':
            commands.append("python3 verify_uaf.py")
        elif vuln_type == 'format_string':
            commands.append("python3 verify_format_string.py")
        else:
            commands.append("python3 verify_vulnerability.py")
        return ' && '.join(commands)

    def _generate_exploit_command(self, vulnerability_info: Dict[str, Any]) -> str:
        exploit_path = vulnerability_info.get('exploit_path', 'exploit.py')
        return f"python3 {exploit_path}"

    def _generate_regression_command(self, vulnerability_info: Dict[str, Any]) -> str:
        return "python3 -m pytest regression_tests/ -v"

    # ---- DAG 构建与拓扑排序 ----
    def _build_dag(self, tasks: List[TestTask]) -> Dict[str, _TaskNode]:
        nodes: Dict[str, _TaskNode] = {
            t.task_id: _TaskNode(task=t) for t in tasks}
        for t in tasks:
            for dep_id in t.dependencies:
                if dep_id in nodes:
                    nodes[dep_id].successors.append(t.task_id)
                    nodes[t.task_id].indegree += 1
        return nodes

    @staticmethod
    def _topo_levels(nodes: Dict[str, _TaskNode]) -> List[List[TestTask]]:
        """Kahn 算法分层：同层无相互依赖，可并行"""
        indeg = {nid: node.indegree for nid, node in nodes.items()}
        queue: deque[str] = deque(
            nid for nid, d in indeg.items() if d == 0)
        levels: List[List[TestTask]] = []
        while queue:
            level: List[TestTask] = []
            for _ in range(len(queue)):
                nid = queue.popleft()
                level.append(nodes[nid].task)
                for succ in nodes[nid].successors:
                    indeg[succ] -= 1
                    if indeg[succ] == 0:
                        queue.append(succ)
            if level:
                levels.append(level)
        # 未到达节点 → 循环依赖或缺失依赖，追加到末层按序执行
        remaining = [nodes[nid].task for nid, d in indeg.items() if d > 0]
        if remaining:
            logger.warning("DAG cycle or missing deps for: %s",
                           [t.task_id for t in remaining])
            levels.append(remaining)
        return levels

    # ---- 事件总线 ----
    @property
    def events(self) -> EventBus:
        return self._event_bus

    # ---- 单任务执行与重试 ----
    def _execute_one(self, task: TestTask) -> None:
        task.status = TaskStatus.RUNNING
        self._event_bus.publish(f"task:{task.task_id}",
                                {"event": "running", "task": task.task_id})
        self._event_bus.publish(f"type:{task.task_type.value}",
                                {"event": "running", "task": task.task_id})

        # 结果缓存检查
        if self._cache is not None:
            cached = self._cache.lookup(task.command, task.working_dir)
            if cached is not None:
                task.output = cached["output"]
                task.exit_code = cached["exit_code"]
                task.status = (
                    TaskStatus.COMPLETED if cached["exit_code"] == 0
                    else TaskStatus.FAILED)
                return

        # 自适应超时：EMA 平滑历史时间 × 2.5 倍安全裕度
        adaptive_timeout = task.timeout
        if task.task_type.value in self._timing_ema:
            adaptive_timeout = min(
                task.timeout,
                int(self._timing_ema[task.task_type.value] * 2.5 + 5))
            adaptive_timeout = max(10, adaptive_timeout)
        effective_timeout = self._profile.effective_timeout(adaptive_timeout)

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                task.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                cwd=task.working_dir,
                env={**os.environ, **task.env} if task.env else None,
            )
            elapsed = time.perf_counter() - t0
            task.output = proc.stdout + proc.stderr
            task.exit_code = proc.returncode
            task.status = (
                TaskStatus.COMPLETED if proc.returncode == 0
                else TaskStatus.FAILED)
            self._event_bus.publish(
                f"task:{task.task_id}",
                {"event": task.status.value, "task": task.task_id,
                 "exit_code": task.exit_code})
        except subprocess.TimeoutExpired:
            elapsed = effective_timeout
            task.output = "Task timed out"
            task.exit_code = -1
            task.status = TaskStatus.FAILED
        except Exception as exc:
            elapsed = time.perf_counter() - t0
            task.output = str(exc)
            task.exit_code = -2
            task.status = TaskStatus.FAILED

        # 更新 EMA 并写入缓存
        tt_key = task.task_type.value
        prev = self._timing_ema.get(tt_key, elapsed)
        self._timing_ema[tt_key] = (
            self._ema_alpha * elapsed + (1 - self._ema_alpha) * prev)
        if self._cache is not None and task.exit_code is not None:
            self._cache.store(
                task.command, task.working_dir,
                task.exit_code, task.output)

    def _execute_with_retry(self, task: TestTask) -> None:
        """指数退避重试：首次失败后等待 2^retry 秒重试"""
        effective_max = self._profile.effective_max_retries(task.max_retries)
        while task.retry_count <= effective_max:
            self._execute_one(task)
            if task.status == TaskStatus.COMPLETED:
                return
            if task.retry_count < effective_max:
                task.status = TaskStatus.RETRYING
                delay = min(2 ** task.retry_count, 30)
                time.sleep(delay)
                task.retry_count += 1
                task.output = ""
                task.exit_code = None
            else:
                return

    # ---- 检查点 ----
    def enable_checkpoint(self, directory: str) -> None:
        self._checkpoint_dir = directory
        os.makedirs(directory, exist_ok=True)

    def _save_checkpoint(self, workflow_id: str, tasks: List[TestTask]) -> None:
        if not self._checkpoint_dir:
            return
        path = os.path.join(self._checkpoint_dir, f"{workflow_id}.ckpt")
        payload = {
            "workflow_id": workflow_id,
            "tasks": [t.to_dict() for t in tasks],
            "timestamp": time.time(),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    def _load_checkpoint(self, workflow_id: str) -> Optional[List[TestTask]]:
        if not self._checkpoint_dir:
            return None
        path = os.path.join(self._checkpoint_dir, f"{workflow_id}.ckpt")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        # 从字典重建任务（简化重建，仅恢复关键字段）
        restored: List[TestTask] = []
        for td in payload.get("tasks", []):
            t = TestTask(
                task_id=td["task_id"],
                task_type=TaskType(td["task_type"]),
                name=td["name"],
                command=td["command"],
                working_dir=td.get("working_dir", "/workspace"),
                dependencies=td.get("dependencies", []),
                timeout=td.get("timeout", 300),
                status=TaskStatus(td.get("status", "pending")),
                output=td.get("output", ""),
                exit_code=td.get("exit_code"),
                max_retries=td.get("max_retries", 2),
            )
            t.retry_count = td.get("retry_count", 0)
            t.checkpoint_data = td.get("checkpoint", {})
            restored.append(t)
        return restored

    # ---- 核心执行循环 ----
    def execute_workflow(self, tasks: List[TestTask],
                         workflow_id: Optional[str] = None,
                         resume: bool = False) -> WorkflowResult:
        if workflow_id is None:
            workflow_id = f"workflow_{int(time.time())}"

        if resume:
            restored = self._load_checkpoint(workflow_id)
            if restored:
                # 合并：保留已完成的任务状态
                done_ids = {t.task_id for t in restored
                            if t.status == TaskStatus.COMPLETED}
                for t in tasks:
                    if t.task_id in done_ids:
                        t.status = TaskStatus.COMPLETED
                logger.info("Resumed workflow %s, %d tasks already done",
                            workflow_id, len(done_ids))
                self._save_checkpoint(workflow_id, tasks)

        start_time = time.time()
        nodes = self._build_dag(tasks)
        levels = self._topo_levels(nodes)
        completed_count = 0
        failed_count = 0
        skipped_count = 0

        for level_idx, level in enumerate(levels):
            pending = [t for t in level
                       if t.status not in (TaskStatus.COMPLETED,
                                           TaskStatus.SKIPPED)]
            if not pending:
                continue

            # 检查依赖：全部依赖完成才可执行，否则跳过
            executable: List[TestTask] = []
            for t in pending:
                deps_ok = all(
                    nodes[d].task.status == TaskStatus.COMPLETED
                    for d in t.dependencies if d in nodes)
                if deps_ok:
                    executable.append(t)
                else:
                    t.status = TaskStatus.SKIPPED
                    t.output = "Dependency not met"
                    skipped_count += 1

            if not executable:
                continue

            # 并行执行当前层
            with ThreadPoolExecutor(
                    max_workers=min(self._pool.capacity, len(executable))
            ) as executor:
                futures = {
                    executor.submit(self._execute_with_retry, t): t
                    for t in executable}
                for fut in as_completed(futures):
                    task = futures[fut]
                    try:
                        fut.result(timeout=task.timeout + 10)
                    except FutureTimeout:
                        task.output = "Task timed out at orchestrator level"
                        task.exit_code = -3
                        task.status = TaskStatus.FAILED
                    except Exception as exc:
                        task.output = str(exc)
                        task.exit_code = -4
                        task.status = TaskStatus.FAILED

            for t in executable:
                if t.status == TaskStatus.COMPLETED:
                    completed_count += 1
                elif t.status == TaskStatus.FAILED:
                    failed_count += 1

            self._save_checkpoint(workflow_id, tasks)

        total_time = time.time() - start_time
        summary = {
            'total_tasks': len(tasks),
            'completed_tasks': completed_count,
            'failed_tasks': failed_count,
            'skipped_tasks': skipped_count,
            'success_rate': (completed_count / len(tasks) * 100
                             if tasks else 0),
            'levels': len(levels),
        }
        return WorkflowResult(
            workflow_id=workflow_id,
            tasks=tasks,
            success_count=completed_count,
            failed_count=failed_count,
            skipped_count=skipped_count,
            total_time=total_time,
            summary=summary)

    # ---- 序列化 ----
    def save_workflow(self, tasks: List[TestTask], filepath: str) -> bool:
        try:
            import json
            workflow_data = {
                'tasks': [t.to_dict() for t in tasks],
                'generated_at': self._get_timestamp()
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(workflow_data, f, indent=2)
            logger.info(f"Workflow saved to: {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save workflow: {e}")
            return False

    # ---- 统计 ----
    def analyze_workflow(self, tasks: List[TestTask]) -> Dict[str, Any]:
        """对任务列表做静态分析：关键路径长度、预估最长执行时间"""
        nodes = self._build_dag(tasks)
        levels = self._topo_levels(nodes)
        critical_path = 0
        for level in levels:
            max_t = max((t.timeout for t in level), default=0)
            critical_path += max_t
        return {
            "task_count": len(tasks),
            "max_parallelism": max(len(lv) for lv in levels) if levels else 0,
            "depth": len(levels),
            "critical_path_seconds_est": critical_path,
        }

    @property
    def cache_stats(self) -> Dict[str, Any]:
        if self._cache is None:
            return {"enabled": False}
        return {
            "enabled": True,
            "entries": len(self._cache._store),
            "hits": self._cache._hits,
            "misses": self._cache._misses,
            "hit_rate": round(self._cache.hit_rate, 3),
            "timing_ema": dict(self._timing_ema),
        }

    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()


def create_test_workflow(vulnerability_info: Dict[str, Any]) -> List[TestTask]:
    orchestrator = TestOrchestrator()
    return orchestrator.create_workflow(vulnerability_info)
