# coding: utf-8
"""
core/hook_dag_scheduler.py
DAG 感知的钩子执行与依赖加载顺序优化 (HookDAG)。

将钩子的线性注册-执行模型升级为依赖图模型:
  1. 钩子声明依赖, 构建有向无环图 (节点=钩子, 边=依赖), 检测环并报告;
  2. Kahn 拓扑分层, 同层无依赖的钩子可并行执行, 压缩关键路径长度;
  3. 失效路径旁路: 某钩子失败仅裁剪其下游子树, 无关分支照常推进;
  4. 依赖折叠: 同组且呈链式数据依赖的钩子折叠为单任务, 模块只加载一次;
  5. 懒加载衔接: 任务可按 module/attr 声明, 首次执行时才导入并缓存,
     同一模块的所有钩子共享一次加载, 直接对接 ../__init__.py 的扁平懒加载。

与 modules/core/hooks.py 的差异:
  现有 HookManager.run_hooks 按注册顺序线性执行 (依赖关系未显式建模);
  本模块引入依赖图与拓扑排序, 并提供可被既有初始化流程调用的调度接口。

算法依据:
  - GraphEdge: 面向 GNN 边缘计算的分层任务调度,
    将无依赖子任务并发执行以压缩关键路径, 并支持失效分支旁路。
  - Kahn: 拓扑排序 + 按层分组, 同层节点相互独立, 层内可并发。
  - 依赖折叠对应 GraphEdge 的可串行化子图合并: 降低调度与模块初始化开销。

边界条件:
  - 依赖环: build() 抛出 DAGCycleError 并报告环路径 (含自环)。
  - 线程无法硬性终止: 超时仅标记失败并旁路, 后台线程可能仍在运行。
  - 同层任务应写入互不冲突的 context 键; 冲突时以先完成者为准。
"""

import importlib
import logging
import os
import time
from collections import defaultdict, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


# 异常类型
class DAGCycleError(Exception):
    """依赖图中检测到环, 携带环路径 (首尾重复以标示闭环)。"""


# 数据结构
@dataclass
class HookTask:
    """DAG 中的一个钩子/初始化任务节点。

    可执行体二选一:
      - fn: 直接可调用对象, mode='context' 时以 fn(context) 调用,
        mode='args' 时以 fn(*context[k] for k in consumes, **kwargs) 调用;
      - module + attr: 懒加载模块路径与属性名, 首次执行时才 import 并缓存,
        实现依赖折叠中的"模块只加载一次"。
    """
    name: str
    fn: Optional[Callable] = None
    module: Optional[str] = None
    attr: Optional[str] = None
    deps: Tuple[str, ...] = ()
    group: Optional[str] = None          # 分组标记, 供 auto_fold 折叠使用
    condition: Optional[Callable[[Dict[str, Any]], bool]] = None
    priority: int = 0                    # 同层内排序权重, 大者优先
    timeout: Optional[float] = None      # 秒; 超时标记失败并旁路
    mode: str = 'context'                # 'context' | 'args'
    consumes: Tuple[str, ...] = ()       # mode='args' 时的 context 键序列
    kwargs: Dict[str, Any] = field(default_factory=dict)
    on_dep_failed: str = 'skip'          # 'skip': 依赖失败则跳过; 'continue': 照常执行
    provides: Tuple[str, ...] = ()
    description: str = ''


@dataclass
class _TaskTelemetry:
    """任务执行遥测, 供 get_telemetry / execution_summary 汇总。"""
    status: str = 'pending'
    call_count: int = 0
    success_count: int = 0
    total_latency_ms: float = 0.0
    last_latency_ms: float = 0.0
    last_error: str = ''


# 调度器核心
class HookDAGScheduler:
    """DAG 驱动的钩子调度器。

    注册 → (可选)auto_fold → execute 三条主路径:
      build()  校验依赖并做 Kahn 分层, 检测环;
      auto_fold() 对链式同组任务折叠;
      execute() 按层并行执行, 失效路径旁路, 产出 context 与遥测。
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, HookTask] = {}
        self._fold_members: Dict[str, HookTask] = {}  # 被折叠成员, 仅供折叠任务内部引用
        self._module_cache: Dict[str, Any] = {}       # 模块加载缓存 → 依赖折叠的关键
        self._succ: Dict[str, List[str]] = {}
        self._levels: List[List[str]] = []
        self._telemetry: Dict[str, _TaskTelemetry] = {}
        self._launch_time: Dict[str, float] = {}
        self._timed_out: set = set()
        self._built: bool = False
        self._parallel: bool = True
        self._max_workers: int = 4
        self._failed: set = set()
        self._skipped: set = set()
        self._exec_start: float = 0.0
        self._exec_end: float = 0.0

# 注册与查询
    def register(
        self,
        name: str,
        fn: Optional[Callable] = None,
        *,
        module: Optional[str] = None,
        attr: Optional[str] = None,
        deps: Tuple[str, ...] = (),
        group: Optional[str] = None,
        condition: Optional[Callable[[Dict[str, Any]], bool]] = None,
        priority: int = 0,
        timeout: Optional[float] = None,
        mode: str = 'context',
        consumes: Tuple[str, ...] = (),
        kwargs: Optional[Dict[str, Any]] = None,
        on_dep_failed: str = 'skip',
        provides: Tuple[str, ...] = (),
        description: str = '',
    ) -> 'HookDAGScheduler':
        """注册一个钩子任务。fn 与 (module, attr) 至少提供其一。

        deps 允许前向引用: 依赖合法性推迟到 build() 统一校验。
        """
        if name in self._tasks:
            raise ValueError(f'重复注册任务: {name}')
        if fn is None and not (module and attr):
            raise ValueError(f'任务 {name} 必须提供 fn 或 (module, attr)')
        if on_dep_failed not in ('skip', 'continue'):
            raise ValueError(f'任务 {name} 的 on_dep_failed 非法: {on_dep_failed}')

        self._tasks[name] = HookTask(
            name=name, fn=fn, module=module, attr=attr,
            deps=tuple(deps), group=group, condition=condition,
            priority=priority, timeout=timeout, mode=mode,
            consumes=tuple(consumes), kwargs=dict(kwargs or {}),
            on_dep_failed=on_dep_failed, provides=tuple(provides),
            description=description,
        )
        self._built = False
        return self

    def module_ref(self, module_path: str, attr: str) -> Callable[..., Any]:
        """返回懒加载 thunk: 首次调用时导入并缓存模块, 取 getattr(module, attr)。

        同一 module_path 只加载一次 (写回 self._module_cache),
        实现依赖折叠中"同一模块的多钩子共享初始化"的目标。
        """
        cache = self._module_cache

        def _resolver(*args: Any, **kw: Any) -> Any:
            mod = cache.get(module_path)
            if mod is None:
                mod = importlib.import_module(module_path)
                cache[module_path] = mod
            return getattr(mod, attr)(*args, **kw)

        return _resolver

    def module_attr(self, module_path: str, attr: str) -> Callable[[], Any]:
        """返回懒加载引用 thunk: 调用后得到模块内的 attr 对象 (类/枚举等)。

        与 module_ref 的区别: module_ref 的 thunk 会立即调用 attr(*args);
        此处仅解析引用, 供访问类成员 (如 Enum.MEMBER) 使用。两者共享
        _module_cache, 模块仍只加载一次。
        """
        cache = self._module_cache

        def _get() -> Any:
            mod = cache.get(module_path)
            if mod is None:
                mod = importlib.import_module(module_path)
                cache[module_path] = mod
            return getattr(mod, attr)

        return _get

    def _get_task(self, name: str) -> HookTask:
        """取任务; 折叠成员仍在 _fold_members 中可查。"""
        task = self._tasks.get(name)
        if task is not None:
            return task
        member = self._fold_members.get(name)
        if member is not None:
            return member
        raise KeyError(f'未知任务: {name}')

    def __contains__(self, name: str) -> bool:
        return name in self._tasks or name in self._fold_members

    def __len__(self) -> int:
        return len(self._tasks) + len(self._fold_members)

# 图构建: 校验 + Kahn 分层 + 环检测
    def build(self) -> 'HookDAGScheduler':
        """校验依赖引用, 构建后继邻接表, 做 Kahn 拓扑分层, 检测环。"""
        known = set(self._tasks)
        unknown = sorted({d for t in self._tasks.values() for d in t.deps if d not in known})
        if unknown:
            raise ValueError(f'未知依赖: {unknown}')

        self._succ = defaultdict(list)
        in_deg: Dict[str, int] = {n: 0 for n in self._tasks}
        for name, task in self._tasks.items():
            for dep in task.deps:
                if dep == name:
                    # 自环立即报告
                    raise DAGCycleError([name, name])
                self._succ[dep].append(name)
                in_deg[name] += 1

        self._levels = self._kahn_levels(in_deg)
        self._built = True
        return self

    def _kahn_levels(self, in_deg: Dict[str, int]) -> List[List[str]]:
        # 标准Kahn分层: 零入度节点出队构成一层, 削减后继入度复入队
        levels: List[List[str]] = []
        ready = deque(sorted(
            (n for n, d in in_deg.items() if d == 0),
            key=lambda n: (-self._tasks[n].priority, n),
        ))
        processed = 0
        while ready:
            level: List[str] = []
            nxt: List[str] = []
            for name in list(ready):
                level.append(name)
                processed += 1
                for succ in self._succ.get(name, ()):
                    in_deg[succ] -= 1
                    if in_deg[succ] == 0:
                        nxt.append(succ)
            levels.append(level)
            ready = deque(sorted(nxt, key=lambda n: (-self._tasks[n].priority, n)))

        if processed != len(self._tasks):
            remaining = [n for n, d in in_deg.items() if d > 0]
            cycle = self._find_cycle(remaining)
            raise DAGCycleError(cycle or remaining)
        return levels

    def _find_cycle(self, nodes: List[str]) -> List[str]:
        # 三色DFS环检测: 白(未访)→灰(在栈)→黑(已出栈), 遇灰即命中环
        color: Dict[str, int] = {n: 0 for n in nodes}  # 0=白/1=灰/2=黑
        path: List[str] = []

        def dfs(n: str) -> Optional[List[str]]:
            color[n] = 1
            path.append(n)
            for succ in self._succ.get(n, ()):
                if succ not in color:
                    continue
                if color[succ] == 1:
                    idx = path.index(succ)
                    return path[idx:] + [succ]
                if color[succ] == 0:
                    found = dfs(succ)
                    if found:
                        return found
            path.pop()
            color[n] = 2
            return None

        for n in nodes:
            if color[n] == 0:
                found = dfs(n)
                if found:
                    return found
        return []

    def topological_levels(self) -> List[List[str]]:
        """返回可并行执行的层级列表 (每层为一个任务名列表)。"""
        if not self._built:
            self.build()
        return [list(level) for level in self._levels]

    def validate(self) -> List[str]:
        """返回图中存在的问题清单 (空表即合法)。"""
        issues: List[str] = []
        try:
            self.build()
        except (DAGCycleError, ValueError) as exc:
            issues.append(str(exc))
        return issues

# 依赖折叠
    def auto_fold(self) -> 'HookDAGScheduler':
        """依赖折叠: 对同组且呈链式数据依赖的任务折叠为单个任务。

        链式判据: 组内每个成员组内入度/出度均 <= 1, 且唯一源可达全部成员。
        折叠后外部依赖重接线到折叠节点, 模块级加载由 _module_cache 保证单次。
        对应 GraphEdge 的可串行化子图合并, 减少调度与初始化开销。
        """
        if not self._tasks:
            return self
        groups: Dict[str, List[str]] = defaultdict(list)
        for name, task in self._tasks.items():
            if task.group:
                groups[task.group].append(name)
        for group, members in groups.items():
            if len(members) < 2:
                continue
            chain = self._find_chain(members)
            if chain:
                self._fold_chain(group, chain)
        self._built = False
        return self

    def _find_chain(self, members: List[str]) -> Optional[List[str]]:
        """判定组内任务是否构成单链, 返回链序或 None。"""
        mset = set(members)
        in_edges = {m: [d for d in self._tasks[m].deps if d in mset] for m in members}
        out_edges = {m: [x for x in members if m in in_edges[x]] for m in members}
        heads = [m for m in members if not in_edges[m]]
        if len(heads) != 1:
            return None  # 无唯一源, 呈扇出/森林结构, 不折叠
        if any(len(v) > 1 for v in in_edges.values()):
            return None  # 多依赖汇合, 不折叠
        if any(len(v) > 1 for v in out_edges.values()):
            return None  # 单源分叉, 不折叠
        chain: List[str] = []
        seen: set = set()
        cur: Optional[str] = heads[0]
        while cur is not None and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            nxt = out_edges[cur]
            cur = nxt[0] if nxt else None
        if set(chain) != mset:
            return None
        return chain

    def _fold_chain(self, group: str, chain: List[str]) -> None:
        """按链序折叠: 折叠函数顺序执行各成员, 任一失败即中止并标记。"""
        members = set(chain)
        ext_deps: List[str] = []
        for m in chain:
            for d in self._tasks[m].deps:
                if d not in members and d not in ext_deps:
                    ext_deps.append(d)

        folded_name = f'{group}:fold'

        def _folded(ctx: Dict[str, Any]) -> Dict[str, Any]:
            failed: set = set()
            skipped: set = set()
            for i, m in enumerate(chain):
                self._execute_one(m, ctx, failed, skipped)
                if m in failed:
                    # 链中断: 后续成员因数据依赖不可得而旁路
                    for rest in chain[i + 1:]:
                        self._telemetry[rest].status = 'skipped'
                        self._telemetry[rest].last_error = f'链前序 {m} 失败'
                    raise RuntimeError(f'折叠成员 {m} 执行失败')
            return ctx

        provides = tuple(sorted({p for m in chain for p in self._tasks[m].provides}))
        self._tasks[folded_name] = HookTask(
            name=folded_name, fn=_folded, deps=tuple(ext_deps),
            group=group, provides=provides,
            description=f'folded: {" -> ".join(chain)}',
        )

        # 外部依赖重接线: 指向被折叠成员的任务改指折叠节点
        for name, task in list(self._tasks.items()):
            if name in members:
                continue
            new_deps = tuple(folded_name if d in members else d for d in task.deps)
            if new_deps != task.deps:
                self._tasks[name] = HookTask(
                    name=name, fn=task.fn, module=task.module, attr=task.attr,
                    deps=new_deps, group=task.group, condition=task.condition,
                    priority=task.priority, timeout=task.timeout, mode=task.mode,
                    consumes=task.consumes, kwargs=dict(task.kwargs),
                    on_dep_failed=task.on_dep_failed, provides=task.provides,
                    description=task.description,
                )

        # 成员移入 _fold_members, 供折叠任务内部执行与遥测查询
        for m in chain:
            self._fold_members[m] = self._tasks.pop(m)

# 执行
    def execute(self, context: Optional[Dict[str, Any]] = None,
                max_workers: Optional[int] = None,
                parallel: bool = True) -> Dict[str, Any]:
        """按拓扑层执行全部钩子, 返回合并后的 context。

        失效路径旁路: 层内失败的钩子加入 failed 集; 其下游按 on_dep_failed
        决定跳过或继续, 无关分支不受影响 (对应 GraphEdge 的失效分支旁路)。
        """
        if not self._built:
            self.build()
        if context is None:
            context = {}
        self._parallel = parallel
        self._max_workers = max_workers or max(1, min(8, os.cpu_count() or 1))

        all_names = set(self._tasks) | set(self._fold_members)
        self._telemetry = {n: _TaskTelemetry() for n in all_names}
        self._launch_time.clear()
        self._timed_out.clear()
        self._failed = set()
        self._skipped = set()
        self._exec_start = time.monotonic()

        for level in self._levels:
            self._run_level(level, context)

        self._exec_end = time.monotonic()
        return context

    def run_task(self, name: str, context: Optional[Dict[str, Any]] = None) -> Any:
        """单任务调试入口: 独立执行指定任务 (含懒加载解析与失败捕获)。"""
        if not self._built:
            self.build()
        if context is None:
            context = {}
        all_names = set(self._tasks) | set(self._fold_members)
        self._telemetry = {n: _TaskTelemetry() for n in all_names}
        failed: set = set()
        skipped: set = set()
        self._execute_one(name, context, failed, skipped)
        return context

    def _run_level(self, level: List[str], context: Dict[str, Any]) -> None:
        """执行一层: 先剔除依赖已失效的任务, 再按 parallel 决定并发策略。"""
        to_run: List[str] = []
        for name in level:
            task = self._tasks.get(name)
            if task is None:
                continue  # 折叠后不存在的活动层不应出现, 防御性跳过
            if any(d in self._failed or d in self._skipped for d in task.deps) \
                    and task.on_dep_failed == 'skip':
                self._telemetry[name].status = 'skipped'
                self._telemetry[name].last_error = '依赖不可用, 旁路'
                self._skipped.add(name)
            else:
                to_run.append(name)

        if not to_run:
            return

        if self._parallel and len(to_run) > 1:
            ex = ThreadPoolExecutor(max_workers=min(self._max_workers, len(to_run)))
            futures = {}
            try:
                for name in to_run:
                    self._launch_time[name] = time.monotonic()
                    futures[ex.submit(self._execute_one, name, context,
                                      self._failed, self._skipped)] = name
                self._collect_futures(futures)
            finally:
                # wait=False: 超时的钩子线程可能仍在运行, 不阻塞整体推进
                ex.shutdown(wait=False)
        else:
            for name in to_run:
                self._execute_one(name, context, self._failed, self._skipped)

    def _collect_futures(self, futures: Dict[Any, str]) -> None:
        """轮询等待层内 future, 按任务自身 timeout 判定超时并旁路。"""
        pending = set(futures)
        while pending:
            done, still = wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
            now = time.monotonic()
            for fut in done:
                self._absorb_future(fut, futures[fut])
            for fut in list(still):
                name = futures[fut]
                task = self._tasks.get(name)
                if task is not None and task.timeout \
                        and now - self._launch_time.get(name, now) > task.timeout:
                    self._absorb_future(fut, name)
                    still.discard(fut)
            pending = still

    def _absorb_future(self, fut: Any, name: str) -> None:
        """收编单个 future 的最终结果; 超时/异常统一标记失败。"""
        task = self._tasks.get(name)
        node = self._telemetry[name]
        if task is None or not task.timeout:
            try:
                fut.result()
            except Exception as exc:  # 工作线程已兜底, 此处仅防御
                node.status = 'failed'
                node.last_error = f'{type(exc).__name__}: {exc}'
                self._failed.add(name)
            return

        elapsed = time.monotonic() - self._launch_time.get(name, time.monotonic())
        try:
            fut.result(timeout=max(0.0, task.timeout - elapsed))
        except TimeoutError:
            node.status = 'failed'
            node.last_error = f'timeout after {task.timeout}s'
            node.call_count += 1
            self._timed_out.add(name)
            self._failed.add(name)
        except Exception as exc:
            node.status = 'failed'
            node.last_error = f'{type(exc).__name__}: {exc}'
            self._failed.add(name)

    def _execute_one(self, name: str, context: Dict[str, Any],
                     failed: set, skipped: set) -> None:
        """执行单个任务: 旁路判定 → 条件过滤 → 运行 → 遥测记录。不抛出。"""
        task = self._get_task(name)
        node = self._telemetry[name]

        # 失效路径旁路: 依赖失败/跳过且策略为 skip 则本任务跳过
        for dep in task.deps:
            if dep in failed or dep in skipped:
                if task.on_dep_failed == 'skip':
                    node.status = 'skipped'
                    node.last_error = f'依赖 {dep} 不可用'
                    skipped.add(name)
                    return

        if task.condition is not None and not task.condition(context):
            node.status = 'skipped'
            skipped.add(name)
            return

        if name in self._timed_out:
            return  # 已被判定超时, 迟到结果不覆盖

        node.status = 'running'
        t0 = time.perf_counter()
        try:
            fn = self._resolve_callable(task)
            if task.mode == 'args':
                args = [context.get(key) for key in task.consumes]
                result = fn(*args, **task.kwargs)
            else:
                result = fn(context)

            elapsed_ms = (time.perf_counter() - t0) * 1000
            if name in self._timed_out:
                return
            node.call_count += 1
            node.success_count += 1
            node.total_latency_ms += elapsed_ms
            node.last_latency_ms = elapsed_ms
            node.status = 'success'
            node.last_error = ''
            if isinstance(result, dict):
                context.update(result)
            elif result is not None:
                context[name] = result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            if name in self._timed_out:
                return
            node.call_count += 1
            node.total_latency_ms += elapsed_ms
            node.last_latency_ms = elapsed_ms
            node.status = 'failed'
            node.last_error = f'{type(exc).__name__}: {exc}'
            failed.add(name)

    def _resolve_callable(self, task: HookTask) -> Callable[..., Any]:
        """解析任务可执行体; module/attr 任务在此完成懒加载与单次缓存。"""
        if task.fn is not None:
            return task.fn
        if task.module and task.attr:
            mod = self._module_cache.get(task.module)
            if mod is None:
                mod = importlib.import_module(task.module)
                self._module_cache[task.module] = mod
            return getattr(mod, task.attr)
        raise ValueError(f'任务 {task.name} 无可执行体')

# 遥测与报告
    def get_telemetry(self) -> List[Dict[str, Any]]:
        """返回全部任务的执行遥测。"""
        out = []
        for name, node in sorted(self._telemetry.items()):
            try:
                task = self._get_task(name)
                deps = list(task.deps)
                group = task.group
            except KeyError:
                deps, group = [], None
            out.append({
                'name': name,
                'status': node.status,
                'calls': node.call_count,
                'successes': node.success_count,
                'avg_latency_ms': round(node.total_latency_ms / max(1, node.call_count), 3),
                'last_latency_ms': round(node.last_latency_ms, 3),
                'last_error': node.last_error,
                'deps': deps,
                'group': group,
            })
        return out

    def execution_summary(self) -> Dict[str, Any]:
        """汇总执行结果: 状态计数、失败/跳过清单、层级数、墙钟耗时。"""
        counts = {'success': 0, 'failed': 0, 'skipped': 0, 'pending': 0, 'running': 0}
        for node in self._telemetry.values():
            counts[node.status] = counts.get(node.status, 0) + 1
        return {
            'status_counts': counts,
            'failed': sorted(self._failed),
            'skipped': sorted(self._skipped),
            'levels': len(self._levels),
            'wall_sec': round(self._exec_end - self._exec_start, 4)
            if self._exec_start and self._exec_end else 0.0,
        }

    def graph_edges(self) -> Dict[str, List[str]]:
        """返回邻接表 (前驱 → 后继), 供外部可视化/调试。"""
        if not self._built:
            self.build()
        return {n: list(v) for n, v in self._succ.items()}


# 模块级便捷入口
def execute_hook_dag(tasks: List[Any],
                     context: Optional[Dict[str, Any]] = None,
                     max_workers: Optional[int] = None,
                     parallel: bool = True,
                     auto_fold: bool = True) -> Dict[str, Any]:
    """从任务列表构建调度器并执行。

    tasks 元素可为 HookTask 实例或与 register() 形参一致的 dict。
    """
    sched = HookDAGScheduler()
    for item in tasks:
        if isinstance(item, HookTask):
            sched.register(
                item.name, item.fn, module=item.module, attr=item.attr,
                deps=item.deps, group=item.group, condition=item.condition,
                priority=item.priority, timeout=item.timeout, mode=item.mode,
                consumes=item.consumes, kwargs=dict(item.kwargs),
                on_dep_failed=item.on_dep_failed, provides=item.provides,
                description=item.description,
            )
        elif isinstance(item, dict):
            sched.register(**dict(item))
        else:
            raise TypeError(f'不支持的钩子任务类型: {type(item)!r}')
    if auto_fold:
        sched.auto_fold()
    return sched.execute(context, max_workers=max_workers, parallel=parallel)


def build_compat_init_dag(binary_path: str = '') -> HookDAGScheduler:
    """构建对接 compat/ 懒加载模块的标准初始化调度图。

    任务以 module/attr 或 module_ref thunk 声明, 首次执行才 import,
    同一模块的多个钩子共享一次加载。各分析分支互不依赖, 可并行;
    ci_report 设 on_dep_failed='continue', 演示单分支失败不阻塞汇总。
    """
    sched = HookDAGScheduler()
    ldr = sched.module_ref('modules.core.compat.binary_format_loader', 'load_binary')

    def task_binary_loader(ctx: Dict[str, Any]) -> Dict[str, Any]:
        # 解析二进制, 产出 ParsedBinary 与格式标识
        info = ldr(ctx.get('binary_path', ''))
        ctx['binary_info'] = info
        fmt = getattr(info, 'format', '')
        ctx['format'] = fmt.value if hasattr(fmt, 'value') else str(fmt)
        return ctx

    def task_binary_summary(ctx: Dict[str, Any]) -> Dict[str, Any]:
        # 由 ParsedBinary 折叠出轻量摘要, 供后续任务消费
        info = ctx.get('binary_info')
        arch = getattr(info, 'arch', '')
        ctx['binary_summary'] = {
            'format': ctx.get('format'),
            'arch': arch.value if hasattr(arch, 'value') else str(arch),
            'bits': getattr(info, 'bits', 0),
            'n_sections': len(getattr(info, 'sections', None) or []),
            'n_imports': len(getattr(info, 'imports', None) or []),
            'n_exports': len(getattr(info, 'exports', None) or []),
        }
        return ctx

    def task_attack_surface(ctx: Dict[str, Any]) -> Dict[str, Any]:
        Mapper = sched.module_ref('modules.core.compat.attack_surface', 'AttackSurfaceMapper')
        ctx['attack_surface'] = Mapper(ctx.get('binary_path', '')).analyze()
        return ctx

    def task_crypto_extract(ctx: Dict[str, Any]) -> Dict[str, Any]:
        Extractor = sched.module_ref('modules.core.compat.crypto_param_extractor',
                                     'CryptoParamExtractor')
        ctx['crypto_params'] = Extractor(ctx.get('binary_path', '')).extract()
        return ctx

    def task_vtable_recover(ctx: Dict[str, Any]) -> Dict[str, Any]:
        Rec = sched.module_ref('modules.core.compat.precise_vtable_recovery', 'VTableRecovery')
        ctx['vtables'] = Rec().recover_vtables(ctx.get('binary_path', ''))
        return ctx

    def task_attack_mapper(ctx: Dict[str, Any]) -> Dict[str, Any]:
        # 依赖 binary_info; 无漏洞列表时以二进制格式占位
        Mapper = sched.module_ref('modules.core.compat.attack_mapper', 'AttackMapper')
        info = ctx.get('binary_info')
        vulns = ctx.get('vulnerabilities')
        if not vulns and info is not None:
            vulns = [{'vulnerability_type': ctx.get('format', ''), 'cwe_id': ''}]
        ctx['attack_mappings'] = Mapper().map_vulnerabilities(vulns or [])
        return ctx

    def task_ids_rules(ctx: Dict[str, Any]) -> Dict[str, Any]:
        Gen = sched.module_ref('modules.core.compat.ids_rule_generator', 'IDSRuleGenerator')
        vulns = ctx.get('vulnerabilities') or [{}]
        ctx['ids_rules'] = Gen().generate_rules_for_vulnerability(
            vuln_info=vulns[0], binary_info=ctx.get('binary_info'))
        return ctx

    def task_ci_report(ctx: Dict[str, Any]) -> Dict[str, Any]:
        # 汇总各分支产物; on_dep_failed='continue' 使单分支失败不阻塞出报告
        CI = sched.module_ref('modules.core.compat.ci_integration', 'CIIntegration')
        CIF = sched.module_ref('modules.core.compat.ci_integration', 'CIFinding')
        Sev = sched.module_attr('modules.core.compat.ci_integration', 'CIFindingSeverity')
        findings = []
        for key in ('attack_surface', 'crypto_params', 'vtables', 'ids_rules',
                    'attack_mappings', 'binary_summary'):
            data = ctx.get(key)
            if data is None:
                continue
            findings.append(CIF(
                rule_id=f'BINMIND-{key.upper()}',
                severity=Sev().INFO,
                message=f'{key}: {type(data).__name__}',
                file_path=ctx.get('binary_path', ''),
            ))
        ci = CI()
        ctx['ci_exit_code'] = ci.get_exit_code(findings)
        ctx['ci_report'] = ci.generate_report(findings)
        return ctx

    def task_status(ctx: Dict[str, Any]) -> Dict[str, Any]:
        # 独立于各分析分支, 任意分支失败不影响状态输出
        ctx['status'] = {'binary_path': ctx.get('binary_path'), 'ok': True}
        return ctx

    sched.register('binary_loader', fn=task_binary_loader, group='loader',
                   provides=('binary_info', 'format'),
                   description='解析二进制格式 (load_binary)')
    sched.register('binary_summary', fn=task_binary_summary, deps=('binary_loader',),
                   group='loader', provides=('binary_summary',),
                   description='由 ParsedBinary 折叠摘要')
    sched.register('attack_surface', fn=task_attack_surface, group='surface',
                   provides=('attack_surface',), description='攻击面分析')
    sched.register('crypto_extract', fn=task_crypto_extract, group='crypto',
                   provides=('crypto_params',), description='密码参数提取')
    sched.register('vtable_recover', fn=task_vtable_recover, group='vtable',
                   provides=('vtables',), description='虚表精确恢复')
    sched.register('attack_mapper', fn=task_attack_mapper, deps=('binary_loader',),
                   provides=('attack_mappings',), description='ATT&CK 攻击映射')
    sched.register('ids_rules', fn=task_ids_rules, deps=('binary_loader',),
                   provides=('ids_rules',), description='IDS 规则生成')
    sched.register('ci_report', fn=task_ci_report,
                   deps=('attack_surface', 'crypto_extract', 'vtable_recover',
                         'attack_mapper', 'ids_rules'),
                   on_dep_failed='continue',
                   provides=('ci_exit_code', 'ci_report'), description='CI 汇总报告')
    sched.register('status', fn=task_status, deps=('binary_loader',),
                   provides=('status',), description='状态输出')
    return sched


def run_compat_init(binary_path: str,
                    context: Optional[Dict[str, Any]] = None,
                    parallel: bool = True,
                    fold: bool = True) -> Tuple[Dict[str, Any], HookDAGScheduler]:
    """便捷入口: 构建标准 compat 初始化 DAG → 折叠 → 执行。

    返回 (context, scheduler), 调用方可用 scheduler.get_telemetry()
    检查各分支执行状态。
    """
    sched = build_compat_init_dag(binary_path)
    if fold:
        sched.auto_fold()
    if context is None:
        context = {'binary_path': binary_path}
    else:
        context.setdefault('binary_path', binary_path)
    ctx = sched.execute(context, parallel=parallel)
    return ctx, sched


__all__ = [
    'HookTask', 'HookDAGScheduler', 'DAGCycleError',
    'execute_hook_dag', 'build_compat_init_dag', 'run_compat_init',
]


