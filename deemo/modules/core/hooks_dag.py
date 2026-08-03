"""
DAG 驱动的并行 Hook 管道 — 将线性执行升级为有向无环图分层并行.

基于 Kahn 拓扑排序将钩子节点按依赖关系分层, 同层无依赖的钩子
可并发执行; 支持条件触发链与执行遥测记录.

理论依据:
  CVE-GENIE (arXiv:2509.01835): EAGER 多智能体框架, 验证 DAG 分层并行
  对多阶段分析管道的加速效果.
  Slyp (arXiv:2605.05000): ReAct 代理管道 + MCP 工具服务器架构参考.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import logging, time

_log = logging.getLogger(__name__)


@dataclass
class HookNode:
    """钩子图节点: 持有可调用对象、依赖列表、条件断言及遥测计数器."""
    name: str
    hook_fn: Callable
    dependencies: List[str] = field(default_factory=list)
    condition: Optional[Callable] = None  # 返回 True 才执行
    priority: int = 0
    # 遥测
    call_count: int = 0
    total_latency_ms: float = 0.0
    success_count: int = 0


class HookDAG:
    """
    DAG 驱动的 Hook 管道 — Kahn 拓扑分层 + 同层并行执行.

    钩子声明依赖后自动分层; 同层节点无数据依赖, 可安全并发.
    条件断言 (condition) 在每层执行前过滤, 未通过者跳过该轮.
    """

    def __init__(self):
        self._nodes: Dict[str, HookNode] = {}
        self._adj: Dict[str, List[str]] = defaultdict(list)
        self._in_degree: Dict[str, int] = defaultdict(int)

    def register(
        self, name: str, hook_fn: Callable,
        deps: Optional[List[str]] = None,
        condition: Optional[Callable] = None,
        priority: int = 0,
    ):
        """注册节点: 建立邻接边并更新入度, 为拓扑分层准备图结构."""
        node = HookNode(name=name, hook_fn=hook_fn, dependencies=deps or [],
                       condition=condition, priority=priority)
        self._nodes[name] = node
        for dep in (deps or []):
            self._adj[dep].append(name)
            self._in_degree[name] = self._in_degree.get(name, 0) + 1
        if name not in self._in_degree:
            self._in_degree[name] = 0

    def topological_levels(self) -> List[List[str]]:
        """Kahn 算法分层: 按优先级降序排列同层节点, 返回层级列表."""
        in_deg = dict(self._in_degree)
        queue = deque([n for n, d in in_deg.items() if d == 0])
        levels: List[List[str]] = []
        while queue:
            level = sorted(queue, key=lambda n: self._nodes[n].priority, reverse=True)
            levels.append(level)
            next_queue = deque()
            for node_name in level:
                for neighbor in self._adj.get(node_name, []):
                    in_deg[neighbor] -= 1
                    if in_deg[neighbor] == 0:
                        next_queue.append(neighbor)
            queue = next_queue
        return levels

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """按序执行各层: 层内 ThreadPoolExecutor 并行, 层间串行 (下层消费上层写入的 context)."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        levels = self.topological_levels()
        for level in levels:
            futures = {}
            with ThreadPoolExecutor(max_workers=min(8, len(level))) as ex:
                for name in level:
                    node = self._nodes[name]
                    if node.condition and not node.condition(context):
                        continue
                    futures[ex.submit(self._execute_node, node, dict(context))] = name
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        result = future.result(timeout=60)
                        if result:
                            context.update(result)
                    except Exception as e:
                        _log.error("Hook %s 失败: %s", name, e)
        return context

    def _execute_node(self, node: HookNode, ctx: dict) -> Optional[dict]:
        t0 = time.perf_counter()
        try:
            result = node.hook_fn(ctx)
            node.success_count += 1
            return result
        finally:
            node.call_count += 1
            node.total_latency_ms += (time.perf_counter() - t0) * 1000

    def get_telemetry(self) -> List[Dict]:
        """返回所有钩子的执行遥测快照."""
        return [{
            "name": n.name, "calls": n.call_count,
            "avg_latency_ms": round(n.total_latency_ms / max(1, n.call_count), 2),
            "success_rate": round(n.success_count / max(1, n.call_count), 3),
            "deps": n.dependencies, "priority": n.priority,
        } for n in self._nodes.values()]


__all__ = ["HookNode", "HookDAG"]
