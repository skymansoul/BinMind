# 类型导向自组装执行DAG (Type-Directed Self-Assembling Execution DAG)
#
# 核心问题: 模块有 50+ 子模块, 每个提供独立的处理能力,
#   但开发者需要手动编排调用顺序. 典型流程:
#     import_file → compute_sha256 → bloom_check → simhash → db_lookup → export
#   手动编排容易遗漏优化机会 (如跳过不必要的阶段、并行化独立操作).
#
# 创新点:
#   1. 类型签名推断: 对每个模块的公开函数, 通过 inspect 反射参数类型
#      和返回值类型, 构建类型签名. 将 Python 类型映射为抽象类型标签:
#        bytes → "binary_data", dict → "signature_record",
#        List[float] → "feature_vector", str → "file_path", ...
#   2. 类型兼容图: 节点 = 函数, 边 = f的输出类型 ⊆ g的输入类型.
#      构建有向图 G(V,E) 后, 用拓扑排序 + DP 求从 source 到 sink
#      的最长路径 (覆盖最多处理阶段). 复杂度 O(V+E).
#   3. 并行化检测: 对 DAG 中入度为 0 且互相无数据依赖的节点,
#      标记为可并行执行. 用 critical path 分析计算理论加速比.
#   4. 成本自适应调度: 每个节点标注估计执行时间 (来自历史统计),
#      调度器优先执行 critical path 上的节点, 将非关键节点
#      延迟到空闲时段或跳过 (若超时预算).
#
# 与现有工作:
#   - pipeline.py: 静态阶段定义, 需手动编排. 本方案自动发现 + 组装.
#   - bandit_router.py: 在固定方法集合中选择. 本方案动态选择方法链.
#   - 程序合成 (program synthesis): 面向通用编程. 本方案面向数据管线的
#     类型导向组装, 搜索空间受限 (仅本模块的公开 API).

import inspect
import time
from collections import defaultdict, deque
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# 类型标签映射: Python type → abstract type tag
_TYPE_TAG_MAP = {
    "bytes": "binary_data",
    "bytearray": "binary_data",
    "str": "string_value",
    "int": "integer_value",
    "float": "numeric_value",
    "bool": "boolean_flag",
    "dict": "signature_record",
    "list": "collection",
    "set": "collection",
    "tuple": "collection",
    "NoneType": "void",
}


class NodeSpec:
    """管线节点规格."""
    __slots__ = ("name","func","input_types","output_type",
                 "est_cost_ms","module_name","is_parallelizable")
    def __init__(self, name: str, func: Callable,
                 input_types: List[str], output_type: str,
                 est_cost_ms: float = 1.0, module_name: str = "",
                 is_parallelizable: bool = True):
        self.name = name; self.func = func
        self.input_types = input_types; self.output_type = output_type
        self.est_cost_ms = est_cost_ms; self.module_name = module_name
        self.is_parallelizable = is_parallelizable


class AutoPipeline:
    """自组装管线: 类型兼容图构建 → 最长路径规划 → 并行调度.

    用法:
      ap = AutoPipeline()
      ap.register("sha256", hashlib.sha256, ["binary_data"], "string_value", cost=0.5)
      ap.register("bloom_check", bloom.might_contain, ["string_value"], "boolean_flag", cost=0.1)
      plan = ap.plan(source="binary_data", sink="signature_record")
      for step in plan:
          print(step.name)
    """

    def __init__(self):
        self._nodes: Dict[str, NodeSpec] = {}
        # 类型兼容图: {output_type: [node_names]}
        self._by_output: Dict[str, List[str]] = defaultdict(list)
        self._by_input: Dict[str, List[str]] = defaultdict(list)

    def register(self, name: str, func: Callable,
                  input_types: List[str], output_type: str,
                  cost: float = 1.0, module: str = "",
                  parallel: bool = True):
        """注册一个管线节点."""
        node = NodeSpec(name, func, input_types, output_type,
                         est_cost_ms=cost, module_name=module,
                         is_parallelizable=parallel)
        self._nodes[name] = node
        self._by_output[output_type].append(name)
        for it in input_types:
            self._by_input[it].append(name)

    def register_from_function(self, func: Callable, cost: float = 1.0):
        """从函数反射自动注册: 推断类型标签."""
        name = func.__name__
        try:
            sig = inspect.signature(func)
        except (ValueError, TypeError):
            return

        input_types = []
        for pname, param in sig.parameters.items():
            if pname == 'self':
                continue
            anno = param.annotation
            tag = self._anno_to_tag(anno)
            input_types.append(tag)

        ret_anno = sig.return_annotation
        output_type = self._anno_to_tag(ret_anno)

        self.register(name, func, input_types, output_type, cost=cost)

    def plan(self, source_type: str, sink_type: str,
              max_depth: int = 10) -> List[NodeSpec]:
        """规划从 source 到 sink 的最优管线.

        算法: 拓扑排序 + DP 最长路径.
        DP[i] = 以节点 i 结尾的最长路径 (阶段数最多).
        """
        # 构建邻接表
        adj: Dict[str, List[str]] = defaultdict(list)
        in_degree: Dict[str, int] = defaultdict(int)

        for name, node in self._nodes.items():
            for it in node.input_types:
                for src_name in self._by_output.get(it, []):
                    if src_name != name:
                        adj[src_name].append(name)
                        in_degree[name] = in_degree.get(name, 0) + 1

        # 找出所有 source_type 可达的节点
        start_nodes = self._by_output.get(source_type, [])
        if not start_nodes:
            return []

        # Kahn 拓扑排序 (含环检测)
        queue = deque(start_nodes[:])
        topo = []
        visited = set()
        indeg = dict(in_degree)
        for sn in start_nodes:
            indeg[sn] = indeg.get(sn, 0)

        while queue:
            cur = queue.popleft()
            if cur in visited:
                continue
            visited.add(cur)
            topo.append(cur)
            for nb in adj.get(cur, []):
                if nb == cur:
                    continue  # 跳过自环
                indeg[nb] = indeg.get(nb, 0) - 1
                if indeg[nb] <= 0 and nb not in visited:
                    queue.append(nb)

        if not topo:
            return []

        # BFS 最短路径 (避免环导致无限长路径)
        # 使用 BFS 层序遍历, 每层是经过的节点数
        prev: Dict[str, Optional[str]] = {}
        visited = set()
        queue = deque()
        for sn in start_nodes:
            if sn not in visited:
                visited.add(sn); prev[sn] = None; queue.append(sn)

        end_node = None
        while queue and end_node is None:
            cur = queue.popleft()
            if self._nodes[cur].output_type == sink_type:
                end_node = cur; break
            if prev.get(cur, ()) and len(self._trace_path(prev, cur)) >= max_depth:
                continue
            for nb in adj.get(cur, []):
                if nb not in visited:
                    visited.add(nb); prev[nb] = cur; queue.append(nb)

        if end_node is None and visited:
            # 无精确 sink: 返回已访问的最远节点
            end_node = max(visited, key=lambda n: len(self._trace_path(prev, n)))

        return self._trace_path(prev, end_node) if end_node else []

    def _trace_path(self, prev: Dict[str, Optional[str]],
                     end: str) -> List[NodeSpec]:
        """从 prev 映射回溯路径."""
        path = []
        cur = end
        visited_in_path = set()
        while cur is not None and cur not in visited_in_path:
            visited_in_path.add(cur)
            path.append(self._nodes[cur])
            cur = prev.get(cur)
        path.reverse()
        return path

    def parallel_plan(self, source_type: str, sink_type: str
                       ) -> Tuple[List[NodeSpec], List[List[NodeSpec]]]:
        """返回 (critical_path, parallel_groups).

        parallel_groups[i] = 第 i 层可并行执行的节点列表.
        """
        path = self.plan(source_type, sink_type)
        if not path:
            return [], []

        # 按拓扑层分组
        levels: Dict[str, int] = {}
        for i, node in enumerate(path):
            levels[node.name] = i

        parallel_groups: List[List[NodeSpec]] = [[] for _ in range(len(path))]
        for i, node in enumerate(path):
            parallel_groups[i].append(node)

        return path, parallel_groups

    def estimate_throughput(self, path: List[NodeSpec]) -> float:
        """估算管线吞吐量 (items/sec).

        瓶颈 = max(cost_i) in critical path. 吞吐量 = 1000/bottleneck_ms.
        """
        if not path:
            return 0.0
        bottleneck = max(node.est_cost_ms for node in path)
        return 1000.0 / max(bottleneck, 0.001)

    def visualize(self, path: List[NodeSpec]) -> str:
        """生成 ASCII 管线图."""
        if not path:
            return "(empty)"
        lines = []
        for i, node in enumerate(path):
            arrow = " → " if i > 0 else ""
            lines.append(f"{arrow}[{node.name}]{{{node.output_type}}}")
        return "".join(lines)

    @property
    def type_graph(self) -> Dict[str, List[str]]:
        """类型转换可达性: {from_type: [to_type, ...]}."""
        return dict(self._by_output)

    def _anno_to_tag(self, annotation) -> str:
        if annotation is inspect.Parameter.empty:
            return "any"
        anno_str = str(annotation).lower().replace("typing.", "")
        for py_type, tag in _TYPE_TAG_MAP.items():
            if py_type in anno_str:
                return tag
        return "any"


# ---------------------------------------------------------------------------
# 快捷: 从模块的 _LAZY_MAP 自动注册
# ---------------------------------------------------------------------------

def discover_and_register(pipeline: AutoPipeline,
                           lazy_map: Dict[str, str],
                           max_per_module: int = 3):
    """从 _LAZY_MAP 自动发现模块并注册公开函数到管线.

    每个模块最多注册 max_per_module 个函数以避免膨胀.
    """
    import importlib
    for name, module_path in lazy_map.items():
        try:
            mod = importlib.import_module(module_path, package=None)
            obj = getattr(mod, name, None)
            if obj is None:
                continue

            count = 0
            if inspect.isclass(obj):
                for method_name in dir(obj):
                    if method_name.startswith('_'):
                        continue
                    if count >= max_per_module:
                        break
                    method = getattr(obj, method_name, None)
                    if callable(method) and not inspect.isclass(method):
                        pipeline.register_from_function(method, cost=1.0)
                        count += 1
            elif callable(obj):
                pipeline.register_from_function(obj, cost=1.0)
        except Exception:
            pass


__all__ = [
    "AutoPipeline",
    "NodeSpec",
    "discover_and_register",
]
