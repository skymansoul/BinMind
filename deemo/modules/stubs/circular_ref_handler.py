# circular_ref_handler.py — 循环引用检测与解除
# 桩模块可能通过不同路径指向同一 compat 模块，导致 import 链循环依赖。
# 参考: ADFEmu (2025) LLM-DSE 协同框架中的依赖图分析 &
#   Call Graphlets (arXiv:2406.02606) 的图结构分析。
from collections import defaultdict as _defdict
import sys as _sys

def build_import_graph(root_pkg: str = 'modules.stubs') -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    prefix = root_pkg + '.'
    for mod_name, mod in _sys.modules.items():
        if not (mod_name.startswith(prefix) or mod_name == root_pkg):
            continue
        graph.setdefault(mod_name, set())
        spec = getattr(mod, '__spec__', None)
        if spec is None:
            continue
        # 从模块全局变量中推断显式 import 目标
        for v in vars(mod).values():
            if hasattr(v, '__module__'):
                target = v.__module__
                if target and (target.startswith(prefix) or target == root_pkg):
                    graph[mod_name].add(target)
    return graph


def find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan SCC — 仅返回 |scc| > 1 的强连通分量。O(|V| + |E|)。"""
    idx_cnt = 0
    stack: list[str] = []
    on_stk: set[str] = set()
    indices: dict[str, int] = {}
    low: dict[str, int] = {}
    sccs: list[list[str]] = []

    def _connect(v: str):
        nonlocal idx_cnt
        indices[v] = idx_cnt
        low[v] = idx_cnt
        idx_cnt += 1
        stack.append(v); on_stk.add(v)

        for w in graph.get(v, set()):
            if w not in indices:
                _connect(w)
                low[v] = min(low[v], low[w])
            elif w in on_stk:
                low[v] = min(low[v], indices[w])

        if low[v] == indices[v]:
            comp = []
            while True:
                w = stack.pop(); on_stk.discard(w)
                comp.append(w)
                if w == v: break
            if len(comp) > 1:
                sccs.append(comp)

    for node in graph:
        if node not in indices:
            _connect(node)
    return sccs


def detect_and_report(root_pkg: str = 'modules.stubs') -> list[dict]:
    g = build_import_graph(root_pkg)
    cycles = find_cycles(g)
    out = []
    for cyc in cycles:
        if len(cyc) <= 3:
            hint = '合并为单模块或提取共享接口'
        else:
            hint = '重构为分层结构，用接口抽象打破循环'
        out.append({'cycle': cyc, 'size': len(cyc), 'recommendation': hint})
    return out
