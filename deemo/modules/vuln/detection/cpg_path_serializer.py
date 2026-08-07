# CPG 路径序列化器 —— 将代码属性图中的关键数据流/控制流路径压缩为紧凑文本片段,
# 作为 LLM 漏洞检测的结构上下文补充, 提升跨函数数据流理解。
#
# 对应论文: LLMxCPG 的核心洞见 —— 单纯输入源码文本时,
# LLM 对跨函数数据流的推断不可靠; 将 CPG 中的 def-use 链与条件路径序列化为
# 文本并拼接进 prompt 后, 上下文感知能力显著增强。
#
# 序列化格式约定:
#   ;CF: L4:if(a1>10) => L5:strcpy(dest,src) => L7:return a1    (控制流路径)
#   ;DF: strcpy@L5: dst <- DEF L3(char dest[8]); src <- PARAM a1   (数据流路径)
# 以分号开头便于 LLM 区分结构注释与源码行; 路径按 sink 可达性降序排列。

import logging
from collections import deque
from typing import Any, Dict, List, Optional, Sequence, Tuple

from modules.vuln.detection.cpg_builder import (
    CPGEdgeKind,
    CPGNodeKind,
    CodePropertyGraph,
    DEFAULT_SINKS,
)

logger = logging.getLogger(__name__)

# 路径枚举上限 —— 防止指数爆炸, 超过即截断
_MAX_PATHS_PER_FUNC = 24
_MAX_PATH_LEN = 8


def _node_label(cpg: CodePropertyGraph, nid: int) -> str:
    """节点标签 —— 附带行号便于 LLM 对齐源码。"""
    n = cpg.node(nid)
    if n is None:
        return "?"
    prefix = f"L{n.line_no}" if n.line_no else ""
    return f"{prefix}:{n.label}" if prefix else n.label


def extract_dataflow_paths(cpg: CodePropertyGraph, fn_id: int,
                           sinks: Sequence[str] = DEFAULT_SINKS,
                           max_paths: int = _MAX_PATHS_PER_FUNC,
                           max_len: int = _MAX_PATH_LEN) -> List[List[int]]:
    """提取到达危险 sink 的逆向数据流路径。

    算法依据:
      以每个 sink 调用点为起点, 沿 DFG 入边做贪心回溯至 def 节点 ——
      每个 def 只连最早可及 use(见 cpg_builder._finalize_dfg),
      因此按入边单向回溯即可得到 def-use 链, 无需完整 BFS。
    约束:
      每个 sink 最多回溯 max_len 步; 全函数路径总数不超过 max_paths。
    """
    sink_set = set(sinks)
    paths: List[List[int]] = []

    # 遍历函数 AST 后代, 收集 sink 调用点
    candidates: List[int] = []
    stack = [fn_id]
    seen = {fn_id}
    while stack:
        cur = stack.pop()
        n = cpg.node(cur)
        if n is not None and n.kind == CPGNodeKind.CALL and n.label in sink_set:
            candidates.append(cur)
        for e in cpg.out_edges(cur, CPGEdgeKind.AST):
            if e.dst not in seen:
                seen.add(e.dst)
                stack.append(e.dst)

    for sink in candidates:
        path: List[int] = []
        cursor = sink
        while cursor is not None and len(path) < max_len:
            path.append(cursor)
            dfg_ins = cpg.in_edges(cursor, CPGEdgeKind.DFG)
            if not dfg_ins:
                break
            cursor = dfg_ins[0].src
        path.reverse()                       # 还原为 def -> ... -> sink 顺序
        if path and path not in paths:
            paths.append(path)
        if len(paths) >= max_paths:
            break
    return paths[:max_paths]


def extract_control_paths(cpg: CodePropertyGraph, fn_id: int,
                          max_paths: int = _MAX_PATHS_PER_FUNC,
                          max_len: int = _MAX_PATH_LEN) -> List[List[int]]:
    """枚举 entry -> exit 的控制流路径(受限)。

    策略:
      启发式 CPG 中 ENTRY 不挂 CFG 出边, 真正的 CFG 链起始于函数内
      "无 CFG 入边但存在 CFG 出边" 的首语句节点; 以这些节点为根做 BFS,
      每节点最多展开 2 个后继以遏制路径爆炸(分支密集处正是边界检查所在)。
    前提:
      CFG 为有向图, 路径数最坏指数增长; 总量受 max_paths / max_len 限制。
    """
    descendants: List[int] = []
    stack = [fn_id]
    seen = {fn_id}
    while stack:
        cur = stack.pop()
        descendants.append(cur)
        for e in cpg.out_edges(cur, CPGEdgeKind.AST):
            if e.dst not in seen:
                seen.add(e.dst)
                stack.append(e.dst)

    exits = [nid for nid in descendants
             if cpg.node(nid).kind == CPGNodeKind.EXIT]

    # CFG 链头: 函数内无 CFG 入边、有 CFG 出边的节点
    heads = [nid for nid in descendants
             if not cpg.in_edges(nid, CPGEdgeKind.CFG)
             and cpg.out_edges(nid, CPGEdgeKind.CFG)]
    if not heads:
        heads = [fn_id]

    paths: List[List[int]] = []
    queue = deque((h, [h]) for h in heads[:4])     # 最多 4 个链头, 防爆炸
    while queue and len(paths) < max_paths:
        cur, trail = queue.popleft()
        succ = cpg.out_edges(cur, CPGEdgeKind.CFG)
        if cur in exits or not succ:
            if trail not in paths:
                paths.append(trail)
            continue
        for e in succ[:2]:
            if len(trail) >= max_len:
                continue
            if e.dst in trail:                     # 回路保护
                continue
            queue.append((e.dst, trail + [e.dst]))
    return paths[:max_paths]


def serialize_paths_to_text(cpg: CodePropertyGraph,
                            function_names: Optional[Sequence[str]] = None,
                            sinks: Sequence[str] = DEFAULT_SINKS,
                            max_paths: int = _MAX_PATHS_PER_FUNC) -> str:
    """将函数级 CPG 路径序列化为紧凑文本块。

    优先级: 先输出数据流路径(直指 sink 的传播链), 再输出控制流路径。
    每条路径独占一行, 以 `;CF:` / `;DF:` 前缀标记类型。
    """
    lines: List[str] = []
    fn_ids: List[int] = []
    if function_names:
        for name in function_names:
            fid = cpg.functions.get(name)
            if fid is not None:
                fn_ids.append(fid)
    else:
        fn_ids = [fid for fid in cpg.function_ids()
                  if not (cpg.node(fid).attrs.get("is_external"))]

    for fid in fn_ids:
        fnode = cpg.node(fid)
        if fnode is None:
            continue
        header = f"@func {fnode.label}"
        lines.append(header)

        df_paths = extract_dataflow_paths(cpg, fid, sinks, max_paths)
        for p in df_paths:
            seg = " <- ".join(_node_label(cpg, nid) for nid in p)
            lines.append(f";DF: {seg}")

        cf_paths = extract_control_paths(cpg, fid, max_paths)
        for p in cf_paths:
            seg = " => ".join(_node_label(cpg, nid) for nid in p)
            lines.append(f";CF: {seg}")

    return "\n".join(lines)


def serialize_dataflow_to_sink(cpg: CodePropertyGraph, fn_id: int,
                               sink_name: str,
                               max_len: int = _MAX_PATH_LEN) -> List[str]:
    """针对单个 sink 的路径文本 —— 供多特征融合的结构特征与证据链使用。"""
    results: List[str] = []
    stack = [fn_id]
    seen = {fn_id}
    while stack:
        cur = stack.pop()
        n = cpg.node(cur)
        if n is not None and n.kind == CPGNodeKind.CALL and n.label == sink_name:
            chain: List[int] = []
            cursor = cur
            for _ in range(max_len):
                dfg_ins = cpg.in_edges(cursor, CPGEdgeKind.DFG)
                if not dfg_ins:
                    break
                cursor = dfg_ins[0].src
                chain.append(cursor)
            chain.reverse()
            chain.append(cur)
            results.append(" <- ".join(_node_label(cpg, nid) for nid in chain))
        for e in cpg.out_edges(cur, CPGEdgeKind.AST):
            if e.dst not in seen:
                seen.add(e.dst)
                stack.append(e.dst)
    return results


def build_cpg_context(cpg: CodePropertyGraph,
                      source_text: str = "",
                      function_names: Optional[Sequence[str]] = None,
                      sinks: Sequence[str] = DEFAULT_SINKS,
                      max_paths: int = _MAX_PATHS_PER_FUNC,
                      max_chars: int = 2000) -> str:
    """构建 LLM prompt 的 CPG 上下文块 —— 源码 + 序列化路径。

    设计意图:
      将路径文本作为 `结构线索` 附在源码之后, 不替换源码本身;
      max_chars 约束防止超长上下文挤占 LLM 输入窗口(反编译函数可达数百行)。
    """
    parts: List[str] = []
    stats = cpg.stats()
    parts.append(f"// CPG stats: nodes={stats['nodes']} edges={stats['edges']} "
                 f"funcs={stats['functions']} sinks={stats['sink_count']}")

    if source_text:
        parts.append("// ---- source ----")
        parts.append(source_text.strip())

    paths_text = serialize_paths_to_text(cpg, function_names, sinks, max_paths)
    if paths_text:
        parts.append("// ---- CPG data/control-flow paths ----")
        parts.append(paths_text)

    joined = "\n".join(parts)
    if len(joined) > max_chars:
        # 优先保留路径段, 源码段可被截断 —— 路径段承载结构信息
        marker = "// ---- CPG data/control-flow paths ----"
        idx = joined.find(marker)
        if idx != -1 and len(joined) - idx <= max_chars:
            joined = joined[idx:]
        joined = joined[-max_chars:]
    return joined


def rank_paths_by_severity(cpg: CodePropertyGraph, paths: List[List[int]]) -> List[float]:
    """路径严重度排序分 —— 0..1, 供融合层与鲁棒性评估使用。

    评分规则:
      经过危险 sink 调用节点 +0.5; 路径长度(跨函数传播链长度)+0.1/步;
      路径中含分支(条件边界)+0.2 —— 分支薄弱点更可能被利用。
    """
    scores: List[float] = []
    sink_labels = set(DEFAULT_SINKS)
    for path in paths:
        score = 0.0
        has_branch = False
        for nid in path:
            n = cpg.node(nid)
            if n is None:
                continue
            if n.kind == CPGNodeKind.CALL and n.label in sink_labels:
                score += 0.5
            elif n.kind == CPGNodeKind.BRANCH:
                has_branch = True
        if has_branch:
            score += 0.2
        score += min(len(path), 5) * 0.1
        scores.append(min(1.0, score))
    return scores
