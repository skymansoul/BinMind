# 代码属性图（Code Property Graph）构造器 - 从源码/反编译伪代码提取
# AST / 控制流(CFG) / 数据流(DFG) / 调用图(CallGraph) 并统一为一张属性图。
#
# 对应论文: LLMxCPG 将 CPG 作为 LLM 漏洞检测的结构上下文,
# CodeSAGE 以 CPG 作为多特征融合的图输入。
# 本模块不依赖 tree-sitter / libclang - 对反编译伪代码(IDA/Ghidra 风格 C)与
# Python 源码采用轻量启发式解析, 精度足以支撑下游的路径序列化与结构特征打分。
#
# 边界条件:
# 反编译伪代码可能缺少类型信息, 变量提取退化为标识符级 def/use 统计。
# 控制流仅按文本顺序与括号嵌套近似, 不保证与真实执行路径一致。
#   - 跨函数调用仅在同一源码片段内解析, 未命中函数名的调用保留为孤立 callee 节点。

import json
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class CPGNodeKind(str, Enum):
    """CPG 节点类型 - 覆盖四种图的节点集合。"""
    FUNCTION = "function"        # 函数
    PARAM = "param"              # 形参
    STMT = "stmt"                # 语句
    ASSIGN = "assign"            # 赋值
    CALL = "call"                # 调用点
    BRANCH = "branch"            # 分支/循环条件
    VAR = "var"                  # 变量标识符
    CONST = "const"              # 常量
    CONTROL = "control"          # return/break/goto 等跳转语句
    ENTRY = "entry"              # 函数入口
    EXIT = "exit"                # 函数出口


class CPGEdgeKind(str, Enum):
    """CPG 边类型 - AST / CFG / DFG / CallGraph 四类边。"""
    AST = "ast"                  # 语法树父到子
    CFG = "cfg"                  # 控制流前驱到后继
    DFG = "dfg"                  # 数据依赖 def到use
    CALL = "call"                # 调用者到被调用者


# 常见危险 sink 关键字 - 用于下游的路径优先级排序与结构风险打分
DEFAULT_SINKS: Tuple[str, ...] = (
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy", "strncpy",
    "snprintf", "scanf", "system", "popen", "execve", "free", "malloc",
    "realloc", "alloca", "read", "recv", "send", "printf",
)


@dataclass
class CPGNode:
    """CPG 节点。"""
    id: int
    kind: CPGNodeKind
    label: str                            # 代码文本/标识符
    line_no: int = 0                      # 源行号
    attrs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CPGEdge:
    """CPG 有向边。"""
    src: int
    dst: int
    kind: CPGEdgeKind
    attrs: Dict[str, Any] = field(default_factory=dict)


class CodePropertyGraph:
    """统一代码属性图。

    设计意图:
      以节点 id 为键的邻接表存储四类边, 支持 O(1) 邻居查询;
      `functions` 维护 函数名 -> 函数节点 id, 用于按函数裁剪。
      裁剪语义为 AST 后代闭包上的导出子图 - 保留函数内部完整结构,
      跨函数边是否保留由 `cross_function` 参数控制。
    """

    def __init__(self, source_name: str = ""):
        self.source_name = source_name
        self._nodes: Dict[int, CPGNode] = {}
        self._edges: List[CPGEdge] = []
        self._adj_out: Dict[int, List[CPGEdge]] = defaultdict(list)
        self._adj_in: Dict[int, List[CPGEdge]] = defaultdict(list)
        self.functions: Dict[str, int] = {}       # 函数名 -> 函数节点 id
        self._next_id: int = 0
        self._def_uses: Dict[str, Tuple[List[int], List[int]]] = defaultdict(
            lambda: ([], []))
        self._order: Dict[int, int] = {}          # 节点文本出现顺序, 供 DFG 排序

# 图构造

    def add_node(self, kind: CPGNodeKind, label: str, line_no: int = 0,
                 **attrs) -> int:
        nid = self._next_id
        self._next_id += 1
        self._nodes[nid] = CPGNode(nid, kind, label, line_no, dict(attrs))
        self._order[nid] = len(self._order)
        return nid

    def add_edge(self, src: int, dst: int, kind: CPGEdgeKind, **attrs) -> None:
        edge = CPGEdge(src, dst, kind, dict(attrs))
        self._edges.append(edge)
        self._adj_out[src].append(edge)
        self._adj_in[dst].append(edge)

    def node(self, nid: int) -> Optional[CPGNode]:
        return self._nodes.get(nid)

    def out_edges(self, nid: int, kind: Optional[CPGEdgeKind] = None) -> List[CPGEdge]:
        if kind is None:
            return self._adj_out.get(nid, [])
        return [e for e in self._adj_out.get(nid, []) if e.kind == kind]

    def in_edges(self, nid: int, kind: Optional[CPGEdgeKind] = None) -> List[CPGEdge]:
        if kind is None:
            return self._adj_in.get(nid, [])
        return [e for e in self._adj_in.get(nid, []) if e.kind == kind]

# 基于文本的启发式构建

    @classmethod
    def from_source(cls, source: str, source_name: str = "") -> "CodePropertyGraph":
        """从源码/伪代码文本构建 CPG。"""
        cpg = cls(source_name)
        if not source:
            return cpg
        lines = source.splitlines()
        func_starts = cls._scan_functions(lines)   # 行号到函数名

        current_func: Optional[int] = None
        block_stack: List[int] = []          # AST 父节点栈(函数/分支/控制块)
        prev_stmt: Optional[int] = None      # 当前控制块内上一条语句, 用于 CFG
        pending_func_sig: Optional[int] = None
        brace_depth = 0

        for idx, raw in enumerate(lines):
            line_no = idx + 1
            stripped = raw.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue
            if stripped.startswith("/*"):
                continue
            if stripped == "{":              # 单独成行的块起始
                brace_depth += 1
                continue

# 函数签名识别(预扫描结果)
            if idx in func_starts:
                fname = func_starts[idx]
                fn_id = cpg.add_node(CPGNodeKind.FUNCTION, fname, line_no)
                entry_id = cpg.add_node(CPGNodeKind.ENTRY, f"entry:{fname}", line_no)
                cpg.add_edge(fn_id, entry_id, CPGEdgeKind.AST)
                current_func = fn_id
                cpg.functions[fname] = fn_id
                block_stack = [fn_id]
                prev_stmt = None
                pending_func_sig = fn_id
                continue

# 分支/循环
            mcond = cls._try_condition(stripped)
            if mcond is not None and current_func is not None:
                br_id = cpg.add_node(CPGNodeKind.BRANCH, mcond, line_no)
                cpg.add_edge(block_stack[-1], br_id, CPGEdgeKind.AST)
                for v in cls._identifiers(mcond):
                    cpg._record_use(v, br_id, line_no)
                if prev_stmt is not None:
                    cpg.add_edge(prev_stmt, br_id, CPGEdgeKind.CFG)
                block_stack.append(br_id)
                prev_stmt = br_id
                continue

# return / break / goto
            if stripped.startswith(("return", "break", "goto", "continue")):
                cid = cpg.add_node(CPGNodeKind.CONTROL, stripped.rstrip(";"), line_no)
                parent = block_stack[-1] if block_stack else current_func
                if parent is not None:
                    cpg.add_edge(parent, cid, CPGEdgeKind.AST)
                if prev_stmt is not None and parent is not None:
                    cpg.add_edge(prev_stmt, cid, CPGEdgeKind.CFG)
                for v in cls._identifiers(stripped):
                    cpg._record_use(v, cid, line_no)
                prev_stmt = cid
                continue

# 闭合块
            if stripped == "}":
                # 仅当回退到最外层(函数体)时才闭合函数 - 内层块 `}` 不触发
                if pending_func_sig is not None and len(block_stack) == 1:
                    exit_id = cpg.add_node(CPGNodeKind.EXIT,
                                           f"exit:{cpg.node(current_func).label}",
                                           line_no)
                    cpg.add_edge(block_stack[0], exit_id, CPGEdgeKind.AST)
                    if prev_stmt is not None:
                        cpg.add_edge(prev_stmt, exit_id, CPGEdgeKind.CFG)
                    pending_func_sig = None
                if block_stack:
                    block_stack.pop()
                brace_depth = max(0, brace_depth - 1)
                continue
            if stripped.startswith("}") and len(stripped) > 1:
                if block_stack:
                    block_stack.pop()
                rest = stripped[1:].strip()
                if rest:
                    prev_stmt = cpg._handle_statement(
                        current_func, block_stack, prev_stmt, rest, line_no)
                continue

# 普通语句(赋值/调用/声明)
            if current_func is not None:
                stmt_id = cpg._handle_statement(
                    current_func, block_stack, prev_stmt, stripped, line_no)
                prev_stmt = stmt_id
            else:
                # 顶层(函数外)语句, 归为 STMT
                sid = cpg.add_node(CPGNodeKind.STMT, stripped, line_no)
                prev_stmt = sid

# 数据流边: def 到 use (按文本顺序约束)
        cpg._finalize_dfg()
        return cpg

# 语句解析

    def _handle_statement(self, func_id: Optional[int], block_stack: List[int],
                          prev_stmt: Optional[int], text: str, line_no: int) -> Optional[int]:
        """解析单条语句, 产出语句节点并接线 AST/CFG/调用边。"""
        parent = block_stack[-1] if block_stack else func_id
        if parent is None:
            return None

        # 赋值形: `lhs = rhs` 或 `type lhs = rhs` - lhs 为定义, rhs 标识符为使用
        massign = re.match(r'^\s*(?:[A-Za-z_]\w*\s+[*&]?\s*)?([A-Za-z_]\w*)\s*=\s*(.+?)\s*;?\s*$', text)
        if massign:
            var_name, rhs = massign.group(1), massign.group(2)
            sid = self.add_node(CPGNodeKind.ASSIGN, text, line_no)
            self.add_edge(parent, sid, CPGEdgeKind.AST)
            vnode = self.add_node(CPGNodeKind.VAR, var_name, line_no)
            self.add_edge(sid, vnode, CPGEdgeKind.AST)
            self._record_def(var_name, sid, line_no)
            # 右侧调用
            call_name = self._try_call_name(rhs)
            if call_name is not None:
                cid = self.add_node(CPGNodeKind.CALL, call_name, line_no)
                self.add_edge(sid, cid, CPGEdgeKind.AST)
                self._record_call(func_id, call_name, cid)
            for v in self._identifiers(rhs):
                self._record_use(v, sid, line_no)
                unode = self.add_node(CPGNodeKind.VAR, v, line_no)
                self.add_edge(sid, unode, CPGEdgeKind.AST)
            if prev_stmt is not None:
                self.add_edge(prev_stmt, sid, CPGEdgeKind.CFG)
            return sid

        # 调用形: `name(args);`
        call_name = self._try_call_name(text)
        if call_name is not None:
            cid = self.add_node(CPGNodeKind.CALL, call_name, line_no)
            self.add_edge(parent, cid, CPGEdgeKind.AST)
            self._record_call(func_id, call_name, cid)
            for v in self._identifiers(text):
                self._record_use(v, cid, line_no)
                unode = self.add_node(CPGNodeKind.VAR, v, line_no)
                self.add_edge(cid, unode, CPGEdgeKind.AST)
            if prev_stmt is not None:
                self.add_edge(prev_stmt, cid, CPGEdgeKind.CFG)
            return cid

        # 声明形: `type var;` / `type var = ...;`
        mdecl = re.match(r'^\s*([A-Za-z_]\w*(?:\s+[*&])?\s*)([A-Za-z_]\w*)\s*(\[\s*\w*\s*\])?\s*;?\s*$', text)
        if mdecl:
            var_name = mdecl.group(2)
            sid = self.add_node(CPGNodeKind.STMT, text, line_no)
            self.add_edge(parent, sid, CPGEdgeKind.AST)
            vnode = self.add_node(CPGNodeKind.VAR, var_name, line_no)
            self.add_edge(sid, vnode, CPGEdgeKind.AST)
            self._record_def(var_name, sid, line_no)
            if prev_stmt is not None:
                self.add_edge(prev_stmt, sid, CPGEdgeKind.CFG)
            return sid

        # 其余: 通用语句节点
        sid = self.add_node(CPGNodeKind.STMT, text, line_no)
        self.add_edge(parent, sid, CPGEdgeKind.AST)
        for v in self._identifiers(text):
            self._record_use(v, sid, line_no)
        if prev_stmt is not None:
            self.add_edge(prev_stmt, sid, CPGEdgeKind.CFG)
        return sid

# 静态辅助

    @staticmethod
    def _match_function_signature(text: str) -> Optional[Tuple[str, str]]:
        """匹配单行函数签名, 返回 (函数名, 行尾) 或 None。

        覆盖 C 风格 `ret __fastcall name(args) {` 与 Python `def name(args):`。
        关键判别:
          - 形参列表内不允许出现分号 - 反编译调用语句参数几乎不含分号。
          - 函数名不得为控制流关键字 - `if (...)` / `while (...)` 形如调用,
            需排除, 否则与分支识别冲突。
        """
        m = re.match(
            r'^(?:def\s+)?(?:[A-Za-z_]\w*\s+)?(?:__\w+\s+)*([A-Za-z_]\w*)'
            r'\s*\(([^)]*)\)\s*(\{|:)?\s*$', text)
        if not m:
            return None
        args, brace = m.group(2), m.group(3)
        if ";" in args:
            return None
        name = m.group(1)
        if name in ("if", "while", "for", "switch", "catch", "sizeof"):
            return None
        return name, brace or ""

    @staticmethod
    def _scan_functions(lines: List[str]) -> Dict[int, str]:
        """预扫描函数签名 - 带前向窥探处理 `{` 单独成行的 C 风格写法。

        算法依据:
          IDA/Ghidra 反编译伪代码通常将 `{` 置于签名下一行, 单行正则
          无法判定; 预扫描允许 O(n) 前瞻, 兼顾 Python `def ...:` 风格。
        约束:
          函数体 `{` 与签名分离时, 要求签名行下一非空行恰为 `{`。
        """
        result: Dict[int, str] = {}
        for i, raw in enumerate(lines):
            stripped = raw.strip()
            if not stripped:
                continue
            hit = CodePropertyGraph._match_function_signature(stripped)
            if hit is None:
                continue
            fname, brace = hit
            if brace in ("{", ":"):
                result[i] = fname
                continue
            # 窥探下一非空行
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and lines[j].strip() == "{":
                result[i] = fname
        return result

    @staticmethod
    def _try_condition(text: str) -> Optional[str]:
        """识别 if/while/for/switch 条件, 返回条件表达式或 None。"""
        m = re.match(r'^\s*(if|while|for|switch)\s*\((.*)\)\s*\{?\s*$', text)
        if not m:
            m = re.match(r'^\s*(if|while|for)\s+(.+?)\s*:\s*$', text)  # Python 风格
        return m.group(0) if m else None

    @staticmethod
    def _try_call_name(text: str) -> Optional[str]:
        """识别调用 `name(...)`, 返回被调函数名。"""
        m = re.match(r'^\s*([A-Za-z_]\w*)\s*\(', text)
        return m.group(1) if m else None

    @staticmethod
    def _identifiers(text: str) -> List[str]:
        """提取文本中的标识符(排除关键字)。"""
        _KW = {"if", "else", "while", "for", "return", "break", "continue",
               "goto", "switch", "case", "default", "int", "char", "void",
               "unsigned", "signed", "long", "short", "float", "double",
               "static", "const", "struct", "sizeof", "NULL", "true", "false"}
        return [w for w in re.findall(r'[A-Za-z_]\w*', text) if w not in _KW]

    def _record_def(self, var: str, node_id: int, line_no: int) -> None:
        defs, _uses = self._def_uses[var]
        defs.append(node_id)
        self._order.setdefault(node_id, line_no)

    def _record_use(self, var: str, node_id: int, line_no: int) -> None:
        _defs, uses = self._def_uses[var]
        uses.append(node_id)
        self._order.setdefault(node_id, line_no)

    def _record_call(self, caller: Optional[int], callee: str, call_node: int) -> None:
        """记录调用边: 已知函数, 直接连; 未知函数, 建立孤立 callee 桩节点。"""
        callee_id = self.functions.get(callee)
        if callee_id is None:
            callee_id = self.add_node(CPGNodeKind.FUNCTION, callee, 0,
                                      is_external=True)
            self.functions[callee] = callee_id
        if caller is not None:
            self.add_edge(caller, callee_id, CPGEdgeKind.CALL, call_site=call_node)

    def _finalize_dfg(self) -> None:
        """为每个变量按 文本顺序(def 早于 use) 构造 DFG 边。"""
        for var, (defs, uses) in self._def_uses.items():
            defs_sorted = sorted(defs, key=lambda n: self._order.get(n, 0))
            uses_sorted = sorted(uses, key=lambda n: self._order.get(n, 0))
            for d in defs_sorted:
                for u in uses_sorted:
                    if self._order.get(u, 0) > self._order.get(d, 0) and d != u:
                        self.add_edge(d, u, CPGEdgeKind.DFG, var=var)
                        break      # 保守: 每 def 只连最早可及 use

# 查询与裁剪

    def function_ids(self) -> List[int]:
        return list(self.functions.values())

    def _ast_descendants(self, root: int) -> Set[int]:
        """AST 后代闭包 - 含自身。"""
        seen: Set[int] = set()
        stack = [root]
        while stack:
            nid = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            stack.extend(e.dst for e in self.out_edges(nid, CPGEdgeKind.AST))
        return seen

    def clip_to_function(self, name: str, cross_function: bool = True) -> "CodePropertyGraph":
        """按函数裁剪为子图。

        cross_function=True 时保留调用边与被调用函数桩, 用于跨函数数据流分析;
        为 False 时仅保留函数内部节点与其 AST/CFG/DFG 边。
        """
        fn_id = self.functions.get(name)
        if fn_id is None:
            raise KeyError(f"CPG 中不存在函数: {name}")
        return self._clip_to_ids(self._ast_descendants(fn_id), cross_function)

    def clip_to_functions(self, names: List[str],
                          cross_function: bool = True) -> "CodePropertyGraph":
        """跨函数裁剪 - 合并多个函数子图, 保留它们之间的调用/数据流关系。"""
        keep: Set[int] = set()
        for name in names:
            fn_id = self.functions.get(name)
            if fn_id is not None:
                keep |= self._ast_descendants(fn_id)
        return self._clip_to_ids(keep, cross_function)

    def _clip_to_ids(self, keep: Set[int], cross_function: bool) -> "CodePropertyGraph":
        sub = CodePropertyGraph(self.source_name)
        for nid in sorted(keep):
            n = self._nodes[nid]
            sub._nodes[nid] = CPGNode(nid, n.kind, n.label, n.line_no, dict(n.attrs))
            sub._order[nid] = self._order.get(nid, 0)
        for name, fid in self.functions.items():
            if fid in keep or (cross_function and any(
                    self._nodes.get(e.src).kind == CPGNodeKind.FUNCTION
                    and e.src in keep for e in self._adj_in.get(fid, []))):
                sub.functions[name] = fid
        sub._next_id = self._next_id
        for e in self._edges:
            if e.src in keep and e.dst in keep:
                sub._edges.append(CPGEdge(e.src, e.dst, e.kind, dict(e.attrs)))
                sub._adj_out[e.src].append(e)
                sub._adj_in[e.dst].append(e)
            elif cross_function and e.kind == CPGEdgeKind.CALL:
                caller_in, callee_ext = e.src in keep, self._nodes.get(e.dst, None)
                if caller_in and callee_ext is not None and e.dst not in keep:
                    sub._nodes.setdefault(e.dst, CPGNode(e.dst, callee_ext.kind,
                                                        callee_ext.label, 0, dict(callee_ext.attrs)))
                    sub._edges.append(CPGEdge(e.src, e.dst, e.kind, dict(e.attrs)))
                    sub._adj_out[e.src].append(e)
                    sub._adj_in[e.dst].append(e)
                    if e.dst not in sub.functions:
                        sub.functions[callee_ext.label] = e.dst
        return sub

    def cyclomatic_complexity(self, fn_id: int) -> int:
        """圈复杂度近似 - M = 分支节点数 + 1 (单入口单出口假设)。"""
        descendants = self._ast_descendants(fn_id)
        branches = sum(1 for nid in descendants
                       if self._nodes[nid].kind == CPGNodeKind.BRANCH)
        returns = sum(1 for nid in descendants
                      if self._nodes[nid].kind == CPGNodeKind.CONTROL
                      and str(self._nodes[nid].label).startswith("return"))
        return max(1, branches + 1)

    def reachable_sinks(self, fn_id: int, sinks: Tuple[str, ...] = DEFAULT_SINKS) -> List[Tuple[str, int]]:
        """函数内经 CFG/DFG 可达的 sink 列表 - (sink名, 最近的调用节点id)。"""
        sink_set = set(sinks)
        result: List[Tuple[str, int]] = []
        for nid in self._ast_descendants(fn_id):
            n = self._nodes[nid]
            if n.kind == CPGNodeKind.CALL and n.label in sink_set:
                result.append((n.label, nid))
        return result

    def to_json(self) -> str:
        data = {
            "source_name": self.source_name,
            "functions": self.functions,
            "nodes": [{"id": n.id, "kind": n.kind.value, "label": n.label,
                       "line_no": n.line_no, "attrs": n.attrs}
                      for n in self._nodes.values()],
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind.value,
                       "attrs": e.attrs} for e in self._edges],
        }
        return json.dumps(data, ensure_ascii=False)

    def stats(self) -> Dict[str, Any]:
        """CPG 规模统计 - 供多特征融合的结构特征使用。"""
        kinds = defaultdict(int)
        for n in self._nodes.values():
            kinds[n.kind.value] += 1
        edge_kinds = defaultdict(int)
        for e in self._edges:
            edge_kinds[e.kind.value] += 1
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "functions": len(self.functions),
            "node_kinds": dict(kinds),
            "edge_kinds": dict(edge_kinds),
            "sink_count": sum(1 for n in self._nodes.values()
                              if n.kind == CPGNodeKind.CALL and n.label in DEFAULT_SINKS),
        }


def build_cpg(source: str, source_name: str = "") -> CodePropertyGraph:
    """便捷函数 - 从源码构建 CPG。"""
    return CodePropertyGraph.from_source(source, source_name)


def build_function_cpg(source: str, function_name: str,
                       cross_function: bool = True) -> CodePropertyGraph:
    """便捷函数 - 构建单函数级 CPG 子图。"""
    cpg = CodePropertyGraph.from_source(source)
    return cpg.clip_to_function(function_name, cross_function=cross_function)
