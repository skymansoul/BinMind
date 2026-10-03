# Sink-to-source 反向路径分析 — 从危险调用点回溯到外部输入

"""Path Analyzer — Sink-to-source 反向可达性分析。

借鉴 Mango 的 Sink-to-Source 回溯策略：
  从每个 sink 出发，沿数据依赖边和控制流边反向追踪。
  若在限制步数内追溯到外部输入(source) → 标记为危险路径。
  若路径上遇到净化操作(sanitization) → 路径终止（去污）。
  若步数耗尽仍无法到达 source → 标记为低风险。

反向追踪的优势：
  - 只需分析潜在危险的 sink，而非所有指令
  - 遇到常量立即截断——自动过滤大量误报
  - 路径深度限制 O(depth * |edges|) 而非全程序分析

追踪终止条件：
  - 到达 source (外部输入入口) → 危险路径
  - 到达常量值 (立即数) → 安全路径
  - 到达净化操作 (sanitization) → 安全路径
  - 超出 max_depth → 截断
  - 到达函数入口 (无前驱) → 截断
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict, deque

_log = logging.getLogger(__name__)


@dataclass
class TraceEdge:
    """追踪路径上的一条边。"""
    from_line: int = 0
    to_line: int = 0
    instruction: str = ""
    reg_flow: str = ""               # 数据流动的寄存器
    edge_type: str = "data"          # data | control


@dataclass
class TaintPath:
    """从 source 到 sink 的一条污点传播路径。"""
    sink_address: int = 0
    sink_function: str = ""
    source_location: str = ""        # 外部输入来源描述
    edges: List[TraceEdge] = field(default_factory=list)
    length: int = 0
    # 路径上的净化
    sanitizations: List[str] = field(default_factory=list)
    is_dangerous: bool = False
    confidence: float = 0.0


@dataclass
class PathReport:
    """路径分析报告。"""
    function_name: str = ""
    total_sinks: int = 0
    dangerous_paths: List[TaintPath] = field(default_factory=list)
    safe_paths: int = 0              # 被净化截断的路径数
    truncated_paths: int = 0         # 超深度截断的路径数

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'total_sinks': self.total_sinks,
            'dangerous': len(self.dangerous_paths),
            'safe': self.safe_paths,
            'truncated': self.truncated_paths,
            'top_paths': [
                {'sink': p.sink_function, 'source': p.source_location,
                 'length': p.length, 'confidence': round(p.confidence, 3)}
                for p in self.dangerous_paths[:5]
            ],
        }


# Def-Use 提取

class DefUseExtractor:
    """逐指令提取 def-use 关系。"""

    def extract_all(self, asm_lines: List[str]
                    ) -> Tuple[List[Set[str]], List[Set[str]], List[bool]]:
        """返回 (defs[i], uses[i], is_call[i])。"""
        defs = []; uses = []; is_call = []
        for line in asm_lines:
            d, u, c = self._extract(line)
            defs.append(d); uses.append(u); is_call.append(c)
        return defs, uses, is_call

    def _extract(self, inst: str) -> Tuple[Set[str], Set[str], bool]:
        stripped = inst.strip().lower().replace(',', ' ')
        parts = stripped.split()
        if not parts:
            return set(), set(), False

        mnemonic = parts[0]
        is_call = mnemonic == 'call'
        d = set(); u = set()
        regs = [p.rstrip(',;') for p in parts[1:]
               if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x|[sd]i[lp]?|sp|bp)$', p)]

        if mnemonic in ('mov','lea','movzx','movsx','pop','xor','add','sub','and','or','shl','shr','mul','imul','inc','dec','neg','not'):
            if regs:
                d.add(regs[0]); u.update(regs[1:])
        elif mnemonic in ('cmp','test','push'):
            u.update(regs)
        elif mnemonic == 'call':
            d.add('rax')
        elif mnemonic == 'ret':
            u.add('rax')

        # 内存操作数
        for p in parts[1:]:
            if '[' in p:
                for m in re.finditer(r'\b(r[a-z0-9]+|e[a-z0-9]+)\b', p):
                    u.add(m.group(0))

        return d, u, is_call


# 路径回溯器

class PathBacktracer:
    """Sink → Source 反向追踪。

    从 sink 位置出发，沿 def-use 链逆向行走。
    每一步检查：谁定义了我需要的寄存器？
    若定义来自 source → 找到危险路径。
    若定义来自常量 → 路径安全终止。
    """

    # 外部输入标记
    _SOURCE_INDICATORS = {
        'read', 'recv', 'fgets', 'scanf', 'getenv', 'recvfrom',
        'fread', 'getc', 'gets', 'argv', 'argc',
    }

    # CFG边权重启发式 — 基于调用频率的加权
    # 循环内边 (向后跳转) → 高频率 → 权重 0.5 (更"热")
    # 顺序边 (fallthrough) → 中等频率 → 权重 0.7
    # 条件跳转边 → 低频率 → 权重 0.9 (障碍)
    _JMP_BACKWARD_PAT = re.compile(r'\bj\w+\s+0x[0-9a-f]+', re.I)

    def __init__(self, max_depth: int = 20):
        self._max_depth = max_depth

    def _edge_weight(self, prev_line: str, next_idx: int, prev_idx: int) -> float:
        """计算CFG边的权重 (0..1，越低越容易被追踪)。

        启发式:
          - 向后跳转 (loop backedge) → 0.5 (循环内高频率)
          - 条件跳转 not-taken (fallthrough) → 0.7
          - 条件跳转 taken → 0.9
          - 无条件跳转 → 0.6
          - 顺序执行 → 0.8
        """
        stripped = prev_line.strip().lower()
        parts = stripped.split()
        if not parts:
            return 0.8
        mnemonic = parts[0]
        if mnemonic in ('jmp', 'b', 'br'):
            return 0.6
        if mnemonic.startswith('j') or mnemonic in ('cbnz', 'cbz', 'tbnz', 'tbz'):
            # 检查跳转方向: 目标地址 < 当前地址 → 向后(循环)
            m = re.search(r'0x([0-9a-f]+)', stripped)
            if m:
                target = int(m.group(1), 16)
                if target < prev_idx * 4:
                    return 0.5  # loop backedge
            if next_idx == prev_idx + 1:
                return 0.7  # fallthrough
            return 0.9  # taken branch
        return 0.8

    def trace(self, asm_lines: List[str],
              sink_line: int,
              sink_func: str = "",
              sanitization_model=None) -> Optional[TaintPath]:
        """从 sink_line 反向追踪到 source。"""
        defs, uses, is_call = DefUseExtractor().extract_all(asm_lines)
        return self._bfs_backward(defs, uses, is_call, asm_lines,
                                  sink_line, sink_func, sanitization_model)

    def _bfs_backward(self, defs: List[Set[str]], uses: List[Set[str]],
                      is_call: List[bool], asm_lines: List[str],
                      start: int, sink_func: str,
                      sanitization_model) -> Optional[TaintPath]:

        if start >= len(uses):
            return None

        target_regs = uses[start].copy()
        if not target_regs:
            # 尝试推断: 若 sink 是 call，则查参数寄存器
            target_regs = {'rdi', 'rsi', 'rdx'}

        queue = deque([(start, target_regs, [], [])])
        visited = set()

        while queue:
            pos, regs_needed, edges, sanitizations = queue.popleft()
            state_key = (pos, frozenset(regs_needed))
            if state_key in visited:
                continue
            visited.add(state_key)

            if len(edges) >= self._max_depth:
                continue

            # 向上一行搜索定义
            for prev in range(pos - 1, -1, -1):
                defined_here = defs[prev] & regs_needed
                if not defined_here:
                    continue

                inst_text = asm_lines[prev].strip()
                edge = TraceEdge(from_line=prev, to_line=pos,
                                 instruction=inst_text,
                                 reg_flow=','.join(sorted(defined_here)))

                # 检查是否到达 source
                if is_call[prev] and self._is_source_call(inst_text):
                    path = TaintPath(
                        sink_function=sink_func,
                        source_location=self._extract_source_name(inst_text),
                        edges=list(edges) + [edge],
                        length=len(edges) + 1,
                        sanitizations=list(sanitizations),
                        is_dangerous=True,
                        confidence=0.85 if sanitizations else 0.95)
                    return path

                # 检查净化
                if sanitization_model and sanitization_model.is_sanitization(inst_text):
                    new_regs = regs_needed - defined_here
                    new_regs.update(uses[prev])
                    queue.append((prev, new_regs,
                                 list(edges) + [edge],
                                 list(sanitizations) + [inst_text[:50]]))
                    continue

                # 继续追踪：需要 prev 指令使用的寄存器
                new_regs = regs_needed - defined_here
                new_regs.update(uses[prev])

                # 若 new_regs 中包含常量定义的寄存器 → 排除（不再向上追）
                filtered = set()
                for r in new_regs:
                    # 检查 prev 行是否 mov r, imm
                    inst_lower = inst_text.lower().replace(',', ' ')
                    if re.search(r'\bmov\s+' + re.escape(r) + r',?\s*(0x[0-9a-f]+|\d+)', inst_lower):
                        continue
                    if re.search(r'\bxor\s+' + re.escape(r) + r',\s*' + re.escape(r), inst_lower):
                        continue
                    filtered.add(r)

                if filtered:
                    queue.append((prev, filtered,
                                 list(edges) + [edge], list(sanitizations)))

        return None

    def _is_source_call(self, inst: str) -> bool:
        inst_lower = inst.lower()
        return any(src in inst_lower for src in self._SOURCE_INDICATORS)

    def _extract_source_name(self, inst: str) -> str:
        m = re.search(r'\bcall\s+(\S+)', inst, re.I)
        return m.group(1).rstrip(';') if m else inst.strip()[:30]


# 路径分析器

class PathAnalyzer:
    """Sink-to-source 路径分析协调器。"""

    def __init__(self, max_depth: int = 20):
        self._tracer = PathBacktracer(max_depth)

    def analyze_function(self, asm_lines: List[str],
                         sinks: List,
                         function_name: str = "",
                         sanitization_model=None) -> PathReport:
        """分析一个函数中的所有 sink 路径。"""
        report = PathReport(function_name=function_name,
                            total_sinks=len(sinks))

        for sink in sinks:
            path = self._tracer.trace(
                asm_lines, sink.call_site_offset,
                sink.function_name, sanitization_model)

            if path:
                path.sink_address = sink.address
                if path.is_dangerous:
                    report.dangerous_paths.append(path)
                elif path.sanitizations:
                    report.safe_paths += 1
                else:
                    report.truncated_paths += 1

        return report
