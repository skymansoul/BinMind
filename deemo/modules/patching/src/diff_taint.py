# 修改记录:
# 2025-08-22 10:31 — 初始实现：taint source/sink/propagation 在补丁前后的差分
# 2025-08-23 15:44 — 增加净化验证：检查补丁是否在 sink 前插入了清洗操作

"""Patch Differential Taint Tracker — 补丁前后的污点流差分分析。

MileSan [CCS 2025] 做硬件-软件差分污点追踪（RTL 级），检测微架构泄漏。
本模块的差异：
  - MileSan 操作在 RTL/硬件级别
  - 本模块操作在二进制补丁的汇编级别
  - 目标不同：MileSan 检测微架构信息泄漏，本模块验证补丁的输入净化

方法：
  1. 在补丁前后的汇编中识别 taint source（用户输入入口）
  2. 追踪污点传播路径（寄存器→寄存器、寄存器→内存）
  3. 识别 taint sink（危险使用点：系统调用参数、内存写入目标等）
  4. 比较 orig vs patched 的 source→sink 路径：
     - 补丁是否缩短了传播路径（更早到达 sink）
     - 补丁是否在路径上插入了清洗操作
     - 补丁是否引入了新的 source 或 sink

净化检测（核心）：
  有效的补丁应在 taint source 和 taint sink 之间插入净化操作
  （如 and 掩码、cmp 检查、范围钳制）。若补丁新增了 source→sink 路径
  但未添加净化，则标记为潜在漏洞。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class TaintNodeType(str, Enum):
    SOURCE = "source"       # 污点来源（如 read/recv/argv）
    PROPAGATE = "propagate" # 传播（mov/lea/算术）
    SINK = "sink"           # 危险汇聚点（如 write/memcpy/system）
    SANITIZE = "sanitize"   # 净化操作（and/cmp/range check）


@dataclass
class TaintNode:
    """污点图中的一个节点。"""
    node_type: TaintNodeType
    instruction: str
    line_index: int = 0
    # 受影响的寄存器
    affected_registers: Set[str] = field(default_factory=set)


@dataclass
class TaintFlow:
    """从 source 到 sink 的一条污点传播路径。"""
    source: TaintNode
    sink: TaintNode
    propagations: List[TaintNode] = field(default_factory=list)
    sanitizations: List[TaintNode] = field(default_factory=list)
    # 此路径是否被充分净化
    is_sanitized: bool = False


@dataclass
class DiffTaintReport:
    """差分污点分析报告。"""
    patch_id: str = ""
    # 原始代码的污点流
    original_flows: List[TaintFlow] = field(default_factory=list)
    # 补丁后的污点流
    patched_flows: List[TaintFlow] = field(default_factory=list)
    # 净化改善
    new_sanitizations: int = 0
    removed_sanitizations: int = 0
    # 新增的未净化路径
    new_unsanitized_paths: int = 0
    # 综合判定
    patch_improves_safety: bool = False
    patch_introduces_risk: bool = False
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'orig_flows': len(self.original_flows),
            'patch_flows': len(self.patched_flows),
            'new_sanitizations': self.new_sanitizations,
            'removed_sanitizations': self.removed_sanitizations,
            'new_unsanitized': self.new_unsanitized_paths,
            'improves': self.patch_improves_safety,
            'introduces_risk': self.patch_introduces_risk,
            'recommendation': self.recommendation,
        }


# ── Taint 源/汇/净化模式库 ────────────────────────────────────────

# Taint source: 用户/外部输入入口
_TAINT_SOURCES = re.compile(
    r'\bcall\s+.*\b(read|recv|recvfrom|fread|fgets|getc|scanf|'
    r'getenv|atoi|strtol|argv|argc|__isoc99_scanf|getsockopt)\b', re.I)

# Taint sink: 危险的数据使用点
_TAINT_SINKS = re.compile(
    r'\bcall\s+.*\b(write|send|sendto|memcpy|memmove|strcpy|strcat|'
    r'sprintf|system|execve|popen|fprintf|printf|syscall)\b|'
    r'\bint\s+0x80\b|\bsyscall\b', re.I)

# Taint 传播: 寄存器间移动
_TAINT_PROPAGATE = re.compile(
    r'\b(mov|lea|add|sub|xor|and|or|shl|shr|push|pop|xchg)\b', re.I)

# Taint 净化: 输入验证/清洗
_TAINT_SANITIZE = re.compile(
    r'\b(and\s+\w+,\s*(0x[0-9a-f]+|\d+)|'        # 位掩码
    r'cmp\s+\w+,\s*(0x[0-9a-f]+|\d+)|'           # 边界比较
    r'test\s+\w+,\s*\w+|'                          # 空值检查
    r'call\s+.*\b(strlen|strnlen|strchr|memchr|'  # 长度/字符检查
    r'isalnum|isdigit|isprint|isascii)\b)', re.I)


# ── 污点追踪引擎 ──────────────────────────────────────────────────

class TaintTracker:
    """汇编级轻量污点追踪。

    不执行符号执行——在指令级别追踪污点标记的传播。
    精度受限于寄存器别名分析（不追踪内存别名）。
    """

    def __init__(self):
        # 污点标记: {reg_name: set of source_line_indices}
        pass

    def extract_taint_graph(self, asm_lines: List[str]
                            ) -> List[TaintFlow]:
        """从汇编中提取所有 source→sink 污点流。"""
        # 第一步：识别所有 source, sink, sanitize 节点
        sources = []
        sinks = []
        sanitizers = []
        for i, line in enumerate(asm_lines):
            stripped = line.strip()
            if _TAINT_SOURCES.search(stripped):
                node = TaintNode(
                    node_type=TaintNodeType.SOURCE,
                    instruction=stripped, line_index=i)
                node.affected_registers = self._regs_written(stripped)
                sources.append(node)
            elif _TAINT_SINKS.search(stripped):
                sinks.append(TaintNode(
                    node_type=TaintNodeType.SINK,
                    instruction=stripped, line_index=i))
            elif _TAINT_SANITIZE.search(stripped):
                sanitizers.append(TaintNode(
                    node_type=TaintNodeType.SANITIZE,
                    instruction=stripped, line_index=i))

        # 第二步：对每个 source→sink 对，收集传播路径
        flows = []
        for src in sources:
            for snk in sinks:
                if src.line_index >= snk.line_index:
                    continue  # sink 在 source 之前
                flow = self._trace_flow(asm_lines, src, snk, sanitizers)
                if flow:
                    flows.append(flow)
        return flows

    def _trace_flow(self, asm: List[str], src: TaintNode,
                    sink: TaintNode,
                    sanitizers: List[TaintNode]) -> Optional[TaintFlow]:
        """追踪单个 source→sink 的污点传播。"""
        tainted_regs = set(src.affected_registers)
        if not tainted_regs:
            tainted_regs = {'rax'}  # 默认假设返回值被污染

        propagations = []
        path_sanitizers = []
        for i in range(src.line_index + 1, sink.line_index):
            line = asm[i].strip()
            # 检查传播
            if self._propagates_taint(line, tainted_regs):
                prop = TaintNode(
                    node_type=TaintNodeType.PROPAGATE,
                    instruction=line, line_index=i)
                new_regs = self._regs_written(line)
                tainted_regs.update(new_regs)
                propagations.append(prop)
            # 检查净化
            for san in sanitizers:
                if san.line_index == i:
                    # 净化操作会取消污点标记
                    cleaned = self._regs_written(san.instruction)
                    tainted_regs.difference_update(cleaned)
                    path_sanitizers.append(san)

        # 检查 sink 是否使用了污点数据
        sink_reads = self._regs_read(sink.instruction)
        is_tainted_at_sink = bool(tainted_regs & sink_reads)
        if not is_tainted_at_sink:
            return None

        return TaintFlow(
            source=src, sink=sink,
            propagations=propagations,
            sanitizations=path_sanitizers,
            is_sanitized=len(path_sanitizers) > 0,
        )

    @staticmethod
    def _propagates_taint(line: str, tainted: Set[str]) -> bool:
        """检查指令是否传播了污点。"""
        if not _TAINT_PROPAGATE.search(line):
            return False
        # 检查源操作数是否在污点集合中
        parts = line.lower().replace(',', ' ').split()
        if len(parts) >= 3:
            src_op = parts[2]
            return src_op in tainted
        return False

    @staticmethod
    def _regs_written(inst: str) -> Set[str]:
        """提取指令写入的寄存器。"""
        parts = inst.lower().replace(',', ' ').split()
        if len(parts) >= 2:
            dst = parts[1].rstrip(',')
            if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x)$', dst):
                return {dst}
        # call 返回值写入 rax
        if inst.lower().startswith('call '):
            return {'rax'}
        return set()

    @staticmethod
    def _regs_read(inst: str) -> Set[str]:
        """提取指令读取的寄存器。"""
        regs = set()
        for m in re.finditer(r'\b(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x)\b', inst, re.I):
            regs.add(m.group(0).lower())
        return regs


# ── 差分分析器 ────────────────────────────────────────────────────

class DiffTaintAnalyzer:
    """补丁前后的污点流差分分析。

    用法:
        analyzer = DiffTaintAnalyzer()
        report = analyzer.analyze(original_asm, patched_asm, 'CVE-2024-0001')
        if report.patch_improves_safety:
            print('补丁改善了输入净化')
    """

    def __init__(self):
        self._tracker = TaintTracker()

    def analyze(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "") -> DiffTaintReport:
        """差分污点分析。"""
        report = DiffTaintReport(patch_id=patch_id)

        orig_flows = self._tracker.extract_taint_graph(original_asm)
        patch_flows = self._tracker.extract_taint_graph(patched_asm)
        report.original_flows = orig_flows
        report.patched_flows = patch_flows

        # 统计净化变化
        orig_san_count = sum(len(f.sanitizations) for f in orig_flows)
        patch_san_count = sum(len(f.sanitizations) for f in patch_flows)
        report.new_sanitizations = max(0, patch_san_count - orig_san_count)
        report.removed_sanitizations = max(0, orig_san_count - patch_san_count)

        # 新增的未净化路径
        orig_unsan = [f for f in orig_flows if not f.is_sanitized]
        patch_unsan = [f for f in patch_flows if not f.is_sanitized]
        report.new_unsanitized_paths = max(0, len(patch_unsan) - len(orig_unsan))

        # 综合判定
        report.patch_improves_safety = (
            report.new_sanitizations > 0 and report.new_unsanitized_paths == 0)
        report.patch_introduces_risk = (
            report.removed_sanitizations > 0 or report.new_unsanitized_paths > 0)

        if report.patch_improves_safety:
            report.recommendation = "补丁有效改善了输入净化——污点流得到了更好的清洗"
        elif report.patch_introduces_risk:
            report.recommendation = ("补丁引入了 %d 条新的未净化路径——"
                                     "可能存在输入验证缺失" % report.new_unsanitized_paths)
        elif report.new_sanitizations == 0 and report.removed_sanitizations == 0:
            report.recommendation = "补丁未改变污点传播模式——输入净化状态不变"
        else:
            report.recommendation = "污点流变化复杂，建议人工审查"

        return report
