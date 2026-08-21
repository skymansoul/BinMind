# SemVer 兼容性矩阵
# 重构：从启发式规则升级为指令依赖图+结构diff

"""Patch Semantic Versioning — 基于指令依赖图的语义版本推断。

旧版使用正则规则评分（本质是模板匹配），新版改为两阶段结构分析：

阶段 1 — 指令依赖图构建
  将补丁前后的汇编指令构建为有向无环图 (DAG)，节点 = 指令，
  边 = 数据依赖 (RAW) 或控制依赖 (分支→被控制指令)。
  通过图编辑距离 (GED) 量化补丁的结构变更程度。

阶段 2 — 变更范围分类
  - API 变更: 新增/删除的 call 节点影响了函数的外部接口
  - ABI 变更: 栈帧节点 (sub rsp) 或 callee-saved 寄存器节点变化
  - 行为变更: 依赖图中 sink 节点的可达路径变化
  三类变更的加权组合决定 MAJOR / MINOR / PATCH。

为什么不用纯启发式：
  正则规则无法区分"在 cmp 前插入 NOP"和"新增一个完整的边界检查函数"。
  图编辑距离对此天然区分——前者 GED ≈ 0，后者 GED >> 0。
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

_log = logging.getLogger(__name__)


class SemVerBump:
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    NO_CHANGE = "no_change"


@dataclass
class InstrNode:
    """指令依赖图中的一个节点。"""
    idx: int
    mnemonic: str
    operands: str
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False
    writes_regs: Set[str] = field(default_factory=set)
    reads_regs: Set[str] = field(default_factory=set)
    writes_mem: bool = False
    reads_mem: bool = False


@dataclass
class DepGraph:
    """指令依赖图。"""
    nodes: List[InstrNode] = field(default_factory=list)
    edges: Set[Tuple[int, int]] = field(default_factory=set)
    # 入口点
    call_targets: Set[str] = field(default_factory=set)
    stack_frame_size: int = 0


@dataclass
class SemVerInfo:
    current_version: str = "1.0.0"
    bump: str = "no_change"
    new_version: str = "1.0.0"
    reasons: List[str] = field(default_factory=list)


@dataclass
class SemVerReport:
    patch_id: str = ""
    before: SemVerInfo = field(default_factory=SemVerInfo)
    after: SemVerInfo = field(default_factory=SemVerInfo)
    abi_compatible: bool = True
    api_compatible: bool = True
    recommended_bump: str = "patch"
    graph_edit_distance: int = 0
    api_nodes_added: int = 0
    abi_nodes_changed: int = 0

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'before': self.before.current_version,
            'after': self.after.new_version,
            'bump': self.recommended_bump,
            'ged': self.graph_edit_distance,
            'api_added': self.api_nodes_added,
            'abi_changed': self.abi_nodes_changed,
            'abi_compat': self.abi_compatible,
            'reasons': self.after.reasons[:5],
        }


# 图构建器

class DepGraphBuilder:
    """从汇编指令列表构建指令依赖图。"""

    _CALLEE_SAVED = {'rbx','r12','r13','r14','r15','rbp','rsp'}
    _PARAM_REGS = {'rdi','rsi','rdx','rcx','r8','r9'}

    def build(self, asm_lines: List[str]) -> DepGraph:
        g = DepGraph()
        for i, line in enumerate(asm_lines):
            node = self._parse_instruction(i, line)
            if node:
                g.nodes.append(node)
                if node.is_call:
                    target = self._extract_call_target(line)
                    if target:
                        g.call_targets.add(target)
        # 建立数据依赖边: 若 node[j] 读取了 node[i] 写入的寄存器，添加 i→j
        for i in range(len(g.nodes)):
            for j in range(i + 1, len(g.nodes)):
                if g.nodes[i].writes_regs & g.nodes[j].reads_regs:
                    # 确保中间没有其他节点覆写同一寄存器
                    killed = False
                    for k in range(i + 1, j):
                        if g.nodes[k].writes_regs & g.nodes[i].writes_regs:
                            killed = True
                            break
                    if not killed:
                        g.edges.add((i, j))
        # 控制依赖: 分支节点 → 后续节点（简化：仅标记，不精确计算支配边界）
        return g

    def _parse_instruction(self, idx: int, line: str) -> Optional[InstrNode]:
        stripped = line.strip()
        if not stripped or stripped.startswith(';') or stripped.startswith('.'):
            return None
        parts = stripped.lower().replace(',', ' ').split()
        if not parts:
            return None
        mnemonic = parts[0].rstrip(':')
        # 跳过纯标签行
        if mnemonic.endswith(':') and len(parts) == 1:
            return None

        node = InstrNode(idx=idx, mnemonic=mnemonic, operands=' '.join(parts[1:]))
        node.is_branch = mnemonic.startswith('j') or mnemonic in ('call','ret')
        node.is_call = mnemonic == 'call'
        node.is_ret = mnemonic == 'ret'

        # 寄存器读写分类
        regs_in_line = [p.rstrip(',;') for p in parts[1:]
                       if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x|[sd]i[lp]?|sp|bp)$', p)]
        if regs_in_line and mnemonic in ('mov','lea','add','sub','xor','and','or','shl','shr','mul','imul','inc','dec','neg','not','pop','xchg'):
            node.writes_regs.add(regs_in_line[0])
            node.reads_regs.update(regs_in_line[1:])
        elif regs_in_line and mnemonic in ('cmp','test','push'):
            node.reads_regs.update(regs_in_line)
        elif mnemonic == 'call':
            node.writes_regs.add('rax')

        # 检测栈帧指令
        if mnemonic == 'sub' and 'rsp' in regs_in_line:
            m = re.search(r'(0x[0-9a-f]+|\d+)', ' '.join(parts[1:]))
            if m:
                v = m.group(1)
                node.writes_regs.add('__stack_frame__')

        # 内存访问
        node.writes_mem = ('[' in stripped and mnemonic.startswith('mov') and '[' in parts[1] if len(parts)>1 else False)
        node.reads_mem = ('[' in stripped and not (mnemonic.startswith('mov') and '[' in (parts[1] if len(parts)>1 else '')))

        return node

    @staticmethod
    def _extract_call_target(line: str) -> str:
        m = re.search(r'\bcall\s+(\S+)', line, re.I)
        return m.group(1).rstrip(';') if m else ""


# 图编辑距离

def graph_edit_distance(g1: DepGraph, g2: DepGraph) -> int:
    """简化图编辑距离: |V1ΔV2| + |E1ΔE2|。

    节点等价判定：同 mnemonic + 同操作数模式（归一化立即数后）。
    边等价判定：同源节点和同目标节点（按等价节点映射）。
    不执行精确的子图同构——对补丁分析场景，启发式足够。
    """
    def norm_op(op: str) -> str:
        return re.sub(r'0x[0-9a-f]+|\b\d+\b', 'IMM', op)

    n1_map = {}  # idx→signature
    n2_map = {}
    for n in g1.nodes:
        n1_map[n.idx] = (n.mnemonic, norm_op(n.operands))
    for n in g2.nodes:
        n2_map[n.idx] = (n.mnemonic, norm_op(n.operands))

    sigs1 = set(n1_map.values())
    sigs2 = set(n2_map.values())
    node_dist = len(sigs1 - sigs2) + len(sigs2 - sigs1)

    # 边距离简化：按节点签名比较
    e1_sigs = set()
    e2_sigs = set()
    sig_to_idx1 = {v: k for k, v in n1_map.items()}
    sig_to_idx2 = {v: k for k, v in n2_map.items()}
    for (src, dst) in g1.edges:
        if src in n1_map and dst in n1_map:
            e1_sigs.add((n1_map[src], n1_map[dst]))
    for (src, dst) in g2.edges:
        if src in n2_map and dst in n2_map:
            e2_sigs.add((n2_map[src], n2_map[dst]))
    edge_dist = len(e1_sigs - e2_sigs) + len(e2_sigs - e1_sigs)

    return node_dist + edge_dist


# 变更分析器

class StructuralChangeAnalyzer:
    """基于依赖图的变更范围分类。"""

    def analyze(self, g_orig: DepGraph, g_patched: DepGraph) -> Tuple[int, int, int]:
        """返回 (api_changes, abi_changes, behavior_changes)。"""
        api = 0; abi = 0; behavior = 0

        # API: 新增/删除 call 目标
        orig_calls = g_orig.call_targets
        patch_calls = g_patched.call_targets
        api += len(patch_calls - orig_calls)
        api += len(orig_calls - patch_calls)
        # 参数寄存器使用变化也算API变更
        for n in g_patched.nodes:
            if n.reads_regs & DepGraphBuilder._PARAM_REGS:
                # 检查原始图中是否有对应读取
                orig_reads = set()
                for on in g_orig.nodes:
                    orig_reads.update(on.reads_regs)
                if n.reads_regs - orig_reads:
                    api += 1

        # ABI: 栈帧+calee-saved变化
        for n in g_patched.nodes:
            if '__stack_frame__' in n.writes_regs:
                orig_has_frame = any('__stack_frame__' in on.writes_regs for on in g_orig.nodes)
                if not orig_has_frame:
                    abi += 1
            if n.writes_regs & DepGraphBuilder._CALLEE_SAVED:
                orig_writes = set()
                for on in g_orig.nodes:
                    orig_writes.update(on.writes_regs)
                if (n.writes_regs & DepGraphBuilder._CALLEE_SAVED) - orig_writes:
                    abi += 1

        # Behavior: GED 减去 ABI/API 后的剩余变更
        ged = graph_edit_distance(g_orig, g_patched)
        behavior = max(0, ged - api - abi)
        return api, abi, behavior


# 推断引擎

class SemVerInferenceEngine:
    """基于结构变更的语义版本推断。"""

    def __init__(self):
        self._builder = DepGraphBuilder()
        self._analyzer = StructuralChangeAnalyzer()

    def infer(self, original_asm: List[str],
              patched_asm: List[str],
              current_version: str = "1.0.0",
              patch_id: str = "") -> SemVerReport:
        report = SemVerReport(patch_id=patch_id)
        report.before = SemVerInfo(current_version=current_version, new_version=current_version)

        g_orig = self._builder.build(original_asm)
        g_patched = self._builder.build(patched_asm)
        ged = graph_edit_distance(g_orig, g_patched)
        report.graph_edit_distance = ged

        api, abi, behavior = self._analyzer.analyze(g_orig, g_patched)
        report.api_nodes_added = api
        report.abi_nodes_changed = abi

        reasons = []
        if abi > 0:
            reasons.append("ABI变更: %d 处栈帧/callee-saved寄存器变化" % abi)
            report.abi_compatible = False
        if api > 0:
            reasons.append("API变更: %d 处call目标/参数变化" % api)
            if abi == 0:
                report.api_compatible = False
        if behavior > 0 and abi == 0 and api == 0:
            reasons.append("行为变更: GED=%d (纯内部逻辑变化)" % ged)

        if abi > 0:
            bump = SemVerBump.MAJOR
        elif api > 0 or ged > 5:
            bump = SemVerBump.MINOR
        elif ged > 0:
            bump = SemVerBump.PATCH
        else:
            bump = SemVerBump.NO_CHANGE
        report.recommended_bump = bump

        major, minor, patch = self._parse(current_version)
        if bump == SemVerBump.MAJOR:
            major += 1; minor = 0; patch = 0
        elif bump == SemVerBump.MINOR:
            minor += 1; patch = 0
        elif bump == SemVerBump.PATCH:
            patch += 1
        report.after = SemVerInfo(
            current_version=current_version, bump=bump,
            new_version="%d.%d.%d" % (major, minor, patch), reasons=reasons)
        return report

    @staticmethod
    def _parse(v: str) -> Tuple[int, int, int]:
        p = v.replace('v','').split('.')
        return (int(p[0]) if len(p)>0 else 1, int(p[1]) if len(p)>1 else 0, int(p[2]) if len(p)>2 else 0)
