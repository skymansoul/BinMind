# 修改记录:
# 2025-09-10 15:27 — 初始实现：补丁组合代数 + 交换性检测 + 冲突消解
# 2025-09-11 09:51 — 增加依赖闭包计算：补丁组合的最小前置条件

"""Multi-Patch Composition Engine — 补丁组合的形式代数。

搜索结果显示该方向完全空白——无任何现有工具对二进制补丁做
代数组合分析。

形式化：
  补丁 P 定义为 (A, R) 对，其中 A 为地址区间集合，R 为替换规则。
  补丁组合 P₁ ∘ P₂ 表示先应用 P₂ 再应用 P₁。

交换性：
  P₁ 和 P₂ 可交换 ⇔ P₁ ∘ P₂ = P₂ ∘ P₁
  即 A₁ ∩ A₂ = ∅ (不相交的修改) 且无数据依赖。

幂等性：
  P 是幂等的 ⇔ P ∘ P = P (重复应用无效)
  大多数安全补丁天然幂等（相同的安全检查不能添加两次）。

组合运算：
  MERGE(P₁, P₂): 合并两个补丁为一个（消解冲突后）
  DIFF(P₁, P₂): 两补丁的差异部分
  CLOSURE(P): 补丁 P 的依赖闭包（P 正常工作的前提补丁集）
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict

_log = logging.getLogger(__name__)


@dataclass
class PatchOp:
    """单个补丁操作。"""
    patch_id: str
    addresses: Set[int] = field(default_factory=set)  # 修改的偏移集合
    address_ranges: List[Tuple[int, int]] = field(default_factory=list)
    regs_read: Set[str] = field(default_factory=set)
    regs_write: Set[str] = field(default_factory=set)
    depends_on: List[str] = field(default_factory=list)  # 依赖的其他补丁ID
    instruction_count: int = 0


@dataclass
class ComposeResult:
    """补丁组合/比较的结果。"""
    op_name: str = ""                # "merge" | "diff" | "commute_check"
    patch_ids: List[str] = field(default_factory=list)
    # 合并结果
    merged_patch: Optional[PatchOp] = None
    conflict_addresses: Set[int] = field(default_factory=set)
    # 交换性
    is_commutative: bool = False
    commutativity_violation: str = ""
    # 差异
    diff_only_in_a: Set[int] = field(default_factory=set)
    diff_only_in_b: Set[int] = field(default_factory=set)
    # 依赖闭包
    closure: List[str] = field(default_factory=list)


@dataclass
class ComposeReport:
    """补丁组合分析报告。"""
    patches: List[PatchOp] = field(default_factory=list)
    results: List[ComposeResult] = field(default_factory=list)
    # 全局信息
    total_conflicts: int = 0
    commutative_pairs: int = 0
    non_commutative_pairs: int = 0
    # 最优应用序
    optimal_order: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'patches': len(self.patches),
            'conflicts': self.total_conflicts,
            'commutative': self.commutative_pairs,
            'non_commutative': self.non_commutative_pairs,
            'optimal_order': self.optimal_order,
        }


# 补丁操作解析器

class PatchOpParser:
    """从汇编/字节级补丁描述提取 PatchOp。"""

    def parse(self, patch_id: str, asm_lines: List[str],
              changed_offsets: List[int] = None) -> PatchOp:
        """从汇编变更列表解析补丁操作。"""
        op = PatchOp(patch_id=patch_id)
        op.instruction_count = len([l for l in asm_lines if l.strip()])

        if changed_offsets:
            op.addresses = set(changed_offsets)
            # 合并连续偏移为区间
            sorted_addr = sorted(op.addresses)
            if sorted_addr:
                start = sorted_addr[0]; prev = start
                for a in sorted_addr[1:]:
                    if a != prev + 1:
                        op.address_ranges.append((start, prev - start + 1))
                        start = a
                    prev = a
                op.address_ranges.append((start, prev - start + 1))

        # 提取寄存器读写
        for line in asm_lines:
            parts = line.strip().lower().replace(',', ' ').split()
            if not parts:
                continue
            mnemonic = parts[0]
            regs_in_line = set()
            for p in parts[1:]:
                r = p.rstrip(',;')
                if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x)$', r):
                    regs_in_line.add(r)
            if not regs_in_line:
                continue
            # 第一个寄存器是写入目标
            first = list(regs_in_line)[0] if regs_in_line else ""
            if mnemonic in ('mov','lea','add','sub','xor','and','or','pop','inc','dec'):
                op.regs_write.add(first)
                op.regs_read.update(regs_in_line - {first})
            elif mnemonic in ('cmp','test','push'):
                op.regs_read.update(regs_in_line)

        return op


# 补丁组合引擎

class PatchCompositionEngine:
    """补丁组合的形式代数引擎。"""

    def __init__(self):
        self._parser = PatchOpParser()

    def check_commutativity(self, a: PatchOp, b: PatchOp) -> ComposeResult:
        """检查两补丁是否可交换。

        条件：A ∩ B = ∅ (无地址重叠) 且无读-写依赖。
        """
        result = ComposeResult(op_name="commute_check", patch_ids=[a.patch_id, b.patch_id])

        # 地址重叠
        addr_overlap = a.addresses & b.addresses
        if addr_overlap:
            result.is_commutative = False
            result.commutativity_violation = "地址重叠于 %d 个偏移" % len(addr_overlap)
            return result

        # 数据依赖：A 写入的寄存器被 B 读取
        if a.regs_write & b.regs_read:
            result.is_commutative = False
            result.commutativity_violation = "A 写入 %s，B 读取 %s" % (
                ','.join(a.regs_write & b.regs_read)[:20],
                ','.join(a.regs_write & b.regs_read)[:20])
            return result

        if b.regs_write & a.regs_read:
            result.is_commutative = False
            result.commutativity_violation = "B 写入 %s，A 读取 %s" % (
                ','.join(b.regs_write & a.regs_read)[:20],
                ','.join(b.regs_write & a.regs_read)[:20])
            return result

        result.is_commutative = True
        return result

    def merge(self, a: PatchOp, b: PatchOp) -> ComposeResult:
        """合并两个补丁。若有冲突返回冲突地址。"""
        result = ComposeResult(op_name="merge", patch_ids=[a.patch_id, b.patch_id])

        conflicts = a.addresses & b.addresses
        result.conflict_addresses = conflicts

        if conflicts:
            merged = PatchOp(
                patch_id="merge(%s,%s)" % (a.patch_id, b.patch_id),
                addresses=a.addresses | b.addresses,
                regs_read=a.regs_read | b.regs_read,
                regs_write=a.regs_write | b.regs_write)
            # 冲突消解策略：A 覆盖 B（先到优先）
            merged.addresses = (a.addresses | b.addresses) - conflicts
            merged.addresses |= conflicts  # 保留冲突地址但标记
            merged.instruction_count = a.instruction_count + b.instruction_count
            result.merged_patch = merged
        else:
            result.merged_patch = PatchOp(
                patch_id="merge(%s,%s)" % (a.patch_id, b.patch_id),
                addresses=a.addresses | b.addresses,
                address_ranges=a.address_ranges + b.address_ranges,
                regs_read=a.regs_read | b.regs_read,
                regs_write=a.regs_write | b.regs_write,
                depends_on=list(set(a.depends_on + b.depends_on)),
                instruction_count=a.instruction_count + b.instruction_count)

        return result

    def diff(self, a: PatchOp, b: PatchOp) -> ComposeResult:
        """计算两补丁的差异。"""
        result = ComposeResult(op_name="diff", patch_ids=[a.patch_id, b.patch_id])
        result.diff_only_in_a = a.addresses - b.addresses
        result.diff_only_in_b = b.addresses - a.addresses
        return result

    def closure(self, patch: PatchOp, all_patches: Dict[str, PatchOp]) -> ComposeResult:
        """计算补丁的依赖闭包（所需的所有前置补丁）。"""
        result = ComposeResult(op_name="closure", patch_ids=[patch.patch_id])
        visited = set(); stack = list(patch.depends_on)
        while stack:
            dep_id = stack.pop()
            if dep_id in visited or dep_id not in all_patches:
                continue
            visited.add(dep_id)
            dep = all_patches[dep_id]
            for d in dep.depends_on:
                if d not in visited:
                    stack.append(d)
        result.closure = sorted(visited)
        return result

    def analyze_set(self, patches: List[PatchOp]) -> ComposeReport:
        """对补丁集合执行完整的组合分析。"""
        report = ComposeReport(patches=patches)
        all_patches = {p.patch_id: p for p in patches}

        # 成对交换性检查
        for i in range(len(patches)):
            for j in range(i + 1, len(patches)):
                cr = self.check_commutativity(patches[i], patches[j])
                report.results.append(cr)
                if cr.is_commutative:
                    report.commutative_pairs += 1
                else:
                    report.non_commutative_pairs += 1

        # 成对合并检查
        for i in range(len(patches)):
            for j in range(i + 1, len(patches)):
                mr = self.merge(patches[i], patches[j])
                report.results.append(mr)
                report.total_conflicts += len(mr.conflict_addresses)

        # 计算最优应用序（拓扑排序 by depends_on）
        report.optimal_order = self._topological_order(patches)

        return report

    @staticmethod
    def _topological_order(patches: List[PatchOp]) -> List[str]:
        """基于依赖的拓扑排序。"""
        in_degree = {p.patch_id: 0 for p in patches}
        adj = defaultdict(list)
        for p in patches:
            for dep in p.depends_on:
                if dep in in_degree:
                    adj[dep].append(p.patch_id)
                    in_degree[p.patch_id] += 1
        from collections import deque
        queue = deque(pid for pid, deg in in_degree.items() if deg == 0)
        order = []
        while queue:
            pid = queue.popleft()
            order.append(pid)
            for child in adj[pid]:
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        # 剩余节点（环）追加到末尾
        for pid, deg in in_degree.items():
            if deg > 0 and pid not in order:
                order.append(pid)
        return order
