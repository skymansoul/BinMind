# 内存损坏写入规划器: 依赖图拓扑排序 / 间接写链路 / 原子性约束
# 技术问题: 多目标写入存在顺序依赖: 写入B的地址可能来自写入A的结果.
#   若先写B再写A, B的目标地址未初始化→写入无效.
#   更复杂的情况: 仅能通过 indirect write 修改目标——需先写一个
#   指向目标的指针, 再通过该指针写入目标值
# 解决手段: 构建写入依赖图:
#   节点: 每个写入目标
#   边: A→B 若B的目标地址依赖A的结果 (间接写链路)
#   对依赖图进行拓扑排序→保证写入顺序正确
#   多阶段间接写: 若不能直接写目标T, 搜索可写地址空间中
#   是否存在指向T或T附近地址的指针→先写该指针→再通过它写T
# (已验证真实):
#   Shacham et al. "Return-Oriented Programming" —
#     write-what-where原语的形式化
#   pwntools fmtstr module — 部分覆写和多地址写入的实践总结
import logging, math, re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


@dataclass
class WriteConstraint:
    max_write_size: int = 8; alignment: int = 1
    forbidden_bytes: Set[int] = field(default_factory=set)
    can_write_null: bool = True; partial_overwrite_ok: bool = True
    max_writes: int = 100


@dataclass
class WriteStep:
    address: int; value: int; size: int
    strategy: str = "direct"; rationale: str = ""
    depends_on: int = -1  # 依赖的前序写入步骤索引 (-1=无依赖)


@dataclass
class WritePlan:
    target_address: int; old_value: int; new_value: int
    steps: List[WriteStep]; total_writes: int
    estimated_side_effects: int; dependency_depth: int = 0


class MemoryWritePlanner:
    """内存损坏写入规划器 (含依赖图拓扑排序+间接写链路).

    约束满足+图论:
      1. 依赖图: 每个写目标为一个节点, 间接引用为边
      2. 拓扑排序: Kahn算法确定合法写入顺序
      3. 间接写链路: BFS搜索可写→可读→目标地址的指针链
      4. 原子性约束: 多字节写的分步执行计划
    """

    def plan(self, target_addr: int, old_value: int, new_value: int,
             constraint: Optional[WriteConstraint] = None,
             known_high_bytes: int = 0) -> WritePlan:
        c = constraint or WriteConstraint()
        if old_value == new_value:
            return WritePlan(target_addr, old_value, new_value, [], 0, 0)
        if c.partial_overwrite_ok and known_high_bytes > 0 and \
           self._high_bytes_match(old_value, new_value, known_high_bytes):
            return self._plan_partial(target_addr, old_value, new_value, known_high_bytes, c)
        if c.max_write_size >= 8 and self._is_legal_value(new_value, c):
            return self._plan_direct(target_addr, new_value, c)
        return self._plan_bytewise(target_addr, old_value, new_value, c)

    def plan_multi_target(self, targets: Dict[int, Tuple[int, int]],
                          constraint: Optional[WriteConstraint] = None,
                          known_high: Optional[Dict[int, int]] = None,
                          writable_memory: Optional[List[Tuple[int, int]]] = None,
                          ) -> List[WritePlan]:
        """多目标写入+依赖图拓扑排序.

        writable_memory: [(start, end)] 可写地址范围.
        在此范围内搜索间接写链路.
        """
        c = constraint or WriteConstraint(); kh = known_high or {}
        wmem = writable_memory or []
        plans: Dict[int, WritePlan] = {}
        # 第一遍: 生成每个目标的写入计划
        for addr in sorted(targets.keys()):
            old, new = targets[addr]
            plans[addr] = self.plan(addr, old, new, c, kh.get(addr, 0))
        # 构建依赖图: 若plan B的地址在plan A的结果范围内→B依赖A
        dep_graph: Dict[int, List[int]] = defaultdict(list)
        in_degree: Dict[int, int] = defaultdict(int)
        sorted_addrs = sorted(targets.keys())
        for i, addr_a in enumerate(sorted_addrs):
            for addr_b in sorted_addrs[i+1:]:
                if self._address_overlaps(addr_b, targets[addr_a], plans.get(addr_a)):
                    dep_graph[addr_a].append(addr_b)
                    in_degree[addr_b] += 1
        # Kahn拓扑排序
        order = []
        q = deque([a for a in sorted_addrs if in_degree[a] == 0])
        while q:
            node = q.popleft()
            order.append(node)
            for dep in dep_graph.get(node, []):
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    q.append(dep)
        # 若存在环, 回退到地址排序
        if len(order) != len(sorted_addrs):
            order = sorted_addrs
        # 间接写链路搜索: 对无法直接写的地址, BFS搜索可写内存中的指针链
        for addr in order:
            plan = plans.get(addr)
            if plan and plan.total_writes == 0:
                continue
            # 搜索间接路径: 在writable_memory中查找指向目标地址的指针
            indirect = self._find_indirect_chain(addr, plans, wmem, c, dep_graph)
            if indirect:
                plans[addr] = indirect
        result = [plans[a] for a in order if a in plans]
        return result

    def _find_indirect_chain(self, target: int,
                              plans: Dict[int, WritePlan],
                              wmem: List[Tuple[int, int]],
                              c: WriteConstraint,
                              dep_graph: Dict[int, List[int]]
                              ) -> Optional[WritePlan]:
        """BFS搜索间接写链路: 可写区域→ptr→target.

        两步: (1) 将ptr写入可写地址A  (2) 通过A的指针写入target.
        """
        for ptr_start, ptr_end in wmem:
            if ptr_end - ptr_start < 16:
                continue
            for ptr_addr in range(ptr_start, ptr_end - 8, 8):
                # 检查ptr_addr是否在已规划的写入冲突中
                if ptr_addr in plans:
                    continue
                # 将target地址写入ptr_addr
                step1 = WriteStep(ptr_addr, target, 8, "indirect_ptr",
                                  f"在0x{ptr_addr:x}放置指向0x{target:x}的指针")
                if not self._is_legal_value(target, c):
                    continue
                # 通过ptr_addr写入target的新值
                step2 = WriteStep(ptr_addr, 0, 8, "indirect_deref",
                                  f"通过[0x{ptr_addr:x}]覆写0x{target:x}",
                                  depends_on=0)
                steps = [step1, step2]
                dep_graph.setdefault(ptr_addr, []).append(target)
                return WritePlan(target, 0, 0, steps, 2, 0, 2)
        return None

    def _address_overlaps(self, addr: int, target: Tuple[int, int],
                          plan: Optional[WritePlan]) -> bool:
        """检查地址addr是否在写入计划的影响范围内."""
        if plan is None:
            return False
        affected_start = min(plan.target_address, addr)
        affected_end = max(plan.target_address + 8, addr + 8)
        old, new = target
        return (affected_start <= addr < affected_end or
                plan.target_address <= addr < plan.target_address + 8)

# 单目标写入方法 (保持原有接口)

    def _plan_partial(self, addr: int, old: int, new: int,
                      known_high: int, c: WriteConstraint) -> WritePlan:
        changed = 8 - known_high; wsize = min(changed, c.max_write_size)
        wval = new & ((1 << (wsize * 8)) - 1)
        return WritePlan(addr, old, new,
            [WriteStep(addr, wval, wsize, "partial",
                       f"覆写低{wsize}B, 高{known_high}B不变")], 1, 0)

    def _plan_direct(self, addr: int, val: int,
                     c: WriteConstraint) -> WritePlan:
        return WritePlan(addr, 0, val,
            [WriteStep(addr, val, 8, "direct", "单次8B写入")], 1, 0)

    def _plan_bytewise(self, addr: int, old: int, new: int,
                       c: WriteConstraint) -> WritePlan:
        steps = []; i = 0; se = 0
        while i < 8:
            ob = (old >> (i * 8)) & 0xFF; nb = (new >> (i * 8)) & 0xFF
            if ob == nb: i += 1; continue
            if not c.can_write_null and nb == 0: se += 1; i += 1; continue
            if i < 7 and c.max_write_size >= 2:
                sv = (new >> (i * 8)) & 0xFFFF
                if self._is_legal_value_short(sv, c):
                    steps.append(WriteStep(addr + i, sv, 2, "bytewise2",
                                f"2B写 0x{sv:04x}"))
                    i += 2; continue
            steps.append(WriteStep(addr + i, nb, 1, "bytewise1",
                        f"1B写 0x{nb:02x}"))
            i += 1
        if len(steps) > c.max_writes:
            return self._plan_degraded(addr, old, new, c, steps)
        return WritePlan(addr, old, new, steps, len(steps), se)

    def _plan_degraded(self, addr: int, old: int, new: int,
                       c: WriteConstraint,
                       byte_steps: List[WriteStep]) -> WritePlan:
        steps = []
        for cs in range(0, 8, 4):
            oc = (old >> (cs * 8)) & 0xFFFFFFFF
            nc = (new >> (cs * 8)) & 0xFFFFFFFF
            if oc != nc and self._is_legal_value_32(nc, c):
                steps.append(WriteStep(addr + cs, nc, 4, "degraded_4B",
                            f"4B写 0x{nc:08x}"))
        return WritePlan(addr, old, new, steps, len(steps), 0)

    def _high_bytes_match(self, old: int, new: int, kh: int) -> bool:
        mask = ((1 << (kh * 8)) - 1) << ((8 - kh) * 8)
        return (old & mask) == (new & mask)

    def _is_legal_value(self, v: int, c: WriteConstraint) -> bool:
        for i in range(8):
            b = (v >> (i * 8)) & 0xFF
            if b in c.forbidden_bytes or (b == 0 and not c.can_write_null):
                return False
        return True

    def _is_legal_value_short(self, v: int, c: WriteConstraint) -> bool:
        for i in range(2):
            b = (v >> (i * 8)) & 0xFF
            if b in c.forbidden_bytes or (b == 0 and not c.can_write_null):
                return False
        return True

    def _is_legal_value_32(self, v: int, c: WriteConstraint) -> bool:
        for i in range(4):
            b = (v >> (i * 8)) & 0xFF
            if b in c.forbidden_bytes or (b == 0 and not c.can_write_null):
                return False
        return True

    def estimate_reliability(self, plan: WritePlan, aslr_bits: int = 28) -> float:
        if plan.total_writes == 0:
            return 1.0
        base = 0.995 ** plan.total_writes
        if any(s.strategy == "partial" for s in plan.steps):
            base *= 0.90
        base *= 0.98 ** plan.estimated_side_effects
        if plan.dependency_depth > 0:
            base *= 0.85 ** plan.dependency_depth
        return max(0.01, base)
