# 修改记录:
# 2025-07-23 11:05 — 初始创建: 漏洞类型→操作序列的Dig&Fill规划框架
# 2025-07-29 14:22 — 增加线性Diophantine方程求解器, 实现精确Dig&Fill
# 2025-08-04 09:38 — 增加tcache/fastbin容量约束传播+多bin分配建模
# 堆布局策略规划器: Dig&Fill Diophantine求解 / bin容量约束 / 多阶段分配
# 技术问题: 手工规划堆操作序列需推导 (分配大小×计数) 的整数解.
#   例如: 目标释放3个0x40 chunk到tcache, 但同时有0x30的噪声分配2次.
#   Δd₁x₁ + Δd₂x₂ + ... + Δdₙxₙ + d = 0 的解给出所需的操作序列
# 解决手段: 实现扩展欧几里得算法求解二元Diophantine方程,
#   n元情况降维为逐对求解. 将bin容量约束(tcache≤7, fastbin≤10)
#   编码为不等式约束, 过滤不可行解
# 参考 (已验证真实):
#   MAZE (Wang et al., USENIX Security 2021) — Dig&Fill框架,
#     本项目实现其核心Diophantine求解的轻量级版本
#   glibc malloc source (ptmalloc2) — bin容量和chunk大小约束
from __future__ import annotations
import logging, math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

_MIN_CHUNK = 0x20; _ALIGNMENT = 0x10
_TCACHE_MAX = 0x410; _TCACHE_COUNT = 7; _FASTBIN_MAX = 0x80


def _align_up(size: int, align: int = _ALIGNMENT) -> int:
    return (size + align - 1) & ~(align - 1)

def _chunk_size(user_size: int) -> int:
    return _align_up(max(_align_up(user_size) + 0x10, _MIN_CHUNK))


@dataclass
class HeapOperation:
    op_type: str; size: int = 0; count: int = 1
    target_label: str = ""; rationale: str = ""


@dataclass
class HeapLayoutPlan:
    vulnerability: str; operations: List[HeapOperation]
    estimated_ops: int; success_confidence: float
    notes: List[str] = field(default_factory=list)


class DiophantineSolver:
    """二元线性Diophantine方程求解器.

    求解 ax + by = c 的整数解 (x, y).
    使用扩展欧几里得算法.
    n元方程降维: 逐对求解, 每次消去一个变量.
    """

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """返回 (gcd, x, y) 使得 ax + by = gcd(a, b)."""
        if b == 0:
            return (a, 1, 0)
        g, x1, y1 = DiophantineSolver.extended_gcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)

    @staticmethod
    def solve_2var(a: int, b: int, c: int) -> Optional[Tuple[int, int]]:
        """求解 ax + by = c, 返回最小的非负解 (x ≥ 0, y ≥ 0)."""
        g, x0, y0 = DiophantineSolver.extended_gcd(abs(a), abs(b))
        if c % g != 0:
            return None
        x0 *= c // g; y0 *= c // g
        if a < 0: x0 = -x0
        if b < 0: y0 = -y0
        # 通解: x = x0 + k*(b/g), y = y0 - k*(a/g)
        step_x = b // g; step_y = a // g
        if step_x == 0 and step_y == 0:
            return (x0, y0) if x0 >= 0 and y0 >= 0 else None
        # 寻找最小的非负解
        best = None
        for direction in (1, -1):
            k = 0
            for _ in range(10000):
                x = x0 + k * step_x
                y = y0 - k * step_y
                if x >= 0 and y >= 0:
                    if best is None or x + y < best[0] + best[1]:
                        best = (x, y)
                    break
                k += direction
                if abs(k) > 10000:
                    break
        return best

    @staticmethod
    def solve_nvar(coeffs: List[int], target: int) -> Optional[List[int]]:
        """求解 Σ aᵢxᵢ = target 的非负整数解.

        降维策略: 每次取两个系数求解, 引入新变量代替其中一个.
        """
        if len(coeffs) == 0:
            return [] if target == 0 else None
        if len(coeffs) == 1:
            if target % coeffs[0] == 0 and target // coeffs[0] >= 0:
                return [target // coeffs[0]]
            return None
        # 降维: 解 a₁x₁ + a₂x₂ = target - Σ_{i>2} aᵢxᵢ
        # 对x₃..xₙ在合理范围内搜索
        remaining = coeffs[2:] if len(coeffs) > 2 else []
        if not remaining:
            # 二元: 直接求解
            result = DiophantineSolver.solve_2var(
                coeffs[0], coeffs[1], target)
            return list(result) if result else None
        # n元: 搜索后两个变量的组合
        a1, a2 = coeffs[0], coeffs[1]
        for x2 in range(0, abs(target // a2) + 1 if a2 != 0 else 1):
            remaining_target = target - a2 * x2
            sub_sol = DiophantineSolver.solve_nvar(
                [a1] + remaining, remaining_target)
            if sub_sol is not None:
                return [sub_sol[0], x2] + sub_sol[1:]
        return None


class BinConstraints:
    """堆bin容量约束检查器."""
    @staticmethod
    def check_tcache(chunk_size: int, count: int) -> bool:
        return chunk_size <= _TCACHE_MAX and count <= _TCACHE_COUNT
    @staticmethod
    def check_fastbin(chunk_size: int, count: int) -> bool:
        return chunk_size <= _FASTBIN_MAX and count <= 10
    @staticmethod
    def check_allocs(total_alloc_bytes: int, heap_limit: int = 1 << 20) -> bool:
        return total_alloc_bytes <= heap_limit


class HeapLayoutPlanner:
    """堆布局策略规划器 (含Diophantine求解).

    使用MAZE的Dig&Fill框架:
      Dig: 通过释放chunk创建目标大小的空洞
      Fill: 通过分配chunk占据目标位置
      Solve: 用Diophantine求解器找到精确的 (分配大小, 计数) 组合
    """

    def __init__(self):
        self._solver = DiophantineSolver()

    def solve_dig_fill(self, target_free_size: int,
                       available_chunk_sizes: List[int],
                       noise_alloc_sizes: Optional[List[int]] = None,
                       ) -> Optional[Dict[str, List[Tuple[int, int]]]]:
        """Diophantine求解: 找到创建目标空洞所需的alloc/free序列.

        target_free_size: 需要释放的总字节数
        available_chunk_sizes: 可用的chunk大小列表
        noise_alloc_sizes: 干扰分配的大小列表 (需额外消化)

        返回: {"free": [(size, count)], "alloc": [(size, count)]}
        """
        coeffs = [-(cs) for cs in available_chunk_sizes]  # free → 负系数
        if noise_alloc_sizes:
            coeffs += noise_alloc_sizes  # alloc → 正系数
        # 求解 Σ coeff_i * x_i = target_free_size
        solution = self._solver.solve_nvar(coeffs, target_free_size)
        if solution is None:
            return None
        result: Dict[str, List[Tuple[int, int]]] = {"free": [], "alloc": []}
        n_free = len(available_chunk_sizes)
        for i, cnt in enumerate(solution):
            if cnt <= 0:
                continue
            if i < n_free:
                cs = available_chunk_sizes[i]
                if BinConstraints.check_tcache(_chunk_size(cs), cnt):
                    result["free"].append((cs, cnt))
                else:
                    return None  # 超出bin容量
            else:
                ns = noise_alloc_sizes[i - n_free] if noise_alloc_sizes else cs
                result["alloc"].append((ns, cnt))
        return result

    def plan_uaf(self, victim_size: int, attacker_size: int,
                 victim_label: str = "victim",
                 attacker_label: str = "attacker") -> HeapLayoutPlan:
        v_chunk = _chunk_size(victim_size); a_chunk = _chunk_size(attacker_size)
        ops = [HeapOperation("alloc", victim_size, 1, victim_label,
                f"分配victim chunk ({v_chunk}B)"),
               HeapOperation("free", victim_size, 1, "",
                f"释放victim→{'tcache' if v_chunk <= _TCACHE_MAX else 'bin'}")]
        notes = []
        if a_chunk != v_chunk:
            diff = v_chunk - a_chunk
            sol = self.solve_dig_fill(diff, [a_chunk], [])
            if sol:
                for sz, cnt in sol["free"]:
                    ops.append(HeapOperation("free", sz, cnt, "",
                        f"填充对齐: 释放{cnt}个{sz}B chunk"))
                notes.append(f"Diophantine解: 差值{diff}B由填充chunk补偿")
            else:
                notes.append(f"attacker大小({a_chunk}B)≠victim({v_chunk}B), 无精确解")
        ops.append(HeapOperation("alloc", attacker_size, 1, attacker_label,
                    "分配attacker→期望落入victim空洞"))
        conf = 0.95 if a_chunk == v_chunk else 0.65
        return HeapLayoutPlan("uaf", ops, len(ops), conf, notes)

    def plan_heap_overflow(self, victim_size: int, overflow_bytes: int,
                           target_type_size: int,
                           victim_label: str = "victim",
                           target_label: str = "target") -> HeapLayoutPlan:
        v_chunk = _chunk_size(victim_size); t_chunk = _chunk_size(target_type_size)
        ops = [HeapOperation("alloc", victim_size, 1, victim_label,
                f"分配overflow源 ({v_chunk}B)"),
               HeapOperation("alloc", target_type_size, 1, target_label,
                f"分配target ({t_chunk}B), 紧邻victim")]
        notes = []
        if overflow_bytes > v_chunk:
            notes.append(f"溢出量({overflow_bytes}B)超过victim大小({v_chunk}B)")
        # 使用Diophantine求解消除victim和target之间的间隙
        gap = max(0, target_type_size - victim_size)
        if gap > 0:
            sol = self.solve_dig_fill(gap, [_MIN_CHUNK - 0x10], [])
            if sol:
                notes.append(f"填充{sum(c for _,c in sol['free'])}个padding消除{gap}B间隙")
        ops.append(HeapOperation("free", 0, 0, "", f"触发溢出: {overflow_bytes}B"))
        return HeapLayoutPlan("heap_overflow", ops, len(ops),
                             0.85 if overflow_bytes <= v_chunk + 256 else 0.50, notes)

    def plan_double_free(self, target_size: int,
                         target_label: str = "target") -> HeapLayoutPlan:
        t_chunk = _chunk_size(target_size); ops = []; notes = []
        if t_chunk > _TCACHE_MAX:
            notes.append("大于tcache上限, 使用fastbin dup策略")
            ops.extend([
                HeapOperation("alloc", target_size, 1, "A", f"分配A ({t_chunk}B)"),
                HeapOperation("alloc", target_size, 1, "B", "隔离chunk B"),
                HeapOperation("free", target_size, 1, "", "free(A)→fastbin"),
                HeapOperation("free", target_size, 1, "", "free(B)→fastbin"),
                HeapOperation("free", target_size, 1, "", "二次free(A)→double free")])
        else:
            ops.extend([
                HeapOperation("alloc", target_size, 1, "A", f"分配A ({t_chunk}B)"),
                HeapOperation("free", target_size, 1, "", "free(A)→tcache"),
                HeapOperation("free", target_size, 1, "", "二次free(A)→tcache dup")])
            notes.append("glibc≥2.31需覆盖tcache key字段")
        ops.append(HeapOperation("alloc", target_size, 1, target_label, "重新分配获得同地址"))
        return HeapLayoutPlan("double_free", ops, len(ops), 0.80, notes)

    def plan_off_by_one(self, victim_size: int,
                        victim_label: str = "victim",
                        target_label: str = "target") -> HeapLayoutPlan:
        ops = [HeapOperation("alloc", victim_size, 1, victim_label, "victim"),
               HeapOperation("alloc", _MIN_CHUNK - 0x10, 1, target_label, "target紧邻"),
               HeapOperation("free", 0, 0, "", "off-by-one: 覆写target size LSB")]
        return HeapLayoutPlan("off_by_one", ops, len(ops), 0.65,
                              ["目标: 修改target的size字段→触发重叠chunk"])

    def plan(self, vulnerability: str, **kwargs) -> Optional[HeapLayoutPlan]:
        planners = {"uaf": self.plan_uaf, "heap_overflow": self.plan_heap_overflow,
                    "double_free": self.plan_double_free, "off_by_one": self.plan_off_by_one}
        planner = planners.get(vulnerability)
        return planner(**kwargs) if planner else None

    def simulate_layout(self, plan: HeapLayoutPlan) -> Dict[str, List[Tuple[int, int, str]]]:
        heap_base = 0x555000000000; current = heap_base
        allocs: Dict[str, List[Tuple[int, int, str]]] = {}
        for op in plan.operations:
            if op.op_type == "alloc" and op.count > 0:
                sz = _chunk_size(op.size)
                for i in range(op.count):
                    lbl = f"{op.target_label}_{i}" if op.target_label else f"anon_{current:x}"
                    allocs.setdefault(op.target_label or lbl, []).append((current, sz, "allocated"))
                    current += sz
        return allocs
