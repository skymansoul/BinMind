# 增加污点置信度衰减链：间接污点 (mov rax, [rbx]; cmp al, 0) 的权重低于直接污点
#
# 污点约束符号探索器 - 将字节级污点信息注入符号执行路径优先级
#
# 问题:
# subreg_taint 知道 RAX[2] 被用户输入污染
# symexec 知道当前有 3 条待探索路径, 每条有不同深度的约束
#   两个子系统之间没有信息通道。结果是符号执行可能花大量时间
#   探索与用户输入无关的死代码路径 (如初始化代码), 而忽略
# 真正由攻击者控制的路径
#
# (a) 从 subreg_taint.SubRegTaintSt 读取每条路径执行时
#       的寄存器污点状态快照
#   (b) 对每条路径的终止条件 (final constraint) 做操作数分析:
# 若约束中引用的寄存器/内存地址与被污染字节重合
#       则该路径获得探索优先级提升
# (c) 提升量 = base_priori * (1 + taint_score)
#       taint_score = weighted_sum(taint_confidence / distance_to_source)
# 其中 distance_to_source 是污点传播跳数, 直接污染=1, 间接=2
#   (d) 污点置信度衰减: 每经过一次 mov/运算传播, 置信度乘以衰减因子
#       (默认 0.85) -- 间接污点的分支更可能是良性而非可利用路径
#
# 与现有模块的关系:
# subreg_taint: 提供字节级污点状态 (数据源)
# PathDiversityTracker: 提供路径空间多样性评分 (竞争者)
# 本模块: 提供基于污点的优先级修正因子 (与多样性评分正交)
#     最终优先级 = diversity_score * 0.6 + taint_score * 0.4
#     权重可调--当前 0.6/0.4 基于 CTF pwn 题的初步调试
#
# 文献:
# Caballero et al. "基于污点追踪的二进制代码提取."
# USENIX Security 2009. 奠基性动态污点工作, 但仅追踪到二进制层
#   FIE - 固件符号执行,
#     提出基于外设访问的路径优先级, 但未使用字节级污点
#   字节级寄存器污点与符号执行路径优先级关联:
# 污点粒度 (1 byte) -> 约束相关性 -> 路径优先级
#
# 边界条件与风险:
# 污点状态快照的内存开销: 每条路径 ~64B (16个通用寄存器 * 8槽位)
#     对 1000 路径约 64KB, 可忽略
#   - 若 subreg_taint 未激活, 本模块降级为均匀优先级 (所有路径 score=0)
# 间接污点链的跳数计算是保守近似: 真实跳数可能需要
#     指令级数据依赖分析, 当前用寄存器写-读链的 BFS 估计

from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import deque


# 数据结构

@dataclass
class TaintSnapshot:
    """单条路径在某执行点的寄存器污点快照"""
    path_id: str
    # reg_name -> [slot0.slot7 的污染置信度 0.0-1.0]
    reg_taint: Dict[str, List[float]] = field(default_factory=dict)
    # 内存地址 -> 污染置信度
    mem_taint: Dict[int, float] = field(default_factory=dict)
    # 污点传播跳数估计 (从原始输入到当前状态)
    propagation_depth: int = 1


@dataclass
class TaintPriorityScore:
    """一条路径的污点优先级评分"""
    path_id: str
    taint_score: float  # [0, 1]
    tainted_registers: List[str]  # 哪些寄存器被污染
    propagation_depth: int
    constraint_overlap_count: int  # 约束中引用被污染寄存器的次数


# 核心类

class TaintConstrainedExplorer:
    """基于污点信息的符号执行路径优先级调整器

    用法:
    explorer = TaintConstrainedExplorer()
    快照 = explorer.capture_taint(path_id, subreg_st)
    score = explorer.score_path(快照, path_constraints)
    # 将 score.taint_score 作为 PathDiversityTracker 优先级的修正因子
    """

    # x86-64 通用寄存器集合, 与 subreg_taint._REG_SLOT_MAP 一致
    _GP_REGS = {
        'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
        'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
    }
    # 子寄存器 -> 父寄存器映射 (常用子集)
    _SUBREG_TO_PARENT = {
        'EAX': 'RAX', 'AX': 'RAX', 'AL': 'RAX', 'AH': 'RAX',
        'EBX': 'RBX', 'BX': 'RBX', 'BL': 'RBX', 'BH': 'RBX',
        'ECX': 'RCX', 'CX': 'RCX', 'CL': 'RCX', 'CH': 'RCX',
        'EDX': 'RDX', 'DX': 'RDX', 'DL': 'RDX', 'DH': 'RDX',
        'ESI': 'RSI', 'SI': 'RSI', 'SIL': 'RSI',
        'EDI': 'RDI', 'DI': 'RDI', 'DIL': 'RDI',
        'EBP': 'RBP', 'BP': 'RBP', 'BPL': 'RBP',
        'ESP': 'RSP', 'SP': 'RSP', 'SPL': 'RSP',
        'R8D': 'R8', 'R8W': 'R8', 'R8B': 'R8',
        'R9D': 'R9', 'R9W': 'R9', 'R9B': 'R9',
        'R10D': 'R10', 'R10W': 'R10', 'R10B': 'R10',
        'R11D': 'R11', 'R11W': 'R11', 'R11B': 'R11',
        'R12D': 'R12', 'R12W': 'R12', 'R12B': 'R12',
        'R13D': 'R13', 'R13W': 'R13', 'R13B': 'R13',
        'R14D': 'R14', 'R14W': 'R14', 'R14B': 'R14',
        'R15D': 'R15', 'R15W': 'R15', 'R15B': 'R15',
    }

    def __init__(self,
                 taint_decay_factor: float = 0.85,
                 direct_taint_weight: float = 1.0,
                 indirect_taint_weight: float = 0.6):
        """
        taint_decay_factor: 每次间接传播时污点置信度的衰减因子
        direct_taint_weight: 直接污染 (输入直接流入寄存器) 的权重
        indirect_taint_weight: 间接污染 (经过运算/内存中转) 的权重
        """
        self._decay = taint_decay_factor
        self._direct_weight = direct_taint_weight
        self._indirect_weight = indirect_taint_weight

    # 污点快照捕获

    def capture_taint(self, path_id: str,
                      subreg_state) -> TaintSnapshot:
        """从 SubRegTaintSt 捕获当前路径的寄存器污点快照

        subreg_st 需实现 read_reg(reg_name) -> TaintSet 接口
        不直接 import subreg_taint 以保持模块松耦合--
        任何实现了 read_reg/read_mem 接口的对象均可作为数据源
        """
        snapshot = TaintSnapshot(path_id=path_id)
        for reg in sorted(self._GP_REGS):
            try:
                ts = subreg_state.read_reg(reg)
                # 将 TaintSet 转换为 8 个槽位的置信度列表
                slots = self._taintset_to_slots(ts)
                if any(s > 0.0 for s in slots):
                    snapshot.reg_taint[reg] = slots
            except (AttributeError, KeyError):
                pass

        # 通过子寄存器粒度访问获取实际槽位级别的污点分布
        # subreg_taint 的 read_reg 返回合并后的 TaintSet
        # 我们额外尝试逐字节读取以获取更细粒度的槽位信息
        for subreg, parent in self._SUBREG_TO_PARENT.items():
            try:
                ts = subreg_state.read_reg(subreg)
                slots = self._taintset_to_slots(ts)
                if any(s > 0.0 for s in slots):
                    if parent not in snapshot.reg_taint:
                        snapshot.reg_taint[parent] = [0.0] * 8
                    # 将子寄存器的污点合并到父寄存器的对应槽位
                    parent_slots = snapshot.reg_taint[parent]
                    for i, s in enumerate(slots):
                        if s > parent_slots[i]:
                            parent_slots[i] = s
            except (AttributeError, KeyError):
                pass

        return snapshot

    @staticmethod
    def _taintset_to_slots(taint_set) -> List[float]:
        """将 TaintSet 转换为 8 槽位置信度列表"""
        slots = [0.0] * 8
        if taint_set is None or not hasattr(taint_set, 'tags'):
            return slots
        # 单个 TaintSet 覆盖所有 8 槽位, 取最高置信度
        max_conf = 0.0
        for tag in taint_set.tags.values():
            if hasattr(tag, 'conf'):
                max_conf = max(max_conf, tag.conf)
        if max_conf > 0.0:
            for i in range(8):
                slots[i] = max_conf
        return slots

    # 污点优先级评分

    def score_path(self, snapshot: TaintSnapshot,
                   constraints: List[str]) -> TaintPriorityScore:
        """计算路径的污点优先级评分

        算法:
        1. 从约束字符串中提取所有引用的寄存器名
        2. 检查这些寄存器在污点快照中是否被污染
        3. 加权求和: 直接污染寄存器 * direct_weight +
        间接污染寄存器 * indirect_weight * decay^depth
        4. 归一化到 [0, 1]
        """
        if not constraints or not snapshot.reg_taint:
            return TaintPriorityScore(
                path_id=snapshot.path_id, taint_score=0.0,
                tainted_registers=[], propagation_depth=snapshot.propagation_depth,
                constraint_overlap_count=0,
            )

        # 从约束中提取寄存器引用
        constraint_regs: Set[str] = set()
        for c in constraints:
            c_upper = c.upper()
            for reg in self._GP_REGS:
                if reg in c_upper:
                    constraint_regs.add(reg)
            for subreg, parent in self._SUBREG_TO_PARENT.items():
                if subreg in c_upper:
                    constraint_regs.add(parent)

        if not constraint_regs:
            return TaintPriorityScore(
                path_id=snapshot.path_id, taint_score=0.0,
                tainted_registers=[], propagation_depth=snapshot.propagation_depth,
                constraint_overlap_count=0,
            )

        # 3: 检查重合并加权
        tainted_regs: List[str] = []
        total_score = 0.0
        overlap_count = 0
        depth = max(1, snapshot.propagation_depth)
        decay = self._decay ** (depth - 1)

        for reg in constraint_regs:
            if reg in snapshot.reg_taint:
                slots = snapshot.reg_taint[reg]
                avg_taint = sum(slots) / len(slots) if slots else 0.0
                if avg_taint > 0.0:
                    tainted_regs.append(reg)
                    overlap_count += 1
                    # 直接污染 vs 间接污染的权重区分
                    weight = (self._direct_weight if depth == 1
                             else self._indirect_weight * decay)
                    total_score += avg_taint * weight

        # 归一化
        max_possible = len(constraint_regs) * self._direct_weight
        norm_score = min(1.0, total_score / max(max_possible, 1e-9))

        return TaintPriorityScore(
            path_id=snapshot.path_id,
            taint_score=round(norm_score, 4),
            tainted_registers=tainted_regs,
            propagation_depth=depth,
            constraint_overlap_count=overlap_count,
        )

    # 路径优先级融合

    @staticmethod
    def fuse_priority(diversity_score: float, taint_score: float,
                       diversity_weight: float = 0.6) -> float:
        """将多样性评分和污点评分融合为最终优先级

        diversity_weight: 多样性评分的权重 (0.0-1.0)
        剩余权重归污点评分。当前默认 0.6 基于 CTF pwn 题的初步调试
        后续需要对各类二进制做系统化的权重扫描

        返回 [0, 1] 区间的融合评分
        """
        return diversity_score * diversity_weight + taint_score * (1.0 - diversity_weight)

    # 批量评分, 用于路径调度器

    def rank_paths(self,
                   snapshots: Dict[str, TaintSnapshot],
                   constraints_map: Dict[str, List[str]],
                   diversity_scores: Optional[Dict[str, float]] = None,
                   top_k: int = 10) -> List[Tuple[str, float]]:
        """对多条路径按融合优先级排序

        返回 [(path_id, fused_score),.] 降序排列
        """
        scored = []
        for pid, snap in snapshots.items():
            cons = constraints_map.get(pid, [])
            ts = self.score_path(snap, cons)
            div = (diversity_scores.get(pid, 0.5) if diversity_scores
                   else 0.5)  # 默认中等多样性评分
            fused = self.fuse_priority(div, ts.taint_score)
            scored.append((pid, round(fused, 4)))

        scored.sort(key=lambda x: -x[1])
        return scored[:top_k]
