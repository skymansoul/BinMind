# 执行反馈驱动的语法精炼器 — 在线学习输入有效性约束
#
# 核心问题:
#   grammar_infer.py 从静态样本推断语法——样本集决定了语法质量。
#   若样本不全 (缺少某些消息类型、未覆盖所有字段组合), 推断的语法
#   生成的大部分输入会被程序拒绝, fuzzing效率极低。
#
#   传统方案需要人工提供更全面的样本——在二进制逆向场景不可行。
#
# 本模块的方法 — 执行反馈闭环:
#   1. 从初始语法生成一批输入
#   2. 执行每个输入, 观察程序的拒绝信号:
#      - 退出码非零
#      - stderr 含特定错误消息
#      - 程序在特定偏移处崩溃
#      - 覆盖边数显著少于其他输入 (提前退出)
#   3. 从拒绝信号中提取约束信息:
#      - "输入在偏移4处被拒绝, 期望值=0x7F" → 字节[4]必须为0x7F
#      - "输入长度<8时被拒绝" → min_length = 8
#   4. 将约束反馈回语法——精炼产生式规则
#   5. 迭代直到语法收敛 (生成输入的接受率 > 阈值)
#
# 精炼操作集:
#   - NARROW_RANGE: 缩小某字段的合法值范围
#   - ADD_CONSTRAINT: 添加新字段约束 (如 magic bytes)
#   - SPLIT_RULE: 将过于宽泛的规则拆分为多个具体规则
#   - SET_MIN_LENGTH: 设置最小长度约束
#
# 参考文献:
#   AFLSmart (Pham et al. CCS 2018) — grammar-based fuzzing with Peach;
#     本项目取其语法驱动生成思想但以执行反馈替代手动编写语法
#   Nautilus (Aschermann et al. NDSS 2019) — grammar feedback via
#     parse tree mutations; 本项目取其反馈思想但以约束精炼替代树变异

from __future__ import annotations

import hashlib
import math
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class RefineOp(str, Enum):
    """语法精炼操作"""
    NARROW_RANGE = "narrow_range"        # 收窄合法值范围
    ADD_MAGIC = "add_magic"              # 添加固定值约束 (magic bytes)
    SET_MIN_LENGTH = "set_min_length"    # 设置最小长度
    SET_MAX_LENGTH = "set_max_length"    # 设置最大长度
    SPLIT_FIELD = "split_field"          # 拆分字段为子字段
    NO_OP = "no_op"


@dataclass
class FieldConstraint:
    """单条字段级约束"""
    offset: int                         # 字段起始偏移
    size: int                           # 字段大小 (字节)
    # 值约束
    allowed_values: Optional[Set[int]] = None  # 允许的值集合
    min_value: int = 0
    max_value: int = 255
    is_magic: bool = False              # 是否为固定magic值
    # 关系约束
    depends_on_field: int = -1          # 依赖的字段偏移 (如length字段)
    is_length_field: bool = False       # 是否为长度字段
    # 统计
    confidence: float = 0.5
    rejection_count: int = 0
    accept_count: int = 0


@dataclass
class ExecutionFeedback:
    """单次执行的结构化反馈"""
    input_data: bytes
    # 程序响应
    exit_code: int = 0
    stderr_text: str = ""
    crashed: bool = False
    crash_offset: int = -1              # 崩溃/拒绝的输入偏移 (-1=未知)
    # 覆盖
    covered_edges: int = 0
    # 元信息
    rejected: bool = False              # 程序是否拒绝了此输入
    rejection_reason: str = ""
    execution_time_ms: float = 0.0


@dataclass
class RefinementReport:
    """一轮精炼的报告"""
    round_idx: int
    inputs_generated: int
    inputs_accepted: int
    acceptance_rate: float = 0.0
    refine_ops_applied: List[RefineOp] = field(default_factory=list)
    constraints_modified: int = 0
    new_constraints: int = 0
    summary: str = ""


class ExecGrammarRefiner:
    """执行反馈驱动的语法精炼器。

    典型用法:
        refiner = ExecGrammarRefiner(min_input_size=4, max_input_size=4096)

        # 定义执行器: 给定输入, 返回 ExecutionFeedback
        def executor(data: bytes) -> ExecutionFeedback:
            result = run_program(data)
            return ExecutionFeedback(
                input_data=data, exit_code=result.ec,
                stderr_text=result.stderr, rejected=(result.ec != 0))

        # 迭代精炼
        for round_idx in range(20):
            report = refiner.refine_round(executor, batch_size=50)
            if report.acceptance_rate >= 0.95:
                break  # 收敛
    """

    def __init__(self,
                 min_input_size: int = 1,
                 max_input_size: int = 4096,
                 convergence_threshold: float = 0.90,
                 max_rounds: int = 50):
        self._min_size = min_input_size
        self._max_size = max_input_size
        self._conv_threshold = convergence_threshold
        self._max_rounds = max_rounds

        # 字段约束: offset → FieldConstraint
        self._constraints: Dict[int, FieldConstraint] = {}
        # 全局长度约束
        self._global_min_len = min_input_size
        self._global_max_len = max_input_size
        # 精炼历史
        self._reports: List[RefinementReport] = []
        self._round = 0
        # 收敛追踪
        self._consecutive_improvements = 0
        self._best_acceptance = 0.0

    def add_initial_constraint(self, offset: int, size: int,
                                 allowed: Optional[Set[int]] = None,
                                 min_val: int = 0, max_val: int = 255,
                                 ) -> None:
        """添加初始约束——来自 grammar_infer 或手动指定"""
        self._constraints[offset] = FieldConstraint(
            offset=offset, size=size,
            allowed_values=allowed, min_value=min_val, max_value=max_val,
        )

    def generate_input(self, rng_seed: Optional[int] = None) -> bytes:
        """从当前约束生成一个合法输入。

        生成策略:
          - 全局长度在 [global_min, global_max] 内随机
          - 每个约束字段按 allowed/min-max 随机填值
          - 无约束的字节随机填充
        """
        import random as _rnd
        rng = _rnd.Random(rng_seed)

        size = rng.randint(self._global_min_len, self._global_max_len)
        data = bytearray(size)

        # 填充所有约束字段
        covered: Set[int] = set()
        for off, fc in self._constraints.items():
            end = min(off + fc.size, size)
            for i in range(off, end):
                if fc.allowed_values:
                    data[i] = rng.choice(list(fc.allowed_values))
                else:
                    data[i] = rng.randint(fc.min_value, fc.max_value)
                covered.add(i)

        # 填充无约束的字节 (随机)
        for i in range(size):
            if i not in covered:
                data[i] = rng.randint(0, 255)

        return bytes(data)

    def refine_round(self,
                      executor: Callable[[bytes], ExecutionFeedback],
                      batch_size: int = 50,
                      ) -> RefinementReport:
        """执行一轮精炼: 生成batch_size个输入 → 执行 → 分析反馈 → 更新约束"""
        self._round += 1
        import random as _rnd
        rng = _rnd.Random(self._round)

        # Phase 1: 生成并执行
        feedbacks: List[ExecutionFeedback] = []
        for _ in range(batch_size):
            inp = self.generate_input(rng_seed=rng.randint(0, 2**31 - 1))
            try:
                fb = executor(inp)
            except Exception as exc:
                fb = ExecutionFeedback(
                    input_data=inp, rejected=True,
                    rejection_reason=str(exc))
            feedbacks.append(fb)

        # Phase 2: 分析拒绝模式
        accepted = [f for f in feedbacks if not f.rejected]
        rejected = [f for f in feedbacks if f.rejected]
        acceptance_rate = len(accepted) / max(1, batch_size)

        ops_applied: List[RefineOp] = []
        constraints_modified = 0
        new_constraints = 0

        # Phase 3: 差分执行分析 (语言无关) + 拒绝消息解析 (补充)
        if accepted and rejected:
            diff_ops = self._learn_from_differential(accepted, rejected)
            ops_applied.extend(diff_ops)
            if diff_ops:
                constraints_modified += 1
        # 补充: 从英文错误消息中提取精确值约束
        for fb in rejected:
            ops = self._learn_from_rejection(fb)
            ops_applied.extend(ops)
            if ops:
                constraints_modified += 1

        # Phase 4: 收敛性检查——若接受率高于阈值, 尝试收窄全局约束
        if acceptance_rate >= 0.5 and self._global_max_len > self._global_min_len + 16:
            # 若所有接受输入的size都 < 当前max的80%, 则收窄max
            accepted_sizes = [len(f.input_data) for f in accepted]
            if accepted_sizes:
                avg = sum(accepted_sizes) / len(accepted_sizes)
                if avg < self._global_max_len * 0.6:
                    self._global_max_len = max(
                        self._global_min_len + 16,
                        int(avg * 1.5))
                    ops_applied.append(RefineOp.SET_MAX_LENGTH)

        # Phase 5: 长度不足 → 提升最小长度
        too_short = [f for f in rejected
                      if 'too short' in f.rejection_reason.lower()
                      or 'minimum length' in f.rejection_reason.lower()]
        if too_short:
            short_sizes = [len(f.input_data) for f in too_short]
            # 提升 global_min_len 到拒绝输入的最大值+1
            new_min = max(short_sizes) + 1
            if new_min > self._global_min_len:
                self._global_min_len = min(new_min, self._global_max_len - 1)
                ops_applied.append(RefineOp.SET_MIN_LENGTH)

        report = RefinementReport(
            round_idx=self._round,
            inputs_generated=batch_size,
            inputs_accepted=len(accepted),
            acceptance_rate=acceptance_rate,
            refine_ops_applied=list(set(ops_applied)),
            constraints_modified=constraints_modified,
            new_constraints=new_constraints,
        )
        report.summary = self._build_round_summary(report)
        self._reports.append(report)

        # 收敛追踪
        if acceptance_rate > self._best_acceptance:
            self._best_acceptance = acceptance_rate
            self._consecutive_improvements += 1
        else:
            self._consecutive_improvements = 0

        return report

    def _learn_from_differential(self,
                                   accepted: List[ExecutionFeedback],
                                   rejected: List[ExecutionFeedback],
                                   ) -> List[RefineOp]:
        """差分执行分析: 比较通过/拒绝输入, 定位约束字节位置。

        核心洞察: 若所有通过输入在偏移K处都是同一字节值B,
        而所有拒绝输入在偏移K处都不是B——则字节K很可能是一个
        必须等于B的magic/type约束。此方法完全语言无关,
        不需要解析程序的错误消息文本。
        """
        ops: List[RefineOp] = []
        if not accepted or not rejected:
            return ops

        # 找到通过和拒绝输入的最小公共长度
        min_acc_len = min(len(f.input_data) for f in accepted)
        min_rej_len = min(len(f.input_data) for f in rejected)
        min_len = min(min_acc_len, min_rej_len)

        # 逐字节比较: 检测"通过输入在该位置一致, 拒绝输入不一致"的位置
        for off in range(min_len):
            # 统计通过输入在偏移off处的字节频率
            acc_counter = Counter()
            for f in accepted:
                if off < len(f.input_data):
                    acc_counter[f.input_data[off]] += 1
            if not acc_counter:
                continue

            # 收集拒绝输入在此位置的字节
            rej_bytes = set()
            for f in rejected:
                if off < len(f.input_data):
                    rej_bytes.add(f.input_data[off])
            if not rej_bytes:
                continue

            # 两种情况:
            # a) 100% 通过输入共享同一字节, 拒绝输入无此字节 → 硬约束
            # b) >=70% 通过输入共享, 拒绝输入无此字节 → 软约束 (低置信度)
            n_acc = len(accepted)
            for byte_val, count in acc_counter.most_common(1):
                ratio = count / n_acc
                if byte_val in rej_bytes:
                    continue
                if ratio >= 0.7:
                    confidence = 0.75 if ratio >= 0.95 else 0.45
                    existing = self._constraints.get(off)
                    if existing is None:
                        self._constraints[off] = FieldConstraint(
                            offset=off, size=1,
                            allowed_values={byte_val}, is_magic=True,
                            confidence=confidence)
                        ops.append(RefineOp.ADD_MAGIC)
                    elif existing.allowed_values is None:
                        existing.allowed_values = {byte_val}
                        existing.is_magic = True
                        existing.confidence = confidence
                        ops.append(RefineOp.ADD_MAGIC)
                    elif byte_val in (existing.allowed_values or set()):
                        # 缩小已有的allowed_values集合
                        existing.allowed_values = {byte_val}
                        existing.confidence = confidence
                        ops.append(RefineOp.NARROW_RANGE)

        # 长度约束: 若所有拒绝输入都短于通过输入
        if min_rej_len < min_acc_len:
            if self._global_min_len < min_acc_len:
                self._global_min_len = min_acc_len
                ops.append(RefineOp.SET_MIN_LENGTH)

        return ops

    def _learn_from_rejection(self, fb: ExecutionFeedback) -> List[RefineOp]:
        """从单次拒绝消息中学习约束——分析stderr (补充差分分析)"""
        ops: List[RefineOp] = []
        reason = fb.rejection_reason.lower()

        # 模式1: "expected 0x?? at offset N" → magic byte
        import re
        magic_match = re.search(
            r'(?:expected|require\w*)\s+(?:0x)?([0-9a-fA-F]+)\s+(?:at|@)\s*(?:offset\s*)?(\d+)',
            reason)
        if magic_match:
            try:
                val = int(magic_match.group(1), 16)
                off = int(magic_match.group(2))
                if off < len(fb.input_data):
                    existing = self._constraints.get(off)
                    if existing is None:
                        self._constraints[off] = FieldConstraint(
                            offset=off, size=1,
                            allowed_values={val}, is_magic=True,
                            confidence=0.6)
                        ops.append(RefineOp.ADD_MAGIC)
                    elif existing.allowed_values is None:
                        existing.allowed_values = {val}
                        existing.is_magic = True
                        ops.append(RefineOp.ADD_MAGIC)
            except (ValueError, IndexError):
                pass

        # 模式2: 长度相关拒绝
        if 'too short' in reason or 'minimum' in reason:
            ops.append(RefineOp.SET_MIN_LENGTH)

        # 模式3: 崩溃在特定偏移 → 该偏移的字节可能是magic/checksum
        if fb.crashed and fb.crash_offset >= 0:
            off = min(fb.crash_offset, len(fb.input_data) - 1)
            existing = self._constraints.get(off)
            if existing is None:
                self._constraints[off] = FieldConstraint(
                    offset=off, size=1,
                    min_value=0, max_value=255, confidence=0.3)

        # 模式4: stderr含"invalid"但接受率低 → 尝试收窄附近约束
        if 'invalid' in reason and fb.input_data:
            # 找到最近的约束字段, 缩小其合法范围
            closest_off = -1
            closest_dist = 999999
            for off in self._constraints:
                dist = abs(off - len(fb.input_data) // 2)
                if dist < closest_dist:
                    closest_dist = dist
                    closest_off = off
            if closest_off >= 0:
                fc = self._constraints[closest_off]
                mid = (fc.min_value + fc.max_value) // 2
                fc.min_value = max(fc.min_value, mid - 32)
                fc.max_value = min(fc.max_value, mid + 32)
                ops.append(RefineOp.NARROW_RANGE)

        return ops

    def has_converged(self) -> bool:
        """检查精炼是否收敛"""
        if not self._reports:
            return False
        last = self._reports[-1]
        return last.acceptance_rate >= self._conv_threshold

    def best_constraints(self) -> List[FieldConstraint]:
        """返回当前最佳约束集 (按偏移排序)"""
        return sorted(self._constraints.values(), key=lambda c: c.offset)

    def stats(self) -> Dict[str, Any]:
        return {
            "rounds": self._round,
            "constraints": len(self._constraints),
            "global_size_range": [self._global_min_len, self._global_max_len],
            "best_acceptance": round(self._best_acceptance, 4),
            "converged": self.has_converged(),
        }

    @staticmethod
    def _build_round_summary(report: RefinementReport) -> str:
        ops_str = ", ".join(o.value for o in report.refine_ops_applied[:5])
        return (f"Round {report.round_idx}: "
                f"{report.inputs_accepted}/{report.inputs_generated} accepted "
                f"({report.acceptance_rate:.1%}), "
                f"ops=[{ops_str or 'none'}]")

    def reset(self) -> None:
        self._constraints.clear()
        self._reports.clear()
        self._round = 0
        self._best_acceptance = 0.0
        self._consecutive_improvements = 0


def refine_until_converge(
    executor: Callable[[bytes], ExecutionFeedback],
    initial_constraints: Optional[Dict[int, FieldConstraint]] = None,
    max_rounds: int = 30, batch_size: int = 40,
    ) -> Tuple[List[FieldConstraint], List[RefinementReport]]:
    """便捷入口: 迭代精炼直到收敛或达到最大轮数"""
    refiner = ExecGrammarRefiner(max_rounds=max_rounds)
    if initial_constraints:
        for off, fc in initial_constraints.items():
            refiner.add_initial_constraint(
                off, fc.size, fc.allowed_values,
                fc.min_value, fc.max_value)

    for _ in range(max_rounds):
        refiner.refine_round(executor, batch_size)
        if refiner.has_converged():
            break

    return refiner.best_constraints(), refiner._reports
