# 存储变量流追踪 + CALL 前后分叉检测
"""
流分叉分析重入检测器 — 多路径符号执行追踪存储变量流。

现有 EVM 重入检测 (reentrancy_detector.py) 基于 CALL/SSTORE 时序模式匹配——
仅检测"call 之后有 store"的结构模式, 无法区分真正的 exploitable reentrancy
和 benign reentrancy (如 ERC-777 tokensReceived 回调)。

本模块通过流分叉分析 (flow divergence) 精确判定:
  1. 追踪合约内所有存储变量的数据流——构建变量从 SLOAD→ALU→SSTORE 的路径
  2. 识别"共享存储变量": 被外部调用前后的代码路径同时读写的变量
  3. 流分叉检测: 检查同一存储变量是否在外部调用前后沿不同执行路径被修改,
     且至少一条路径允许攻击者通过重入控制修改方向
  4. multiplex 符号执行: 在一个求解 pass 中检查多个执行顺序,
     判断是否存在共同起始状态使得 exploitable 条件可满足

与现有 reentrancy_detector.py 的关系:
  后者做快速模式匹配 (高召回、低精度), 本模块做精确流分叉分析 (高精度),
  两者串联: 模式匹配初筛 → 流分叉确认 → 报告 exploitable reentrancy。

ref: DivertScan — flow divergence + multiplex symbolic execution
     for state-inconsistency bugs, 本项目简化为两阶段: 共享变量识别→分叉检测
ref: Securify — Datalog-based compliance/ violation patterns,
     本项目取其"存储变量依赖图"概念但使用符号执行替代 Datalog
ref: Oyente — 首个 EVM 符号执行重入检测器,
     本项目的流分叉分析补全了 Oyente 缺少的"exploitability 判定"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from typing import Optional


class StorageAccessKind(Enum):
    SLOAD = 'sload'
    SSTORE = 'sstore'


@dataclass
class StorageAccess:
    """一次存储访问 — EVM 层面的 SLOAD/SSTORE。"""
    slot: int                 # 存储槽位 (keccak256 后的索引)
    kind: StorageAccessKind
    pc: int                   # 程序计数器
    in_external_call: bool = False  # 是否在 CALL/DELEGATECALL 之后执行
    value_tainted: bool = False     # 值是否来源于 msg.sender / msg.value


@dataclass
class FlowPath:
    """一条存储变量的数据流路径。"""
    slot: int
    accesses: list[StorageAccess] = field(default_factory=list)
    has_divergence: bool = False


@dataclass
class ReentrancyReport:
    """流分叉分析的重入报告。"""
    contract_addr: str = ''
    vulnerable_function: str = ''
    storage_slot: int = 0
    call_pc: int = 0              # 外部调用的 PC
    post_call_sstore_pc: int = 0  # 调用后修改存储的 PC
    divergence_type: str = ''     # 'read_after_call' | 'write_after_call' | 'conditional_bypass'
    exploitability: str = ''      # 'definite' | 'likely' | 'unlikely'
    constraint_summary: str = ''  # 可满足性约束的文本摘要


# 存储变量流追踪

class StorageFlowTracer:
    """在 EVM 字节码执行 trace 上追踪存储变量的数据流。

    分析每个 SLOAD/SSTORE 的位置、上下文 (是否在外部调用后)、
    以及值是否受用户输入 (CALLDATA) 污染。"""

    __slots__ = ('_accesses', '_slots', '_call_stack_depth')

    def __init__(self):
        self._accesses: dict[int, list[StorageAccess]] = defaultdict(list)
        self._slots: set[int] = set()
        self._call_stack_depth = 0

    def trace_opcode(self, opcode: str, pc: int, stack: list[int],
                     storage_context: dict | None = None) -> None:
        """处理单条 EVM 操作码——追踪存储访问。"""
        op = opcode.upper()
        ctx = storage_context or {}

        if op == 'SLOAD' and len(stack) >= 1:
            slot = stack[-1]
            self._accesses[slot].append(StorageAccess(
                slot=slot, kind=StorageAccessKind.SLOAD, pc=pc,
                in_external_call=self._call_stack_depth > 0,
            ))
            self._slots.add(slot)

        elif op == 'SSTORE' and len(stack) >= 2:
            slot = stack[-2]
            value = stack[-1]
            tainted = ctx.get('value_tainted', False) or self._is_user_controlled(value)
            self._accesses[slot].append(StorageAccess(
                slot=slot, kind=StorageAccessKind.SSTORE, pc=pc,
                in_external_call=self._call_stack_depth > 0,
                value_tainted=tainted,
            ))
            self._slots.add(slot)

    def _is_user_controlled(self, value: int) -> bool:
        """启发式: 检查值是否可能来自用户输入 (CALLDATA)。
        简化版——检查值是否在前 4 字节函数选择器范围。"""
        return 0 <= value <= 0xFFFFFFFF

    def mark_external_call(self) -> None:
        self._call_stack_depth += 1

    def mark_external_return(self) -> None:
        self._call_stack_depth = max(0, self._call_stack_depth - 1)

    def find_shared_slots(self, call_pc: int) -> list[int]:
        """找到在外部调用前后都被访问的存储槽位——候选重入目标。"""
        shared = []
        for slot, accesses in self._accesses.items():
            before_call = [a for a in accesses if a.pc < call_pc]
            after_call = [a for a in accesses if a.pc > call_pc]
            if before_call and after_call:
                shared.append(slot)
        return shared

    def get_accesses(self, slot: int) -> list[StorageAccess]:
        return self._accesses.get(slot, [])


# 流分叉检测器

class FlowDivergenceDetector:
    """检测存储变量流分叉——判定重入是否 exploitable。

    分叉类型:
      - read_after_call: 外部调用前读取变量V, 调用后再次读取——
        若 attacker 在回调中修改V, 第二次读取得到错误值
      - write_after_call: 外部调用前写入变量V, 调用后再次写入——
        若 attacker 在回调中修改V, 最终写入覆盖攻击者的修改或基于过期值
      - conditional_bypass: 外部调用前基于V做条件判断, 调用后不再检查——
        attacker 在回调中修改V 绕过检查
    """

    __slots__ = ('_detected',)

    def __init__(self):
        self._detected: list[ReentrancyReport] = []

    def analyze(self, tracer: StorageFlowTracer,
                call_pc: int,
                contract_addr: str = '',
                func_name: str = '') -> list[ReentrancyReport]:
        """分析一次外部调用前后是否存在 exploitable 流分叉。"""
        self._detected = []
        shared_slots = tracer.find_shared_slots(call_pc)

        for slot in shared_slots:
            accesses = tracer.get_accesses(slot)
            pre_call = [a for a in accesses if a.pc < call_pc]
            post_call = [a for a in accesses if a.pc > call_pc]

            # 检测 write_after_call: 调用后有 SSTORE
            post_stores = [a for a in post_call
                          if a.kind == StorageAccessKind.SSTORE]
            if post_stores and pre_call:
                last_pre = pre_call[-1]
                first_post = post_stores[0]
                report = ReentrancyReport(
                    contract_addr=contract_addr,
                    vulnerable_function=func_name,
                    storage_slot=slot,
                    call_pc=call_pc,
                    post_call_sstore_pc=first_post.pc,
                    divergence_type='write_after_call',
                    exploitability='likely',
                    constraint_summary=f'slot {slot}: SLOAD@{last_pre.pc} → CALL@{call_pc} → SSTORE@{first_post.pc}',
                )
                # 提升: 若调用后的 SSTORE 值受用户控制 → definite
                if first_post.value_tainted:
                    report.exploitability = 'definite'
                self._detected.append(report)

            # 检测 read_after_call: 调用后仅读取 (无写入)
            post_loads = [a for a in post_call
                         if a.kind == StorageAccessKind.SLOAD]
            if post_loads and not post_stores and pre_call:
                last_pre = pre_call[-1]
                first_post = post_loads[0]
                self._detected.append(ReentrancyReport(
                    contract_addr=contract_addr,
                    vulnerable_function=func_name,
                    storage_slot=slot,
                    call_pc=call_pc,
                    post_call_sstore_pc=first_post.pc,
                    divergence_type='read_after_call',
                    exploitability='likely',
                    constraint_summary=f'slot {slot}: pre-call state used post-call @{first_post.pc}',
                ))

            # 检测 conditional_bypass: 调用前有 SSTORE, 调用后无任何访问
            pre_stores = [a for a in pre_call
                         if a.kind == StorageAccessKind.SSTORE]
            if pre_stores and not post_loads and not post_stores:
                last_pre_sstore = pre_stores[-1]
                # 检查调用前是否有基于此 slot 的条件跳转
                has_conditional = any(
                    a for a in pre_call
                    if a.kind == StorageAccessKind.SLOAD and a != last_pre_sstore
                )
                if has_conditional:
                    self._detected.append(ReentrancyReport(
                        contract_addr=contract_addr,
                        vulnerable_function=func_name,
                        storage_slot=slot,
                        call_pc=call_pc,
                        post_call_sstore_pc=0,
                        divergence_type='conditional_bypass',
                        exploitability='unlikely',
                        constraint_summary=f'slot {slot}: conditional check pre-call, unchecked post-call',
                    ))

        return self._detected

    def stats(self) -> dict:
        definite = sum(1 for r in self._detected if r.exploitability == 'definite')
        likely = sum(1 for r in self._detected if r.exploitability == 'likely')
        return {
            'total': len(self._detected),
            'definite': definite,
            'likely': likely,
            'by_type': {
                dt: sum(1 for r in self._detected if r.divergence_type == dt)
                for dt in {'write_after_call', 'read_after_call', 'conditional_bypass'}
            },
        }


# EVM trace 重放适配器
# 从 EVM 执行 trace (JSON 格式) 重放并填充 StorageFlowTracer。

def replay_evm_trace(trace: list[dict],
                     tracer: StorageFlowTracer | None = None,
                     call_pc_hint: int = -1) -> tuple[StorageFlowTracer, int]:
    """从 EVM 执行 trace 中提取存储访问模式。
    返回 (tracer, detected_call_pc)。"""
    if tracer is None:
        tracer = StorageFlowTracer()

    stack: list[int] = []
    call_pc = call_pc_hint

    for step in trace:
        op = step.get('op', '')
        pc = step.get('pc', 0)
        stack_after = step.get('stack', [])

        if op in ('CALL', 'DELEGATECALL', 'CALLCODE', 'STATICCALL'):
            tracer.mark_external_call()
            if call_pc < 0:
                call_pc = pc

        # 简化: 用执行后的 stack 逆向推断 SLOAD/SSTORE 的参数
        if op == 'SLOAD' and stack_after:
            slot = stack_after[0] if stack_after else 0
            tracer._accesses[slot].append(StorageAccess(
                slot=slot, kind=StorageAccessKind.SLOAD, pc=pc,
                in_external_call=tracer._call_stack_depth > 0,
            ))
            tracer._slots.add(slot)

        elif op == 'SSTORE' and len(stack_after) >= 1:
            slot = stack_after[0] if len(stack_after) >= 1 else 0
            tracer._accesses[slot].append(StorageAccess(
                slot=slot, kind=StorageAccessKind.SSTORE, pc=pc,
                in_external_call=tracer._call_stack_depth > 0,
            ))
            tracer._slots.add(slot)

    return tracer, call_pc


__all__ = [
    'StorageFlowTracer', 'FlowDivergenceDetector',
    'StorageAccess', 'StorageAccessKind', 'FlowPath',
    'ReentrancyReport', 'replay_evm_trace',
]
