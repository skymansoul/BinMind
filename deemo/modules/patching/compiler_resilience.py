"""
编译器优化弹性测试器 (Compiler Optimization Resilience Tester, CORT)

验证补丁在不同编译优化级别下的一致性, 检测优化引入的语义变化.

设计依据:
  二进制补丁通常基于特定优化级别 (-O0 或 -O2) 生成.
  同一补丁在不同优化级别下可能产生不同的机器码:
    - -O0: 保留冗余指令, 补丁空间充裕
    - -O2: 指令重排/内联, 补丁可能破坏优化假设
    - -Os: 代码尺寸优先, 跳转偏移可能越界
  现有补丁工具 (VeriBin, RetSpill) 不测试跨优化级别的弹性.

  CORT 模拟不同优化级别的效果:
    1. 指令重排 (模拟 -O2 的调度效果)
    2. 寄存器重分配 (模拟寄存器分配器的不同选择)
    3. 跳转偏移变化 (模拟代码尺寸变化)
    对补丁区域施加这些变换后重新验证功能等价性.
"""
import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class OptimizationTransform:
    """模拟的优化变换."""
    name: str            # 'reorder' | 'reallocate' | 'resize_jumps'
    description: str
    applicable: bool = True
    risk_score: float = 0.0  # 0-1, 该变换对补丁的破坏风险


@dataclass
class ResilienceReport:
    """弹性测试报告."""
    optimization_level: str
    is_resilient: bool
    transformations_applied: List[str] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)
    risk_score: float = 0.0


class CompilerResilienceTester:
    """编译器优化弹性测试器.

    用法:
      crt = CompilerResilienceTester(verify_fn)
      # verify_fn: 接受补丁字节 → bool (功能是否正常)
      report = crt.test(patch_bytes, patch_context)
    """

    def __init__(self, verify_fn: Callable[[bytes], bool]):
        self._verify = verify_fn
        self._transforms = self._define_transforms()

    def _define_transforms(self) -> List[OptimizationTransform]:
        return [
            OptimizationTransform(
                'nop_sled_removal',
                '移除 NOP sled — 模拟 -Os 尺寸优化',
                risk_score=0.1,
            ),
            OptimizationTransform(
                'register_renumber',
                '寄存器重编号 — 模拟寄存器分配器差异',
                risk_score=0.4,
            ),
            OptimizationTransform(
                'jump_offset_shift',
                '跳转偏移 ±8 字节扰动 — 模拟代码布局变化',
                risk_score=0.5,
            ),
            OptimizationTransform(
                'instruction_reschedule',
                '相邻独立指令交换 — 模拟 -O2 指令调度',
                risk_score=0.6,
            ),
        ]

    def test(self, patch_bytes: bytes,
             context: Optional[Dict[str, Any]] = None) -> List[ResilienceReport]:
        """测试补丁在各模拟优化级别下的弹性."""
        reports = []
        context = context or {}

        for level_name, transforms in [
            ('-O0_baseline', []),
            ('-Os_simulated', ['nop_sled_removal', 'jump_offset_shift']),
            ('-O2_simulated', ['register_renumber', 'instruction_reschedule',
                               'jump_offset_shift']),
        ]:
            current = patch_bytes
            applied = []
            failures = []
            for t in self._transforms:
                if t.name in transforms:
                    current = self._apply_transform(current, t, context)
                    applied.append(t.name)
            # 验证变换后的补丁
            is_ok = self._verify(current)
            if not is_ok:
                failures.append('verification_failed')

            risk = self._compute_risk(applied, failures)
            reports.append(ResilienceReport(
                optimization_level=level_name,
                is_resilient=is_ok,
                transformations_applied=applied,
                failures=failures,
                risk_score=round(risk, 3),
            ))
        return reports

    def _apply_transform(self, data: bytes, transform: OptimizationTransform,
                         context: Dict[str, Any]) -> bytes:
        """对补丁字节应用模拟优化变换."""
        buf = bytearray(data)
        if transform.name == 'nop_sled_removal':
            # 移除连续的 0x90 (NOP) 序列, 仅保留一个
            result = bytearray()
            i = 0
            while i < len(buf):
                if buf[i] == 0x90:
                    result.append(0x90)
                    while i < len(buf) and buf[i] == 0x90:
                        i += 1
                else:
                    result.append(buf[i])
                    i += 1
            return bytes(result)

        elif transform.name == 'register_renumber':
            # 将寄存器编码在合法范围内循环偏移
            # x86 ModR/M 字节: mod(2) + reg(3) + rm(3)
            for i in range(len(buf)):
                b = buf[i]
                # 检测 ModR/M 模式 (简化启发式: 0xC0-0xFF 范围)
                if 0xC0 <= b <= 0xFF:
                    reg_field = (b >> 3) & 0x07
                    rm_field = b & 0x07
                    # 交换 reg 和 rm (模拟寄存器重分配)
                    new_b = (b & 0xC0) | (rm_field << 3) | reg_field
                    buf[i] = new_b
            return bytes(buf)

        elif transform.name == 'jump_offset_shift':
            # 跳转偏移 ±4 字节扰动
            for i in range(len(buf) - 4):
                if buf[i] in (0xEB, 0xE9, 0x0F):  # JMP/Jcc 操作码
                    offset_pos = i + 1 if buf[i] != 0x0F else i + 2
                    if offset_pos + 3 < len(buf):
                        shift = random.choice([-4, -2, 2, 4])
                        # 仅扰动非零偏移
                        if buf[offset_pos:offset_pos+4] != b'\x00\x00\x00\x00':
                            val = int.from_bytes(
                                buf[offset_pos:offset_pos+4], 'little', signed=True
                            )
                            val += shift
                            buf[offset_pos:offset_pos+4] = val.to_bytes(
                                4, 'little', signed=True
                            )
            return bytes(buf)

        elif transform.name == 'instruction_reschedule':
            # 交换相邻的独立指令对 (简化: 交换相邻 4 字节块)
            for i in range(0, len(buf) - 8, 8):
                if random.random() < 0.3:
                    a = buf[i:i+4]
                    b = buf[i+4:i+8]
                    buf[i:i+4] = b
                    buf[i+4:i+8] = a
            return bytes(buf)

        return bytes(buf)

    def _compute_risk(self, applied: List[str], failures: List[str]) -> float:
        base_risk = sum(
            t.risk_score for t in self._transforms if t.name in applied
        ) / max(1, len(applied)) if applied else 0.0
        if failures:
            base_risk += 0.3
        return min(1.0, base_risk)

    def recommend_mitigation(self, reports: List[ResilienceReport]) -> str:
        """基于弹性测试报告推荐缓解措施."""
        failed = [r for r in reports if not r.is_resilient]
        if not failed:
            return '补丁在所有模拟优化级别下保持语义等价'
        levels = [r.optimization_level for r in failed]
        return (
            f'补丁在 {", ".join(levels)} 下失效. '
            f'建议: 避免依赖特定寄存器分配, 使用位置无关的跳转编码'
        )
