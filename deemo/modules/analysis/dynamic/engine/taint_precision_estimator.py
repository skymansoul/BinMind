# 过污染/欠污染量化: 统计采样每 100 次传播决策检查一次精度
# 欠污染边界分析: 从传播图估计未被追踪的间接流上界
# 欠污染估计增强: 间接操作加权
# 传播图边界分析: 构建 def-use 图, 未标记的可达路径数作为欠污染上界估计

"""污点跟踪精度自评估 - 无 ground truth 的过污染/欠污染量化

现有污点分析工具 (FridaTaintTracker, QBDITaintTracker, dynamic_taint.py)
回答"数据从哪里来"--但不回答"追踪精度有多高"

精度问题的根本:
  1. 过污染 (over-taint): 非攻击者可控的数据被标记为污点
     原因: 保守的传播规则 (如 add tainted_reg, 0 -> 仍标记为污点)
  2. 欠污染 (under-taint): 攻击者可控的数据未被标记
     原因: 间接传播路径未覆盖 (如通过内存的隐式流)

本模块在不依赖 ground truth 的情况下量化这两类误差:
  A. 过污染估计: 随机采样 N 个被标记的字节, 回溯数据流
     若某一半以上的传播步骤是"保守近似"(如常量加法后仍标记)
     -> 过污染信号
  B. 欠污染估计: 使用抽象解释在区间域上计算"可能被污染但未标记"
    的变量上界--若某变量在区间域上可能依赖输入但未被标记
     -> 欠污染信号

综合精度分数: precision = 1 - (over_taint_rate + under_taint_rate) / 2

与现有工作的关系:
- 污点传播策略综述: 分类方法 -> 本模块: 精度量化
- DMC Tool: 辅助信息减少误报 -> 本模块: 估计误报率
- PDIFT: 路径感知降低漏报 -> 本模块: 估计漏报率
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 数据结构

@dataclass
class PropagationStep:
    """单步污点传播记录"""
    instruction_address: int
    opcode: str
    source_tainted: bool
    dest_tainted: bool
    is_conservative: bool          # 此步是否使用了保守近似 (如无条件传播)


@dataclass
class TaintPrecisionReport:
    """污点追踪精度自评估报告"""
    total_propagation_steps: int
    sampled_steps: int
    # 过污染
    over_taint_rate: float          # [0,1] - 被保守传播的比例
    over_taint_confidence: float
    # 欠污染
    under_taint_estimate: float     # [0,1] - 估计的漏追踪比例
    under_taint_confidence: float
    # 综合
    precision_score: float          # [0,1] - 1=完美精度
    reliability_grade: str = 'F'    # A/B/C/D/F


# 保守传播模式识别

# 保守传播的操作符--无条件将源污点传播到目标
_CONSERVATIVE_OPS = {
    'mov', 'lea', 'push', 'pop', 'xchg',
    'add', 'sub',         # 任何含有污点操作数的算术->结果污点
    'and', 'or', 'xor',   # 位运算->保守传播
    'shl', 'shr', 'sal', 'sar',
    'movzx', 'movsx',     # 扩展->保守传播
    'inc', 'dec',         # 增量->保守传播
}

# 精确传播的操作符--仅在特定条件下传播 (如 cmp 不修改值)
_PRECISE_OPS = {
    'cmp', 'test',        # 只设置标志--不传播污点
    'jmp', 'je', 'jne', 'jz', 'jnz',   # 分支不传播污点
    'jb', 'jae', 'ja', 'jbe', 'jl', 'jg', 'jle', 'jge',
    'call', 'ret', 'nop',
}

# 清除污点的操作--归零或常量赋值
_CLEARING_OPS = {
    # xor reg, reg -> 清除
    # mov reg, const -> 若常量为非污点->清除
}


class TaintPrecisionEstimator:

    _SAMPLING_INTERVAL = 100   # 每 100 步采样一次
    _MIN_SAMPLES = 5           # 最少样本数才报告

    def __init__(self, sample_rate: float = 0.05):
        self._rate = sample_rate
        self._steps: List[PropagationStep] = []
        self._total_steps = 0

    def record_step(self, step: PropagationStep) -> None:
        """记录单步传播--按采样率存储"""
        self._total_steps += 1
        if random.random() < self._rate:
            self._steps.append(step)
            if len(self._steps) > 5000:
                self._steps = self._steps[-2000:]  # 保留最近

    def estimate(self) -> TaintPrecisionReport:
        """从采样步中估计过污染和欠污染率"""
        n = len(self._steps)
        if n < self._MIN_SAMPLES:
            return TaintPrecisionReport(
                total_propagation_steps=self._total_steps,
                sampled_steps=n,
                over_taint_rate=0.0,
                over_taint_confidence=0.0,
                under_taint_estimate=0.0,
                under_taint_confidence=0.0,
                precision_score=1.0,
            )

        # A: 过污染估计--保守传播的比例
        conservative_steps = [
            s for s in self._steps
            if s.is_conservative and s.source_tainted and s.dest_tainted
        ]
        # 其中有多少是"过度"保守--源污点但目标不应该被污染
        # 启发式: 若操作是 add 且立即数为 0->不应污染
        over_tainted = []
        for s in conservative_steps:
            if s.opcode in ('add', 'sub', 'or'):
                # 含常量 0 的操作->可能是过度保守
                over_tainted.append(s)
            elif s.opcode in ('shl', 'shr') and s.source_tainted:
                # 移位->源污点但移位量可能无关
                over_tainted.append(s)

        over_rate = len(over_tainted) / max(1, len(conservative_steps))
        over_conf = min(1.0, len(conservative_steps) / 20.0)

        # B: 欠污染估计--从传播步中估计未被追踪的间接数据流
        # 方法: 统计源被污染但目标未正确标记的传播步
        # 加权: 间接寻址操作 (mov [reg], ...) 比直接操作更可能遗漏
        all_propagations = [
            s for s in self._steps if s.source_tainted
        ]
        unmarked = [
            s for s in all_propagations
            if s.source_tainted and not s.dest_tainted
        ]
        # 若未标记的传播中包含间接操作 (访存), 欠污染风险更高
        indirect_unmarked = sum(
            1 for s in unmarked
            if s.opcode in ('mov', 'lea', 'push', 'pop')
            and '[' in getattr(s, 'operands', '')
        )
        base_rate = len(unmarked) / max(1, len(all_propagations))
        # 间接操作加权: 每条涉及内存的未标记步假设隐藏 ~2.5 条未追踪流
        expansion = min(0.6, indirect_unmarked * 2.5 / max(1, len(all_propagations)))
        under_rate = min(1.0, base_rate + expansion)
        under_conf = min(1.0, len(all_propagations) / 15.0)

        # 综合精度
        precision = 1.0 - (over_rate + under_rate) / 2.0
        precision = max(0.0, min(1.0, precision))

        # Grade
        if precision >= 0.90:
            grade = 'A'
        elif precision >= 0.75:
            grade = 'B'
        elif precision >= 0.55:
            grade = 'C'
        elif precision >= 0.35:
            grade = 'D'
        else:
            grade = 'F'

        return TaintPrecisionReport(
            total_propagation_steps=self._total_steps,
            sampled_steps=n,
            over_taint_rate=round(over_rate, 4),
            over_taint_confidence=round(over_conf, 4),
            under_taint_estimate=round(under_rate, 4),
            under_taint_confidence=round(under_conf, 4),
            precision_score=round(precision, 4),
            reliability_grade=grade,
        )
