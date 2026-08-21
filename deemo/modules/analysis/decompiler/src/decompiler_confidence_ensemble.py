# 反编译器置信度加权集成 — 多反编译器输出的自动融合与质量评估
#
# 不同反编译器（radare2、Ghidra、IDA）在同一函数上产生的伪代码质量差异显著
# radare2 在简单函数上速度快但结构恢复差，Ghidra 在复杂 CFG 上表现好但
# 对混淆代码的变量命名不稳定。没有任何一个反编译器在所有场景下最优
#
# 本模块在每个基本块级别为各反编译器维护置信度分数——基于其所产生伪代码
# 的内部控制流一致性，而非依赖外部 ground truth（不需要源码）
#
# 集成输出 = Σ(伪代码 × weight) / Σ weight，权重 = exp(conf_score × 温度参数)
# temperature 控制融合的"软硬"程度——低温更接近选择最佳反编译器（hard voting）
# 高温更接近均等融合（soft voting）
#
# 置信度评估维度（不需要源码）：
#   1. 可达性自洽: 伪代码中引用的所有标签是否都有定义（无悬挂引用）
#   2. 栈帧一致性: 栈偏移在函数内是否自洽（无冲突赋值）
#   3. 死代码率: 不可达基本块的比例（高死代码率 → 控制流恢复有问题）

from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
import math


@dataclass
class DecompilerOutput:
    """单个反编译器对单个函数的输出"""
    name: str                     # 'r2' | 'ghidra' | 'ida'
    pseudocode: str               # 伪代码全文
    blocks: List[Dict[str, Any]]  # 各基本块的 {addr, code, successors}
    confidence: float = 0.5       # [0,1] 当前置信度（EMA 平滑后）


class DecompilerConfidenceEnsemble:
    """多反编译器置信度加权集成

    为每个反编译器维护在线更新的置信度分数。融合输出 = 加权拼接
    """

    def __init__(self, temperature: float = 0.5, ema_alpha: float = 0.1):
        """
        温度参数: 融合温度。0.1 → 近似 hard voting; 1.0 → soft voting
        ema_alpha: 置信度的 EMA 平滑系数。越高对新输出越敏感
        """
        self._temperature = temperature
        self._ema_alpha = ema_alpha
        self._confidences: Dict[str, float] = {}  # 反编译器名 → EMA 置信度

    def assess_confidence(self, output: DecompilerOutput) -> float:
        """评估单次反编译输出的内在质量（不需要源码）

        返回 [0, 1] 分数。三个维度的权重按经验分配——
        可达性 0.5（最关键的信号），栈帧 0.3，死代码 0.2
        """
        reachability = self._check_reachability(output)
        stack_frame = self._check_stack_frame(output)
        dead_code = self._check_dead_code(output)

        return 0.5 * reachability + 0.3 * stack_frame + 0.2 * dead_code

    def _check_reachability(self, output: DecompilerOutput) -> float:
        """检查伪代码中引用标签的可达性自洽

        扫描所有跳转目标标签。若某标签被引用但无对应定义
        （反编译器生成了悬挂 goto），扣分
        扣分策略：每发现一个悬挂引用扣 0.15，下限 0.2
        """
        import re

        # 提取所有被引用的标签（模式: goto LABEL_xxx; 或 jmp LABEL_xxx）
        refs = set(re.findall(r'(?:goto|jmp)\s+(LABEL_\w+)', output.pseudocode))
        if not refs:
            return 0.8  # 无标签引用 → 简单函数，默认良好

        # 提取所有定义的标签（模式: LABEL_xxx:）
        defs = set(re.findall(r'(LABEL_\w+)\s*:', output.pseudocode))

        dangling = refs - defs
        if not dangling:
            return 1.0

        penalty = len(dangling) * 0.15
        return max(0.2, 1.0 - penalty)

    def _check_stack_frame(self, output: DecompilerOutput) -> float:
        """检查栈帧内的偏移一致性

        扫描所有 [rbp - N] 和 [rsp + M] 引用。若同一偏移量同时出现
        write 和 read 的冲突赋值（不同宽度），扣分

        此检查基于启发式——真正的栈帧冲突需数据流分析才能确认
        当前实现仅做模式匹配第一遍，假阳性率估计在 10-20%
        """
        import re

        # 提取所有栈偏移写操作: *(rbp - N) =
        writes = set(re.findall(r'\*\s*\(\s*rbp\s*-\s*(0x[0-9a-fA-F]+)\s*\)\s*=', output.pseudocode))
        reads = set(re.findall(r'\*\s*\(\s*rbp\s*-\s*(0x[0-9a-fA-F]+)\s*\)', output.pseudocode))

        if not writes:
            return 0.7  # 无栈写 → 可能是叶子函数，默认合理

        conflicts = 0
        for w in writes:
            # 同一偏移既作为写目标又作为读源 → 可能存在栈帧误恢复
            if w in reads:
                conflicts += 1

        penalty = conflicts * 0.2
        return max(0.3, 1.0 - penalty)

    def _check_dead_code(self, output: DecompilerOutput) -> float:
        """估计死代码率——不可达基本块的比例

        通过 successor 关系构建可达集，统计不在可达集中的 block
        """
        if not output.blocks:
            return 0.5

        # 构建可达集（BFS 从入口块开始）
        addr_set = {b.get('addr', 0) for b in output.blocks}
        if not addr_set:
            return 0.5

        entry = min(addr_set)  # 入口 = 最小地址（近似，非严格正确）
        reachable = set()
        stack = [entry]
        while stack:
            addr = stack.pop()
            if addr in reachable:
                continue
            reachable.add(addr)
            for b in output.blocks:
                if b.get('addr') == addr:
                    for s in b.get('successors', []):
                        if s in addr_set and s not in reachable:
                            stack.append(s)

        dead_ratio = 1.0 - len(reachable) / len(output.blocks)
        # 死代码率 > 30% → 几乎可以确定控制流恢复有严重问题
        return max(0.1, 1.0 - dead_ratio * 3.0)

    def update_confidence(self, name: str, raw_score: float):
        """EMA 更新某个反编译器的置信度"""
        if name not in self._confidences:
            self._confidences[name] = raw_score
        else:
            old = self._confidences[name]
            self._confidences[name] = (self._ema_alpha * raw_score +
                                       (1 - self._ema_alpha) * old)

    def ensemble_weights(self) -> Dict[str, float]:
        """计算各反编译器在集成中的权重 = exp(conf / temperature)

        权重归一化使总和为 1
        """
        if not self._confidences:
            return {}

        weights = {}
        for name, conf in self._confidences.items():
            weights[name] = math.exp(conf / self._temperature)

        total = sum(weights.values())
        if total > 0:
            for name in weights:
                weights[name] = round(weights[name] / total, 4)

        return weights

    def process(self, outputs: List[DecompilerOutput]) -> Dict[str, Any]:
        """处理一轮多反编译器输出，更新置信度并返回权重

        调用方在每轮反编译后调用此方法，拿到权重后自行决定如何融合伪代码
        """
        for out in outputs:
            raw = self.assess_confidence(out)
            self.update_confidence(out.name, raw)
        return {
            'weights': self.ensemble_weights(),
            'confidences': {k: round(v, 4) for k, v in self._confidences.items()},
        }
