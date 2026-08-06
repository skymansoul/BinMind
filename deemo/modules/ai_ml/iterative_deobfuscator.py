# 迭代一致性引导反混淆: 多轮CFG/DFG交叉验证的精化去混淆
#
# 核心问题: 现有LLM反混淆是单轮处理——无法验证去混淆结果是否语义等价。
# 混淆器的不透明谓词和虚假控制流可能被LLM误读为真实逻辑。
#
# 技术方案:
#   1. 多轮精化: 每轮后重建CFG/DFG，与原始混淆代码做一致性检查
#   2. 不一致区域识别: CFG/DFG差异最大的子图区域 → 定向精化提示
#   3. 定向精化: 仅将不一致区域反馈给LLM——提高注意力密度，避免过度修正
#   4. 收敛判定: 两轮间一致性增量 < 阈值时停止
#
# CFG/DFG重建实现在 src/deobfuscate/cfg_extractor.py

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any, Callable

from .src.deobfuscate.cfg_extractor import (
    CFGNode, DFGEdge, CFGDFGExtractor, CFGDFGConsistency,
)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class IterativeDeobfuscator:
    """迭代一致性引导反混淆调度器。

    编排多轮 LLM去混淆→一致性检查→定向精化 循环。

    收敛准则: |consistency_t - consistency_{t-1}| < 0.03 或 最多5轮
    """

    def __init__(self,
                 deobfuscate_fn: Callable[[str, Optional[str]], str],
                 max_iterations: int = 5,
                 convergence_threshold: float = 0.03):
        """
        Args:
            deobfuscate_fn: (code, hint_or_None) → deobfuscated_code
            max_iterations: 最大精化轮数
            convergence_threshold: 一致性增量阈值
        """
        self._deobfuscate = deobfuscate_fn
        self._max_iter = max_iterations
        self._conv_threshold = convergence_threshold
        self._checker = CFGDFGConsistency()
        self._extractor = CFGDFGExtractor()

    def deobfuscate(self, obfuscated_code: str) -> Dict[str, Any]:
        """执行完整的迭代一致性引导反混淆。

        Returns:
            {'final_code': str, 'iterations': int,
             'consistency_history': [...], 'converged': bool,
             'improvement': float}
        """
        history = []
        current_code = obfuscated_code
        converged = False

        # 第0轮: 全量去混淆
        current_code = self._deobfuscate(obfuscated_code, None)
        consistency = self._checker.compute_consistency(
            obfuscated_code, current_code)
        history.append({
            'round': 0, 'consistency': consistency['overall'],
            'cfg_sim': consistency['cfg_similarity'],
            'dfg_sim': consistency['dfg_similarity'],
            'inconsistent_count': len(consistency['inconsistent_regions']),
        })

        # 后续轮次: 定向精化
        for iteration in range(1, self._max_iter + 1):
            prev = consistency['overall']
            inconsistent = consistency['inconsistent_regions']

            if not inconsistent:
                converged = True
                break

            # 构造定向提示——仅标注不一致区域
            cfg_nodes = self._extractor.extract_cfg(current_code)
            hint_parts = []
            for region_id in inconsistent[:5]:
                if region_id < len(cfg_nodes):
                    snippet = '\n'.join(cfg_nodes[region_id].instructions[:10])
                    hint_parts.append(
                        f"Block {region_id}: inconsistent CFG. "
                        f"Verify successors:\n{snippet}")
            hint = "\n\n".join(hint_parts) if hint_parts else None

            current_code = self._deobfuscate(current_code, hint)
            consistency = self._checker.compute_consistency(
                obfuscated_code, current_code)
            history.append({
                'round': iteration, 'consistency': consistency['overall'],
                'cfg_sim': consistency['cfg_similarity'],
                'dfg_sim': consistency['dfg_similarity'],
                'inconsistent_count': len(consistency['inconsistent_regions']),
            })

            delta = consistency['overall'] - prev
            if abs(delta) < self._conv_threshold:
                converged = True
                break

        improvement = (history[-1]['consistency'] - history[0]['consistency']
                      if history else 0.0)
        return {
            'final_code': current_code,
            'iterations': len(history),
            'consistency_history': history,
            'converged': converged,
            'improvement': improvement,
        }
