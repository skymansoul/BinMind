"""
堆溢出集成器的路径敏感整合 — 桥接 cfg_path_splitter 与 3引擎集成过滤。
函数同时含守卫与非守卫写入路径时, 合并路径的守卫关联会误判 SUPPRESS;
本模块在集成投票前检查写入点是否处于多路径区域, 逐路径独立投票:
任一路径溢出→KEEP, 全部路径安全→SUPPRESS。
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple

from core.cfg_path_splitter import (
    CfgPathSplitter, PathSplitResult, PathState,
)


@dataclass
class PathIntegratorResult:
    """单个写入点的整合结果。"""
    write_line: int
    path_result: Optional[PathSplitResult] = None
    is_multi_path: bool = False
    # 原始集成投票 (拆分前)
    original_verdict: str = 'KEEP'
    # 路径感知判定
    path_verdict: str = 'KEEP'
    # 最终: 路径不一致时以路径感知结果为准
    final_verdict: str = 'KEEP'
    confidence: float = 0.50
    detail: str = ''


class HeapPathIntegrator:
    """堆集成检测的路径敏感整合器 — 用法: integrate(ir_lines, write_line, ensemble_verdict, confidence)。"""

    def __init__(self, max_paths: int = 64):
        self._splitter = CfgPathSplitter(max_paths=max_paths)
        self.stats: Dict[str, int] = {}

    def integrate(
        self,
        ir_lines: List[str],
        write_line: int,
        ensemble_verdict: str = 'KEEP',
        ensemble_confidence: float = 0.50,
    ) -> PathIntegratorResult:
        """执行路径敏感分析并与集成判定合并。

        单路径信任集成; 多路径含安全路径→REVIEW; 多路径全溢出→确认KEEP。
        """
        result = PathIntegratorResult(
            write_line=write_line,
            original_verdict=ensemble_verdict,
        )

        path = self._splitter.analyze(ir_lines, write_line)
        result.path_result = path

        if path.total_paths <= 1:
            # 单路径: 无合并歧义, 信任集成
            result.is_multi_path = False
            result.path_verdict = ensemble_verdict
            result.final_verdict = ensemble_verdict
            result.confidence = ensemble_confidence
            result.detail = 'single_path'
            return result

        result.is_multi_path = True

        # 多路径: 逐路径评估安全性
        if path.overflow_paths > 0 and path.safe_paths == 0:
            # 全部路径溢出 → 确认为漏洞
            result.path_verdict = 'KEEP'
            result.confidence = min(0.90, ensemble_confidence + 0.15)
            result.detail = f'{path.overflow_paths} overflow paths, 0 safe'
        elif path.overflow_paths > 0 and path.safe_paths > 0:
            # 部分安全部分溢出 → REVIEW (存在真实溢出路径, 不应抑制)
            result.path_verdict = 'KEEP'
            result.confidence = max(0.55, ensemble_confidence - 0.10)
            result.detail = (f'{path.safe_paths} safe + '
                           f'{path.overflow_paths} overflow paths')
        elif path.overflow_paths == 0 and path.safe_paths > 0:
            # 全部路径安全 → 确定性误报, 抑制
            result.path_verdict = 'SUPPRESS'
            result.confidence = 0.85
            result.detail = f'all {path.safe_paths} paths safe'
        else:
            # 仅死路径 → 无法判定, 信任集成
            result.path_verdict = ensemble_verdict
            result.confidence = ensemble_confidence
            result.detail = f'{path.dead_paths} dead paths, no live paths'

        # 最终: 路径不一致时以路径感知结果为准
        # 保守处理: 路径判 SUPPRESS 而集成判 KEEP → REVIEW
        if (result.path_verdict == 'SUPPRESS' and
                ensemble_verdict == 'KEEP'):
            result.final_verdict = 'REVIEW'
            result.confidence = 0.45
            result.detail += '; ensemble/path conflict→REVIEW'
        elif (result.path_verdict == 'KEEP' and
              ensemble_verdict == 'SUPPRESS'):
            # 路径分析发现溢出路径, 不抑制
            result.final_verdict = 'REVIEW'
            result.confidence = 0.55
            result.detail += '; path found overflow despite ensemble SUPPRESS'
        else:
            result.final_verdict = result.path_verdict

        return result

    def integrate_all(
        self,
        ir_lines: List[str],
        candidates: List[Dict],
        decisions: List[Any],
    ) -> Tuple[List[PathIntegratorResult], Dict[str, int]]:
        """对全部候选执行路径整合, 返回 (整合结果列表, 统计)。"""
        results = []
        suppressed = kept = review = 0

        for i, (cand, dec) in enumerate(zip(candidates, decisions)):
            write_line = cand.get('line', 0)
            ensemble_v = getattr(dec, 'verdict', 'KEEP')
            ensemble_c = getattr(dec, 'ensemble_score', 0.50)

            ir = self.integrate(
                ir_lines, write_line, ensemble_v, ensemble_c)

            if ir.final_verdict == 'SUPPRESS':
                suppressed += 1
            elif ir.final_verdict == 'KEEP':
                kept += 1
            else:
                review += 1

            results.append(ir)

        self.stats = {
            'total': len(results),
            'multi_path': sum(1 for r in results if r.is_multi_path),
            'suppressed': suppressed,
            'kept': kept,
            'review': review,
            'path_overrides': sum(
                1 for r in results
                if r.original_verdict != r.final_verdict),
        }
        return results, self.stats


def integrate_path_analysis(
    ir_lines: List[str],
    candidates: List[Dict],
    decisions: List[Any],
) -> Tuple[List[PathIntegratorResult], Dict[str, int]]:
    """便捷接口: 对集成结果运行路径感知整合。"""
    integrator = HeapPathIntegrator()
    return integrator.integrate_all(ir_lines, candidates, decisions)


__all__ = [
    'PathIntegratorResult', 'HeapPathIntegrator',
    'integrate_path_analysis',
]
