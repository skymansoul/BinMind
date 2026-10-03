# coding: utf-8
"""二进制链路检测器 — 与 detectors.py 源码正则 baseline 并行的第二轨.

口径(2026-09-16 审计确立, 指标必须注明是哪一轨):
- baseline 轨 (detectors.py): C 源码正则 + gold.jsonl 标签, 仅供开发回归;
- binary 轨 (本文件): 真实 core.pipeline.run_pipeline + 样本 vuln.exe,
  代表二进制链路实际表现, 对外指标以本轨为准;
- r2 缺失或 pipeline 报错时如实返回失败, 禁止伪造检出.
"""

import sys
from pathlib import Path
from typing import Callable, Dict, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parents[3]  # deemo
sys.path.insert(0, str(_PROJECT_ROOT))


def run_binary_pipeline_detector(exe_path: str) -> Tuple[bool, str]:
    """对单个二进制执行真实 pipeline, total_vulns>0 视为检出.

    ai_analysis=False 跳过全局 LLM 研判; ollama 不可达时 per-function
    分析在 pipeline 内部自动降级启发式, 不阻塞、不伪造.
    max_funcs=8: 与 binary_pipeline_full.json 评测口径一致,
    避免 MAX_FUNCTIONS=500 把 CRT 库函数全部拖入分析(实测 148 函数/
    5000 条弱注入, 单样本 135s; 限 8 个后回到 ~25s/9 vulns).
    """
    from core.pipeline import run_pipeline
    result = run_pipeline(binary_path=exe_path, ai_analysis=False,
                          symbolic=False, fuzz=False, output_format='json',
                          max_funcs=8)
    if not isinstance(result, dict):
        return False, f"pipeline returned {type(result).__name__}, expected dict"
    if 'error' in result:
        return False, f"pipeline error: {result['error']}"
    vulns = int(result.get('total_vulns', 0) or 0)
    elapsed = result.get('elapsed')
    detail = f"total_vulns={vulns}"
    if elapsed is not None:
        detail += f", elapsed={elapsed:.1f}s"
    return vulns > 0, detail


def locate_binary(sample_dir) -> str:
    """样本目录内定位二进制制品: vuln.exe 优先, 其次目录内首个 exe."""
    sample_dir = Path(sample_dir)
    exe = sample_dir / 'vuln.exe'
    if exe.exists():
        return str(exe)
    candidates = sorted(sample_dir.glob('*.exe'))
    if candidates:
        return str(candidates[0])
    return ''


# 类型→二进制检测器映射; 与 DETECTOR_MAP 结构对称, 但输入为 exe 路径.
# pipeline 为全类型检测, 四个类型共用同一入口, 映射仅保留类型对称性.
BINARY_DETECTOR_MAP: Dict[str, Callable] = {
    'heap_overflow': run_binary_pipeline_detector,
    'uaf': run_binary_pipeline_detector,
    'integer_overflow': run_binary_pipeline_detector,
    'format_string': run_binary_pipeline_detector,
}
