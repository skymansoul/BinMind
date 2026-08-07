"""
Format string batch scanner — FCPV+PCFC (source-level) as primary,
EnhancedFmtDetector (IR-level) as UNCERTAIN fallback.

Architecture:
  1. Read C source
  2. FCPV collects 4 constraint types, solves on 3-valued safety lattice
  3. PCFC filters path-unreachable VULN (function-boundary aware)
  4. FCPV VULN (surviving PCFC) → CONFIRMED
  5. FCPV SAFE → FILTERED
  6. FCPV UNCERTAIN → fallback to EnhancedFmtDetector (IR-level)
  7. Compare against ground truth labels
  8. Output per-sample JSON + aggregate metrics

Usage:
  python -m tests.run_fmt_scanner
  python -m tests.run_fmt_scanner --verbose
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Resolve project root
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(PROJECT_DIR, 'samples', 'format_string')
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'eval')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Import local modules
sys.path.insert(0, PROJECT_DIR)

from core.source_ir_extractor import extract_from_file as extract_ir
from core.format_string_enhanced import EnhancedFmtDetector, FmtCandidate
from core.fcpv_pipeline import fcpv_filter
from core.pcfc_verifier import filter_fmt_by_pcfc
from core.fcpv_constraint_types import SafetyLabel


# ground truth
# TP = 真实格式字符串漏洞, 应被检出
# FP = 安全代码, 应被过滤

FMT_GROUND_TRUTH: Dict[str, str] = {
    'sample_fmt_01': 'TP',   # 基础: fgets→printf(buf)
    'sample_fmt_02': 'FP',   # 安全: printf("%s", buf)
    'sample_fmt_03': 'TP',   # sprintf(dst, buf)
    'sample_fmt_04': 'TP',   # fprintf(stderr, buf)
    'sample_fmt_05': 'TP',   # syslog(buf)
    'sample_fmt_06': 'FP',   # 安全包装: safe_print→printf("%s",s)
    'sample_fmt_07': 'TP',   # argv[1]→printf
    'sample_fmt_08': 'TP',   # fgets→printf (可注入%n)
    'sample_fmt_09': 'FP',   # 常量格式: printf("hello %s", name)
    'sample_fmt_10': 'TP',   # 间接传播: snprintf("%s",buf)→printf(dst)
    'sample_fmt_11': 'TP',   # getenv→printf
    'sample_fmt_12': 'TP',   # recv→printf (网络输入)
    'sample_fmt_13': 'TP',   # 位置参数%n写入: printf(argv[1])
    'sample_fmt_14': 'TP',   # 跨函数fprintf: log_error→fprintf(stderr,user)
    'sample_fmt_15': 'TP',   # syslog+printf: recv_data→syslog(buffer)+printf(buffer)
}


def find_fmt_samples() -> List[str]:
    """扫描 samples/format_string/ 目录, 返回所有样本目录名。"""
    if not os.path.isdir(SAMPLES_DIR):
        return []
    dirs = sorted([
        d for d in os.listdir(SAMPLES_DIR)
        if os.path.isdir(os.path.join(SAMPLES_DIR, d))
        and d.startswith('sample_fmt')
    ])
    return dirs


def get_c_source(sample_dir: str) -> Optional[str]:
    """获取样本的C源文件路径。"""
    full_dir = os.path.join(SAMPLES_DIR, sample_dir)
    c_files = list(Path(full_dir).glob('*.c'))
    if c_files:
        return str(c_files[0])
    return None


def classify_verdict(candidate: FmtCandidate, label: str) -> Tuple[str, bool]:
    """判断检测结果是否正确。"""
    if label == 'TP':
        if candidate.verdict == 'CONFIRMED':
            return ('tp_hit', True)
        elif candidate.verdict == 'UNCERTAIN':
            return ('tp_uncertain', True)
        else:
            return ('fn_missed', False)
    else:  # FP
        if candidate.verdict == 'FILTERED':
            return ('tn_filtered', True)
        elif candidate.verdict == 'CONFIRMED':
            return ('fp_false_alarm', False)
        else:
            return ('fp_uncertain', False)


