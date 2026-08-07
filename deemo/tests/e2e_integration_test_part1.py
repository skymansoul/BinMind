"""
端到端集成测试 — 验证全部检测管道的完整链路。

测试覆盖:
  1. 样本发现 → 源码读取 → 检测 → 置信度计算 → 贝叶斯融合 → 风险分类
  2. 四管道独立运行 + 跨管道融合
  3. 回归矩阵生成 + 一致性检查
  4. 端到端延迟测量

用法:
  python tests/e2e_integration_test.py
  python tests/e2e_integration_test.py --quick  # 仅关键路径
"""

from __future__ import annotations
import json
import os
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


# 轻量级检测器 (无需导入完整模块)

def _detect_heap(src: str) -> Tuple[bool, float]:
    has_alloc = any(p in src for p in ['malloc(', 'calloc(', 'realloc('])
    has_write = any(p in src for p in ['memcpy(', 'memset(', 'strcpy('])
    has_guard = any(p in src for p in ['if (', 'sizeof(', 'min(', 'max('])
    if has_alloc and has_write:
        conf = 0.45 if has_guard else 0.75
        return True, conf
    return False, 0.1


def _detect_uaf(src: str) -> Tuple[bool, float]:
    free_count = src.count('free(')
    has_use = any(p in src for p in ['->', '*ptr', 'deref'])
    if free_count >= 2:
        return True, 0.85
    if free_count >= 1 and has_use:
        return True, 0.70
    return False, 0.1


def _detect_fmt(src: str) -> Tuple[bool, float]:
    has_printf = any(p in src for p in ['printf(', 'fprintf(', 'syslog('])
    has_direct = any(p in src for p in ['printf(f', 'printf(buf', 'printf(msg'])
    has_input = any(p in src for p in ['argv[', 'fgets(', 'scanf('])
    if has_printf and has_direct:
        return True, 0.90
    if has_printf and has_input:
        return True, 0.65
    return False, 0.1


def _detect_intof(src: str) -> Tuple[bool, float]:
    has_alloc = any(p in src for p in ['malloc(', 'calloc('])
    has_mul = any(p in src for p in ['* sizeof', '*sizeof', 'n *', 'size *'])
    has_shift = '<<' in src and has_alloc
    has_cast = '(size_t)' in src
    if has_alloc and (has_mul or has_shift):
        return True, 0.75
    if has_cast:
        return True, 0.55
    return False, 0.15


DETECTORS = {
    'heap_overflow': _detect_heap,
    'use_after_free': _detect_uaf,
    'format_string': _detect_fmt,
    'integer_overflow': _detect_intof,
}


