#!/usr/bin/env python3
"""
ASIP消融实验配置 — 消融配置类与六种预定义配置.

"""
from __future__ import annotations


class AblationConfig:
    """消融配置: 控制五引擎启用/禁用."""
    def __init__(self, name: str, *,
                 e1_guard: bool = False,
                 e2_clamp: bool = False,
                 e3_path: bool = False,
                 e4_alloc_write: bool = False,
                 e5_modulo: bool = False):
        self.name = name
        self.e1_guard = e1_guard
        self.e2_clamp = e2_clamp
        self.e3_path = e3_path
        self.e4_alloc_write = e4_alloc_write
        self.e5_modulo = e5_modulo


# 六种消融配置: 逐引擎启用
CONFIGS = [
    AblationConfig('B0_NoEngine'),
    AblationConfig('B1_PlusE1Guard', e1_guard=True),
    AblationConfig('B2_PlusE2Clamp', e1_guard=True, e2_clamp=True),
    AblationConfig('B3_PlusE3Path', e1_guard=True, e2_clamp=True, e3_path=True),
    AblationConfig('B4_PlusE4AllocWrite', e1_guard=True, e2_clamp=True,
                   e3_path=True, e4_alloc_write=True),
    AblationConfig('B5_PlusE5Modulo', e1_guard=True, e2_clamp=True,
                   e3_path=True, e4_alloc_write=True, e5_modulo=True),
    AblationConfig('B6_FullAllEngines', e1_guard=True, e2_clamp=True,
                   e3_path=True, e4_alloc_write=True, e5_modulo=True),
]
