#!/usr/bin/env python3
"""
ASIP堆溢出CVE样本集 — 55个样本(40原有+15新增).

样本设计原则:
  - 每个样本代表一种真实CVE模式
  - 包含VULN(真阳性)和SAFE(真阴性)两类
  - SAFE样本是现有管线(B0)误报但ASIP应正确过滤的
  - VULN样本是真实漏洞, ASIP不得过滤

分类:
  - BASIC_VULN (1-10): 基础堆溢出模式
  - GUARD_SAFE (11-20): 路径守卫保护的安全写入
  - ALLOCATOR_SAFE (21-30): 分配器对齐/扩展边界保护
  - REAL_CVE (31-40): 真实CVE漏洞模式
  - ASIP_CHALLENGE (41-55): ASIP专项挑战样本
    41-45: 间接guard保护(SAFE) — heap_guard_collector遗漏
    46-50: 条件赋值+路径受限(SAFE) — widen过激进误判
    51-55: 不同缓冲区配对(SAFE) — alloc-write误配对
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from eval.asip_cve_samples_a import BASIC_VULN, GUARD_SAFE, ALLOCATOR_SAFE
from eval.asip_cve_samples_b import REAL_CVE, ASIP_CHALLENGE

ALL_SAMPLES = BASIC_VULN + GUARD_SAFE + ALLOCATOR_SAFE + REAL_CVE + ASIP_CHALLENGE

__all__ = [
    'BASIC_VULN', 'GUARD_SAFE', 'ALLOCATOR_SAFE',
    'REAL_CVE', 'ASIP_CHALLENGE', 'ALL_SAMPLES',
]
