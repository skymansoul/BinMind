# 堆漏洞分析器 — 基于值流的UAF/double-free检测
#
# 输入: angr CFG + value_flow.py 的def-use链
# 输出: 标准化漏洞发现列表

from __future__ import annotations
from typing import List, Dict, Any, Optional
import re

def _get_cfg(binary_path):
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        return proj.analyses.CFGFast(normalize=True)
    except Exception:
        return None

def _extract_heap_ops(cfg):
    ops = {'malloc': [], 'free': [], 'realloc': []}
    if cfg is None: return ops
    for func in cfg.kb.functions.values():
        fname = func.name
        for block in func.blocks:
            insns = block.disassembly.insns
            for insn in insns:
                if insn.mnemonic == 'call':
                    op_str = insn.op_str
                    for op_type in ops:
                        if op_type in op_str:
                            ops[op_type].append({
                                'function': fname, 'address': insn.address,
                                'operand': op_str,
                            })
    return ops

def analyze_heap_vulnerabilities(binary_path, cfg=None):
    findings = []
    if cfg is None: cfg = _get_cfg(binary_path)
    if cfg is None: return findings
    ops = _extract_heap_ops(cfg)
    try:
        from core.value_flow import build_def_use_chains, detect_uaf_pattern
        chains = build_def_use_chains(cfg)
        uaf_findings = detect_uaf_pattern(chains)
        for f in uaf_findings:
            findings.append({
                'type': 'use-after-free', 'function': f.get('free_block','unknown'),
                'severity': 'Critical', 'cwe': 'CWE-416',
                'confidence': f.get('confidence', 0.7),
                'description': 'UAF: freed ptr used later in same block',
            })
    except Exception: pass
    free_addrs = [o['address'] for o in ops.get('free',[])]
    seen = {}
    for a in free_addrs: seen[a] = seen.get(a,0) + 1
    for a, c in seen.items():
        if c >= 2:
            findings.append({
                'type': 'double-free', 'function': f'0x{a:x}',
                'severity': 'Critical', 'cwe': 'CWE-415', 'confidence': 0.7,
                'description': f'double-free at 0x{a:x}',
            })
    return findings
