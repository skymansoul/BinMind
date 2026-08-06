# 两级污点过滤
from __future__ import annotations
from typing import List, Set, Optional
import re

_SOURCE_FUNCTIONS = {
    "read", "fread", "recv", "recvfrom", "fgets", "gets",
    "scanf", "fscanf", "getenv", "getopt",
}

def is_external_source(func_name):
    return func_name.lower() in _SOURCE_FUNCTIONS

def taint_trace_2hop(proj, target_call_addr):
    try:
        cfg = proj.analyses.CFGFast(normalize=True)
        node = cfg.model.get_any_node(target_call_addr)
        if node is None: return False
        preds = list(cfg.model.get_predecessors(node))
        for pred in preds[:5]:
            block = cfg.model.get_any_node(pred.addr)
            if block is None: continue
            insns = getattr(block, "disassembly", None)
            if insns is None: continue
            for insn in reversed(insns.insns if hasattr(insns, "insns") else []):
                if insn.mnemonic == "call":
                    op = insn.op_str or ""
                    for src in _SOURCE_FUNCTIONS:
                        if src in op: return True
                    break
        return False
    except Exception:
        return False

def filter_format_findings(findings, binary_path):
    filtered = []
    for f_r in findings:
        call_line = f_r.get("call_line", "")
        if not call_line:
            filtered.append(f_r)
            continue
        # printf("const") -> safe
        if re.match(r'.*(printf|fprintf|sprintf|snprintf)\s*\(\s*"', call_line):
            continue
        filtered.append(f_r)
    return filtered
